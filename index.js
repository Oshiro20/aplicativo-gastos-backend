require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

const GEMINI_API_KEY = (process.env.GEMINI_API_KEY || '').trim();
const GEMINI_MODEL = (process.env.GEMINI_MODEL || 'gemini-3-flash-preview').trim();
const GEMINI_FALLBACK_MODEL = (process.env.GEMINI_FALLBACK_MODEL || 'gemini-3.1-flash-lite-preview').trim();

const GROQ_API_KEY = (process.env.GROQ_API_KEY || '').trim();
const GROQ_MODEL = (process.env.GROQ_MODEL || 'llama-3.3-70b-versatile').trim();

const DATABASE_URL = (process.env.DATABASE_URL || '').trim();
const TOKEN_SECRET = (
    process.env.TOKEN_SECRET ||
    crypto.createHash('sha256').update(`walletai:${GEMINI_API_KEY}:${GROQ_API_KEY}`).digest('hex')
).trim();

// ─── PostgreSQL (Opcional para Cuenta en Nube y Respaldo) ─────────────────────

let pgPool = null;
let schemaReady = false;

function getPool() {
    if (!DATABASE_URL) return null;
    if (!pgPool) {
        pgPool = new Pool({
            connectionString: DATABASE_URL,
            ssl: DATABASE_URL.includes('localhost') || DATABASE_URL.includes('127.0.0.1')
                ? false
                : { rejectUnauthorized: false },
        });
    }
    return pgPool;
}

async function ensureCloudSchema() {
    const pool = getPool();
    if (!pool) return false;
    if (schemaReady) return true;

    await pool.query(`
        CREATE TABLE IF NOT EXISTS wallet_users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS wallet_backups (
            user_id INTEGER PRIMARY KEY REFERENCES wallet_users(id) ON DELETE CASCADE,
            device_id TEXT NOT NULL,
            device_name TEXT NOT NULL,
            schema_version INTEGER NOT NULL DEFAULT 15,
            accounts_count INTEGER NOT NULL DEFAULT 0,
            transactions_count INTEGER NOT NULL DEFAULT 0,
            categories_count INTEGER NOT NULL DEFAULT 0,
            checksum TEXT NOT NULL,
            payload_base64 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL DEFAULT 0,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS ecosystem_summaries (
            user_id INTEGER PRIMARY KEY REFERENCES wallet_users(id) ON DELETE CASCADE,
            payload_json JSONB NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS ecosystem_pending_tx (
            id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES wallet_users(id) ON DELETE CASCADE,
            source TEXT NOT NULL DEFAULT 'mylifeos',
            payload_json JSONB NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            acked_at TIMESTAMPTZ
        );
    `);

    schemaReady = true;
    return true;
}

// ─── Utilidades de Auth / JWT ─────────────────────────────────────────────────

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const derived = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${derived}`;
}

function verifyPassword(password, stored) {
    const parts = String(stored || '').split(':');
    if (parts.length !== 2) return false;
    const [salt, originalHex] = parts;
    const derived = crypto.scryptSync(password, salt, 64);
    const original = Buffer.from(originalHex, 'hex');
    if (derived.length !== original.length) return false;
    return crypto.timingSafeEqual(derived, original);
}

function base64UrlEncode(input) {
    return Buffer.from(input).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64UrlDecode(str) {
    const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
    return Buffer.from(padded, 'base64').toString('utf8');
}

function signToken(payload, expiresInDays = 60) {
    const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const exp = Math.floor(Date.now() / 1000) + expiresInDays * 86400;
    const body = base64UrlEncode(JSON.stringify({ ...payload, exp }));
    const signature = crypto
        .createHmac('sha256', TOKEN_SECRET)
        .update(`${header}.${body}`)
        .digest('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
    return `${header}.${body}.${signature}`;
}

function verifyToken(token) {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) return null;
    const [header, body, sig] = parts;
    const expected = crypto
        .createHmac('sha256', TOKEN_SECRET)
        .update(`${header}.${body}`)
        .digest('base64')
        .replace(/=/g, '')
        .replace(/\+/g, '-')
        .replace(/\//g, '_');
    if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
        return null;
    }
    const decoded = JSON.parse(base64UrlDecode(body));
    if (!decoded.exp || decoded.exp < Math.floor(Date.now() / 1000)) {
        return null;
    }
    return decoded;
}

function requireAuth(req, res, next) {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const user = verifyToken(token);
    if (!user) {
        return res.status(401).json({ error: 'Sesión inválida o expirada. Inicia sesión nuevamente.' });
    }
    req.user = user;
    return next();
}

function formatBackupMeta(row) {
    if (!row) {
        return { exists: false };
    }
    return {
        exists: true,
        deviceId: row.device_id,
        deviceName: row.device_name,
        schemaVersion: row.schema_version,
        accountsCount: row.accounts_count,
        transactionsCount: row.transactions_count,
        categoriesCount: row.categories_count,
        checksum: row.checksum,
        sizeBytes: row.size_bytes,
        updatedAt: new Date(row.updated_at).toISOString(),
    };
}

// ─── Utilidades de IA (Gemini + Groq Fallback) ────────────────────────────────

async function callGemini({
    systemPrompt,
    userMessage,
    expectJson,
    model,
    mediaBase64,
    mediaMimeType,
    mediaItems,
    history,
}) {
    if (!GEMINI_API_KEY) {
        const err = new Error('GEMINI_API_KEY no configurada');
        err.statusCode = 401;
        throw err;
    }

    const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(GEMINI_API_KEY)}`;

    const userParts = [{ text: userMessage }];
    if (mediaBase64 && mediaMimeType) {
        userParts.push({
            inlineData: {
                mimeType: mediaMimeType,
                data: mediaBase64,
            },
        });
    }
    if (Array.isArray(mediaItems)) {
        for (const item of mediaItems) {
            if (item && item.base64 && item.mimeType) {
                userParts.push({
                    inlineData: {
                        mimeType: String(item.mimeType),
                        data: String(item.base64),
                    },
                });
            }
        }
    }

    const contents = [];
    if (Array.isArray(history)) {
        for (const item of history) {
            if (!item || !item.text) continue;
            contents.push({
                role: item.role === 'model' ? 'model' : 'user',
                parts: [{ text: String(item.text) }],
            });
        }
    }
    contents.push({
        role: 'user',
        parts: userParts,
    });

    const body = {
        ...(systemPrompt && {
            systemInstruction: {
                parts: [{ text: systemPrompt }],
            },
        }),
        contents,
        ...(expectJson && {
            generationConfig: {
                responseMimeType: 'application/json',
            },
        }),
    };

    const response = await axios.post(url, body, {
        headers: { 'Content-Type': 'application/json' },
        timeout: 60000,
    });

    const parts = response.data?.candidates?.[0]?.content?.parts || [];
    const text = parts.map((p) => p.text || '').join('').trim();
    if (!text) {
        const err = new Error('Gemini devolvió una respuesta vacía');
        err.statusCode = 502;
        throw err;
    }

    return {
        provider: `gemini:${model}`,
        text,
        choices: [{ message: { role: 'assistant', content: text } }],
    };
}

async function callGroq({ systemPrompt, userMessage, expectJson, history }) {
    if (!GROQ_API_KEY) {
        const err = new Error('GROQ_API_KEY no configurada');
        err.statusCode = 401;
        throw err;
    }

    const messages = [];
    if (systemPrompt) {
        messages.push({ role: 'system', content: systemPrompt });
    }
    if (Array.isArray(history)) {
        for (const item of history) {
            if (!item || !item.text) continue;
            messages.push({
                role: item.role === 'model' ? 'assistant' : 'user',
                content: String(item.text),
            });
        }
    }
    messages.push({ role: 'user', content: userMessage });

    const payload = {
        model: GROQ_MODEL,
        messages,
        ...(expectJson && { response_format: { type: 'json_object' } }),
    };

    const response = await axios.post(
        'https://api.groq.com/openai/v1/chat/completions',
        payload,
        {
            headers: {
                Authorization: `Bearer ${GROQ_API_KEY}`,
                'Content-Type': 'application/json',
            },
            timeout: 45000,
        }
    );

    const text = response.data?.choices?.[0]?.message?.content || '';
    return {
        ...response.data,
        text,
        provider: `groq:${GROQ_MODEL}`,
    };
}

async function generateAIResponse({
    systemPrompt,
    userMessage,
    expectJson,
    mediaBase64,
    mediaMimeType,
    mediaItems,
    history,
}) {
    const errors = [];
    const hasMedia = Boolean(mediaBase64) || (Array.isArray(mediaItems) && mediaItems.length > 0);

    if (GEMINI_API_KEY) {
        const modelsToTry = [GEMINI_MODEL];
        if (GEMINI_FALLBACK_MODEL && GEMINI_FALLBACK_MODEL !== GEMINI_MODEL) {
            modelsToTry.push(GEMINI_FALLBACK_MODEL);
        }

        for (const model of modelsToTry) {
            try {
                return await callGemini({
                    systemPrompt,
                    userMessage,
                    expectJson,
                    model,
                    mediaBase64,
                    mediaMimeType,
                    mediaItems,
                    history,
                });
            } catch (err) {
                const status = err.response?.status || err.statusCode || 500;
                const msg = err.response?.data?.error?.message || err.message;
                console.error(`[AI] Gemini (${model}) error ${status}:`, msg);
                errors.push({ status, msg });
            }
        }
    }

    if (GROQ_API_KEY && !hasMedia) {
        try {
            return await callGroq({ systemPrompt, userMessage, expectJson, history });
        } catch (err) {
            const status = err.response?.status || err.statusCode || 500;
            const msg = err.response?.data?.error?.message || err.message;
            console.error(`[AI] Groq error ${status}:`, msg);
            errors.push({ status, msg });
        }
    }

    const last = errors[errors.length - 1] || {
        status: 503,
        msg: 'Ningún proveedor de IA está configurado en el servidor.',
    };
    const finalError = new Error(last.msg);
    finalError.statusCode = last.status;
    throw finalError;
}

// ─── Health & Root ────────────────────────────────────────────────────────────

app.get('/', (req, res) => {
    res.send('Aplicativo Gastos Backend is running! 🚀');
});

app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        ai: {
            geminiConfigured: Boolean(GEMINI_API_KEY),
            geminiModel: GEMINI_MODEL,
            groqConfigured: Boolean(GROQ_API_KEY),
        },
        cloudBackupConfigured: Boolean(DATABASE_URL),
    });
});

// ─── Endpoints de IA ──────────────────────────────────────────────────────────

app.post('/api/parse-voice', async (req, res) => {
    try {
        const { systemPrompt, userMessage } = req.body;
        if (!systemPrompt || !userMessage) {
            return res.status(400).json({ error: 'Faltan parámetros: systemPrompt o userMessage' });
        }

        const expectJson = systemPrompt.includes('JSON EXACTO');
        const result = await generateAIResponse({ systemPrompt, userMessage, expectJson });
        return res.json(result);
    } catch (error) {
        const status = error.statusCode || 500;
        return res.status(status).json({
            error: error.message || 'Error procesando la solicitud en la IA',
        });
    }
});

app.post('/api/parse-receipt', async (req, res) => {
    try {
        const { systemPrompt, textContent, base64Image } = req.body;
        const ocrText = textContent || base64Image;
        if (!systemPrompt || !ocrText) {
            return res.status(400).json({ error: 'Faltan parámetros: systemPrompt o data del recibo' });
        }

        const expectJson = systemPrompt.toLowerCase().includes('json');
        const result = await generateAIResponse({
            systemPrompt,
            userMessage: ocrText,
            expectJson,
        });
        return res.json(result);
    } catch (error) {
        const status = error.statusCode || 500;
        return res.status(status).json({
            error: error.message || 'Error procesando el recibo visual',
        });
    }
});

// Proxy genérico de IA (texto, chat multi-turno y visión/audio base64 para el ecosistema)
app.post('/api/ai/generate', async (req, res) => {
    try {
        const {
            systemPrompt,
            userMessage,
            expectJson = false,
            mediaBase64,
            mediaMimeType,
            mediaItems,
            history,
        } = req.body || {};

        if (!userMessage || typeof userMessage !== 'string') {
            return res.status(400).json({ error: 'Falta parámetro obligatorio: userMessage' });
        }

        const result = await generateAIResponse({
            systemPrompt: systemPrompt ? String(systemPrompt) : undefined,
            userMessage: String(userMessage),
            expectJson: Boolean(expectJson),
            mediaBase64: mediaBase64 ? String(mediaBase64) : undefined,
            mediaMimeType: mediaMimeType ? String(mediaMimeType) : undefined,
            mediaItems: Array.isArray(mediaItems) ? mediaItems : undefined,
            history,
        });
        return res.json(result);
    } catch (error) {
        const status = error.statusCode || 500;
        return res.status(status).json({
            error: error.message || 'Error procesando la solicitud en la IA',
        });
    }
});

// ─── Endpoints de Cuenta en la Nube & Respaldos ───────────────────────────────

app.post('/api/auth/register', async (req, res) => {
    try {
        if (!(await ensureCloudSchema())) {
            return res.status(503).json({
                error: 'CLOUD_DB_NOT_CONFIGURED',
                message: 'El almacenamiento en nube requiere configurar DATABASE_URL en Render.',
            });
        }

        const rawUser = String(req.body.username || '').trim().toLowerCase();
        const password = String(req.body.password || '');

        if (rawUser.length < 3) {
            return res.status(400).json({ error: 'El usuario o correo debe tener al menos 3 caracteres.' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres.' });
        }

        const pool = getPool();
        const existing = await pool.query('SELECT id FROM wallet_users WHERE username = $1', [rawUser]);
        if (existing.rows.length > 0) {
            return res.status(409).json({ error: 'Ese usuario/correo ya está registrado.' });
        }

        const passwordHash = hashPassword(password);
        const inserted = await pool.query(
            'INSERT INTO wallet_users (username, password_hash) VALUES ($1, $2) RETURNING id, username, created_at',
            [rawUser, passwordHash]
        );
        const user = inserted.rows[0];
        const token = signToken({ id: user.id, username: user.username });

        return res.status(201).json({
            token,
            user: { id: user.id, username: user.username },
            latestBackup: { exists: false },
        });
    } catch (error) {
        console.error('[AUTH] register error:', error.message);
        return res.status(500).json({ error: 'No se pudo registrar la cuenta en la nube.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        if (!(await ensureCloudSchema())) {
            return res.status(503).json({
                error: 'CLOUD_DB_NOT_CONFIGURED',
                message: 'El almacenamiento en nube requiere configurar DATABASE_URL en Render.',
            });
        }

        const rawUser = String(req.body.username || '').trim().toLowerCase();
        const password = String(req.body.password || '');

        if (!rawUser || !password) {
            return res.status(400).json({ error: 'Ingresa tu usuario/correo y contraseña.' });
        }

        const pool = getPool();
        const result = await pool.query(
            'SELECT id, username, password_hash FROM wallet_users WHERE username = $1',
            [rawUser]
        );

        if (result.rows.length === 0 || !verifyPassword(password, result.rows[0].password_hash)) {
            return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
        }

        const user = result.rows[0];
        const token = signToken({ id: user.id, username: user.username });

        const backupRes = await pool.query(
            `SELECT device_id, device_name, schema_version, accounts_count, transactions_count, categories_count, checksum, size_bytes, updated_at
             FROM wallet_backups WHERE user_id = $1`,
            [user.id]
        );

        return res.json({
            token,
            user: { id: user.id, username: user.username },
            latestBackup: formatBackupMeta(backupRes.rows[0]),
        });
    } catch (error) {
        console.error('[AUTH] login error:', error.message);
        return res.status(500).json({ error: 'Error al iniciar sesión en la nube.' });
    }
});

app.get('/api/backup/status', requireAuth, async (req, res) => {
    try {
        if (!(await ensureCloudSchema())) {
            return res.status(503).json({
                error: 'CLOUD_DB_NOT_CONFIGURED',
                message: 'El almacenamiento en nube requiere configurar DATABASE_URL en Render.',
            });
        }

        const pool = getPool();
        const backupRes = await pool.query(
            `SELECT device_id, device_name, schema_version, accounts_count, transactions_count, categories_count, checksum, size_bytes, updated_at
             FROM wallet_backups WHERE user_id = $1`,
            [req.user.id]
        );

        return res.json({
            user: { id: req.user.id, username: req.user.username },
            latestBackup: formatBackupMeta(backupRes.rows[0]),
        });
    } catch (error) {
        console.error('[BACKUP] status error:', error.message);
        return res.status(500).json({ error: 'Error consultando el estado del respaldo.' });
    }
});

app.post('/api/backup/upload', requireAuth, async (req, res) => {
    try {
        if (!(await ensureCloudSchema())) {
            return res.status(503).json({
                error: 'CLOUD_DB_NOT_CONFIGURED',
                message: 'El almacenamiento en nube requiere configurar DATABASE_URL en Render.',
            });
        }

        const {
            deviceId,
            deviceName,
            schemaVersion = 15,
            accountsCount = 0,
            transactionsCount = 0,
            categoriesCount = 0,
            checksum,
            payloadBase64,
            baseUpdatedAt,
            force = false,
        } = req.body;

        if (!deviceId || !checksum || !payloadBase64) {
            return res.status(400).json({ error: 'Faltan datos obligatorios del respaldo.' });
        }

        const pool = getPool();
        const existingRes = await pool.query(
            `SELECT device_id, device_name, schema_version, accounts_count, transactions_count, categories_count, checksum, size_bytes, updated_at
             FROM wallet_backups WHERE user_id = $1`,
            [req.user.id]
        );

        if (existingRes.rows.length > 0 && !force) {
            const current = existingRes.rows[0];
            const serverIso = new Date(current.updated_at).toISOString();
            const isDifferentDevice = current.device_id !== deviceId;
            const clientKnowsVersion = baseUpdatedAt && new Date(baseUpdatedAt).getTime() >= new Date(current.updated_at).getTime();

            if (isDifferentDevice && !clientKnowsVersion) {
                return res.status(409).json({
                    error: 'CONFLICT_NEWER_BACKUP',
                    message: `Otro dispositivo (${current.device_name}) guardó una copia más reciente (${serverIso}).`,
                    latestBackup: formatBackupMeta(current),
                });
            }
        }

        const sizeBytes = Buffer.byteLength(payloadBase64, 'base64');
        const upsert = await pool.query(
            `INSERT INTO wallet_backups (
                user_id, device_id, device_name, schema_version,
                accounts_count, transactions_count, categories_count,
                checksum, payload_base64, size_bytes, updated_at
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
             ON CONFLICT (user_id) DO UPDATE SET
                device_id = EXCLUDED.device_id,
                device_name = EXCLUDED.device_name,
                schema_version = EXCLUDED.schema_version,
                accounts_count = EXCLUDED.accounts_count,
                transactions_count = EXCLUDED.transactions_count,
                categories_count = EXCLUDED.categories_count,
                checksum = EXCLUDED.checksum,
                payload_base64 = EXCLUDED.payload_base64,
                size_bytes = EXCLUDED.size_bytes,
                updated_at = NOW()
             RETURNING device_id, device_name, schema_version, accounts_count, transactions_count, categories_count, checksum, size_bytes, updated_at`,
            [
                req.user.id,
                String(deviceId),
                String(deviceName || 'Android'),
                Number(schemaVersion) || 15,
                Number(accountsCount) || 0,
                Number(transactionsCount) || 0,
                Number(categoriesCount) || 0,
                String(checksum),
                String(payloadBase64),
                sizeBytes,
            ]
        );

        return res.json({
            success: true,
            latestBackup: formatBackupMeta(upsert.rows[0]),
        });
    } catch (error) {
        console.error('[BACKUP] upload error:', error.message);
        return res.status(500).json({ error: 'No se pudo subir el respaldo a la nube.' });
    }
});

app.get('/api/backup/download', requireAuth, async (req, res) => {
    try {
        if (!(await ensureCloudSchema())) {
            return res.status(503).json({
                error: 'CLOUD_DB_NOT_CONFIGURED',
                message: 'El almacenamiento en nube requiere configurar DATABASE_URL en Render.',
            });
        }

        const pool = getPool();
        const result = await pool.query(
            `SELECT device_id, device_name, schema_version, accounts_count, transactions_count, categories_count, checksum, payload_base64, size_bytes, updated_at
             FROM wallet_backups WHERE user_id = $1`,
            [req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'No hay respaldo guardado en tu cuenta.' });
        }

        const row = result.rows[0];
        return res.json({
            latestBackup: formatBackupMeta(row),
            payloadBase64: row.payload_base64,
        });
    } catch (error) {
        console.error('[BACKUP] download error:', error.message);
        return res.status(500).json({ error: 'No se pudo descargar el respaldo desde la nube.' });
    }
});

// ─── Endpoints de Ecosistema (WalletAI <-> MyLifeOS) ──────────────────────────

app.put('/api/ecosystem/summary', requireAuth, async (req, res) => {
    try {
        if (!(await ensureCloudSchema())) {
            return res.status(503).json({
                error: 'CLOUD_DB_NOT_CONFIGURED',
                message: 'El almacenamiento en nube requiere configurar DATABASE_URL en Render.',
            });
        }

        const payload = req.body;
        if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
            return res.status(400).json({ error: 'Payload de resumen inválido.' });
        }

        const pool = getPool();
        const result = await pool.query(
            `INSERT INTO ecosystem_summaries (user_id, payload_json, updated_at)
             VALUES ($1, $2::jsonb, NOW())
             ON CONFLICT (user_id) DO UPDATE SET
                payload_json = EXCLUDED.payload_json,
                updated_at = NOW()
             RETURNING updated_at`,
            [req.user.id, JSON.stringify(payload)]
        );

        return res.json({
            success: true,
            updatedAt: new Date(result.rows[0].updated_at).toISOString(),
        });
    } catch (error) {
        console.error('[ECOSYSTEM] summary put error:', error.message);
        return res.status(500).json({ error: 'No se pudo publicar el resumen del ecosistema.' });
    }
});

app.get('/api/ecosystem/summary', requireAuth, async (req, res) => {
    try {
        if (!(await ensureCloudSchema())) {
            return res.status(503).json({
                error: 'CLOUD_DB_NOT_CONFIGURED',
                message: 'El almacenamiento en nube requiere configurar DATABASE_URL en Render.',
            });
        }

        const pool = getPool();
        const result = await pool.query(
            `SELECT payload_json, updated_at
             FROM ecosystem_summaries
             WHERE user_id = $1`,
            [req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                exists: false,
                error: 'Aún no hay resumen publicado desde WalletAI para esta cuenta.',
            });
        }

        const row = result.rows[0];
        return res.json({
            exists: true,
            summary: row.payload_json,
            updatedAt: new Date(row.updated_at).toISOString(),
        });
    } catch (error) {
        console.error('[ECOSYSTEM] summary get error:', error.message);
        return res.status(500).json({ error: 'No se pudo obtener el resumen del ecosistema.' });
    }
});

app.post('/api/ecosystem/pending-transactions', requireAuth, async (req, res) => {
    try {
        if (!(await ensureCloudSchema())) {
            return res.status(503).json({
                error: 'CLOUD_DB_NOT_CONFIGURED',
                message: 'El almacenamiento en nube requiere configurar DATABASE_URL en Render.',
            });
        }

        const body = req.body || {};
        const amount = Number(body.amount);
        if (!Number.isFinite(amount) || amount <= 0) {
            return res.status(400).json({ error: 'El monto debe ser un número mayor a 0.' });
        }

        const id = String(body.id || crypto.randomUUID());
        const source = String(body.source || 'mylifeos');
        const payload = {
            id,
            source,
            type: body.type === 'income' ? 'income' : 'expense',
            amount,
            currency: String(body.currency || 'PEN'),
            description: String(body.description || 'Compra desde MyLifeOS'),
            categoryHint: String(body.categoryHint || 'Alimentación'),
            date: body.date ? String(body.date) : new Date().toISOString(),
            items: Array.isArray(body.items) ? body.items : [],
        };

        const pool = getPool();
        await pool.query(
            `INSERT INTO ecosystem_pending_tx (id, user_id, source, payload_json, status, created_at)
             VALUES ($1, $2, $3, $4::jsonb, 'pending', NOW())
             ON CONFLICT (id) DO UPDATE SET
                payload_json = EXCLUDED.payload_json,
                status = 'pending'`,
            [id, req.user.id, source, JSON.stringify(payload)]
        );

        return res.status(201).json({
            success: true,
            id,
            transaction: payload,
        });
    } catch (error) {
        console.error('[ECOSYSTEM] pending-tx post error:', error.message);
        return res.status(500).json({ error: 'No se pudo enviar el movimiento pendiente.' });
    }
});

app.get('/api/ecosystem/pending-transactions', requireAuth, async (req, res) => {
    try {
        if (!(await ensureCloudSchema())) {
            return res.status(503).json({
                error: 'CLOUD_DB_NOT_CONFIGURED',
                message: 'El almacenamiento en nube requiere configurar DATABASE_URL en Render.',
            });
        }

        const pool = getPool();
        const result = await pool.query(
            `SELECT id, source, payload_json, status, created_at
             FROM ecosystem_pending_tx
             WHERE user_id = $1 AND status = 'pending'
             ORDER BY created_at DESC`,
            [req.user.id]
        );

        return res.json({
            items: result.rows.map((r) => ({
                ...(typeof r.payload_json === 'object' ? r.payload_json : {}),
                id: r.id,
                source: r.source,
                status: r.status,
                createdAt: new Date(r.created_at).toISOString(),
            })),
        });
    } catch (error) {
        console.error('[ECOSYSTEM] pending-tx get error:', error.message);
        return res.status(500).json({ error: 'No se pudieron consultar los movimientos pendientes.' });
    }
});

app.post('/api/ecosystem/pending-transactions/:id/ack', requireAuth, async (req, res) => {
    try {
        if (!(await ensureCloudSchema())) {
            return res.status(503).json({
                error: 'CLOUD_DB_NOT_CONFIGURED',
                message: 'El almacenamiento en nube requiere configurar DATABASE_URL en Render.',
            });
        }

        const pool = getPool();
        const result = await pool.query(
            `UPDATE ecosystem_pending_tx
             SET status = 'processed', acked_at = NOW()
             WHERE id = $1 AND user_id = $2
             RETURNING id`,
            [String(req.params.id), req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Movimiento pendiente no encontrado.' });
        }

        return res.json({ success: true, id: req.params.id });
    } catch (error) {
        console.error('[ECOSYSTEM] pending-tx ack error:', error.message);
        return res.status(500).json({ error: 'No se pudo confirmar el movimiento.' });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Backend running on port ${PORT}`);
});
