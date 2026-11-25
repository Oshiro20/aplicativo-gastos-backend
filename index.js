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
const GEMINI_EXTRA_FALLBACKS = ['gemini-3.5-flash-lite', 'gemini-2.5-flash'];

const MISTRAL_API_KEY = (process.env.MISTRAL_API_KEY || '').trim();
const MISTRAL_MODEL = (process.env.MISTRAL_MODEL || 'mistral-small-latest').trim();
const MISTRAL_VISION_MODEL = (process.env.MISTRAL_VISION_MODEL || 'pixtral-12b-2409').trim();

const CLOUDFLARE_API_TOKEN = (process.env.CLOUDFLARE_API_TOKEN || '').trim();
const CLOUDFLARE_ACCOUNT_ID = (process.env.CLOUDFLARE_ACCOUNT_ID || '').trim();
const CLOUDFLARE_MODEL = (
    process.env.CLOUDFLARE_MODEL || '@cf/meta/llama-3.3-70b-instruct-fp8-fast'
).trim();
const CLOUDFLARE_FALLBACK_MODEL = (
    process.env.CLOUDFLARE_FALLBACK_MODEL || '@cf/meta/llama-3.1-8b-instruct-fast'
).trim();

const OPENROUTER_API_KEY = (process.env.OPENROUTER_API_KEY || '').trim();
const OPENROUTER_MODELS = (
    process.env.OPENROUTER_MODELS ||
    'openrouter/free,mistralai/mistral-small-3.1-24b-instruct:free,meta-llama/llama-3.3-70b-instruct:free,google/gemma-3-27b-it:free'
)
    .split(',')
    .map((m) => m.trim())
    .filter(Boolean);

const NVIDIA_API_KEY = (process.env.NVIDIA_API_KEY || '').trim();
const NVIDIA_MODEL = (process.env.NVIDIA_MODEL || 'meta/llama-3.3-70b-instruct').trim();

const DATABASE_URL = (process.env.DATABASE_URL || '').trim();
const TOKEN_SECRET = (
    process.env.TOKEN_SECRET ||
    crypto.createHash('sha256').update(`walletai:${GEMINI_API_KEY}:cloud`).digest('hex')
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
            display_name TEXT,
            email TEXT,
            recovery_key_hash TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
    `);

    await pool.query(`ALTER TABLE wallet_users ADD COLUMN IF NOT EXISTS display_name TEXT;`);
    await pool.query(`ALTER TABLE wallet_users ADD COLUMN IF NOT EXISTS email TEXT;`);
    await pool.query(`ALTER TABLE wallet_users ADD COLUMN IF NOT EXISTS recovery_key_hash TEXT;`);
    await pool.query(`ALTER TABLE wallet_users ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW();`);
    await pool.query(`
        CREATE UNIQUE INDEX IF NOT EXISTS idx_wallet_users_email_lower
        ON wallet_users (LOWER(email))
        WHERE email IS NOT NULL AND email <> '';
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS mylifeos_backups (
            user_id INTEGER PRIMARY KEY REFERENCES wallet_users(id) ON DELETE CASCADE,
            device_id TEXT NOT NULL,
            device_name TEXT NOT NULL,
            schema_version INTEGER NOT NULL DEFAULT 16,
            includes_photos BOOLEAN NOT NULL DEFAULT FALSE,
            checksum TEXT NOT NULL,
            payload_base64 TEXT NOT NULL,
            size_bytes INTEGER NOT NULL DEFAULT 0,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
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

function signToken(payload, expiresInDays = 365) {
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

function formatMyLifeOSBackupMeta(row) {
    if (!row) {
        return { exists: false };
    }
    return {
        exists: true,
        deviceId: row.device_id,
        deviceName: row.device_name,
        schemaVersion: row.schema_version,
        includesPhotos: Boolean(row.includes_photos),
        checksum: row.checksum,
        sizeBytes: row.size_bytes,
        updatedAt: new Date(row.updated_at).toISOString(),
    };
}

function formatPublicUser(row) {
    return {
        id: row.id,
        username: row.username,
        displayName: row.display_name || row.username,
        email: row.email || null,
        hasRecoveryKey: Boolean(row.recovery_key_hash),
        createdAt: row.created_at ? new Date(row.created_at).toISOString() : null,
    };
}

function generateRecoveryKey() {
    const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
    const bytes = crypto.randomBytes(12);
    const chars = Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('');
    return `MLO-${chars.slice(0, 4)}-${chars.slice(4, 8)}-${chars.slice(8, 12)}`;
}

function normalizeRecoveryKey(raw) {
    return String(raw || '').trim().toUpperCase().replace(/\s+/g, '');
}

// ─── Utilidades de IA (Router Multi-Proveedor: Gemini + Mistral + Cloudflare + OpenRouter) ─

function buildOpenAIMessages({ systemPrompt, userMessage, history, mediaBase64, mediaMimeType, mediaItems }) {
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

    const images = [];
    if (mediaBase64 && mediaMimeType && String(mediaMimeType).startsWith('image/')) {
        images.push({ mimeType: String(mediaMimeType), base64: String(mediaBase64) });
    }
    if (Array.isArray(mediaItems)) {
        for (const item of mediaItems) {
            if (item && item.base64 && item.mimeType && String(item.mimeType).startsWith('image/')) {
                images.push({ mimeType: String(item.mimeType), base64: String(item.base64) });
            }
        }
    }

    if (images.length > 0) {
        const content = [{ type: 'text', text: userMessage }];
        for (const img of images) {
            content.push({
                type: 'image_url',
                image_url: { url: `data:${img.mimeType};base64,${img.base64}` },
            });
        }
        messages.push({ role: 'user', content });
    } else {
        messages.push({ role: 'user', content: userMessage });
    }
    return messages;
}

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

async function callMistral({
    systemPrompt,
    userMessage,
    expectJson,
    history,
    mediaBase64,
    mediaMimeType,
    mediaItems,
    useVision = false,
}) {
    if (!MISTRAL_API_KEY) {
        const err = new Error('MISTRAL_API_KEY no configurada');
        err.statusCode = 401;
        throw err;
    }

    const model = useVision ? MISTRAL_VISION_MODEL : MISTRAL_MODEL;
    const messages = buildOpenAIMessages({
        systemPrompt,
        userMessage,
        history,
        mediaBase64: useVision ? mediaBase64 : undefined,
        mediaMimeType: useVision ? mediaMimeType : undefined,
        mediaItems: useVision ? mediaItems : undefined,
    });

    const payload = {
        model,
        messages,
        temperature: expectJson ? 0.2 : 0.4,
        ...(expectJson && !useVision && { response_format: { type: 'json_object' } }),
    };

    const response = await axios.post(
        'https://api.mistral.ai/v1/chat/completions',
        payload,
        {
            headers: {
                Authorization: `Bearer ${MISTRAL_API_KEY}`,
                'Content-Type': 'application/json',
            },
            timeout: 45000,
        }
    );

    const text = (response.data?.choices?.[0]?.message?.content || '').trim();
    if (!text) {
        const err = new Error('Mistral devolvió una respuesta vacía');
        err.statusCode = 502;
        throw err;
    }
    return {
        ...response.data,
        text,
        provider: `mistral:${model}`,
    };
}

async function callCloudflareAI({ systemPrompt, userMessage, expectJson, history, model = CLOUDFLARE_MODEL }) {
    if (!CLOUDFLARE_API_TOKEN || !CLOUDFLARE_ACCOUNT_ID) {
        const err = new Error('CLOUDFLARE_API_TOKEN o CLOUDFLARE_ACCOUNT_ID no configurados');
        err.statusCode = 401;
        throw err;
    }

    const messages = buildOpenAIMessages({ systemPrompt, userMessage, history });
    const url = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(CLOUDFLARE_ACCOUNT_ID)}/ai/v1/chat/completions`;
    const payload = {
        model,
        messages,
        temperature: expectJson ? 0.2 : 0.4,
        max_tokens: 2048,
    };

    const response = await axios.post(url, payload, {
        headers: {
            Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
            'Content-Type': 'application/json',
        },
        timeout: 40000,
    });

    const text = (response.data?.choices?.[0]?.message?.content || '').trim();
    if (!text) {
        const err = new Error('Cloudflare Workers AI devolvió una respuesta vacía');
        err.statusCode = 502;
        throw err;
    }
    return {
        ...response.data,
        text,
        provider: `cloudflare:${model}`,
    };
}

async function callOpenRouter({ systemPrompt, userMessage, expectJson, history }) {
    if (!OPENROUTER_API_KEY) {
        const err = new Error('OPENROUTER_API_KEY no configurada');
        err.statusCode = 401;
        throw err;
    }

    const messages = buildOpenAIMessages({ systemPrompt, userMessage, history });
    let lastError = null;

    for (const model of OPENROUTER_MODELS) {
        try {
            const payload = {
                model,
                messages,
                temperature: expectJson ? 0.2 : 0.4,
            };
            const response = await axios.post(
                'https://openrouter.ai/api/v1/chat/completions',
                payload,
                {
                    headers: {
                        Authorization: `Bearer ${OPENROUTER_API_KEY}`,
                        'Content-Type': 'application/json',
                        'HTTP-Referer': 'https://api-gastos-6iri.onrender.com',
                        'X-Title': 'WalletAI-MyLifeOS',
                    },
                    timeout: 45000,
                }
            );
            const text = (response.data?.choices?.[0]?.message?.content || '').trim();
            if (text) {
                return {
                    ...response.data,
                    text,
                    provider: `openrouter:${model}`,
                };
            }
        } catch (err) {
            const status = err.response?.status || err.statusCode || 500;
            const msg = err.response?.data?.error?.message || err.message;
            console.error(`[AI] OpenRouter (${model}) error ${status}:`, msg);
            lastError = err;
        }
    }

    throw lastError || new Error('OpenRouter no devolvió una respuesta válida');
}

async function callNvidia({ systemPrompt, userMessage, expectJson, history }) {
    if (!NVIDIA_API_KEY) {
        const err = new Error('NVIDIA_API_KEY no configurada');
        err.statusCode = 401;
        throw err;
    }
    const messages = buildOpenAIMessages({ systemPrompt, userMessage, history });
    const response = await axios.post(
        'https://integrate.api.nvidia.com/v1/chat/completions',
        {
            model: NVIDIA_MODEL,
            messages,
            temperature: expectJson ? 0.2 : 0.4,
            max_tokens: 2048,
        },
        {
            headers: {
                Authorization: `Bearer ${NVIDIA_API_KEY}`,
                'Content-Type': 'application/json',
            },
            timeout: 45000,
        }
    );
    const text = (response.data?.choices?.[0]?.message?.content || '').trim();
    if (!text) {
        const err = new Error('NVIDIA NIM devolvió una respuesta vacía');
        err.statusCode = 502;
        throw err;
    }
    return {
        ...response.data,
        text,
        provider: `nvidia:${NVIDIA_MODEL}`,
    };
}

async function generateAIResponse({
    systemPrompt,
    userMessage,
    expectJson = false,
    mediaBase64,
    mediaMimeType,
    mediaItems,
    history,
    taskType = 'auto',
}) {
    const errors = [];
    const hasMedia = Boolean(mediaBase64) || (Array.isArray(mediaItems) && mediaItems.length > 0);
    const hasOnlyImages = hasMedia &&
        (!mediaMimeType || String(mediaMimeType).startsWith('image/')) &&
        (!Array.isArray(mediaItems) || mediaItems.every((i) => !i?.mimeType || String(i.mimeType).startsWith('image/')));

    const resolvedTask = taskType !== 'auto'
        ? taskType
        : (hasMedia ? 'vision' : (expectJson ? 'fast_json' : 'chat'));

    const candidates = [];

    const addGemini = () => {
        if (!GEMINI_API_KEY) return;
        const seen = new Set();
        const geminiModels = [GEMINI_MODEL, GEMINI_FALLBACK_MODEL, ...GEMINI_EXTRA_FALLBACKS]
            .map((m) => String(m || '').trim())
            .filter((m) => m && !seen.has(m) && seen.add(m));
        for (const model of geminiModels) {
            candidates.push({
                name: `gemini:${model}`,
                fn: () => callGemini({ systemPrompt, userMessage, expectJson, model, mediaBase64, mediaMimeType, mediaItems, history }),
            });
        }
    };
    const addMistral = (useVision = false) => {
        if (!MISTRAL_API_KEY) return;
        candidates.push({
            name: `mistral:${useVision ? MISTRAL_VISION_MODEL : MISTRAL_MODEL}`,
            fn: () => callMistral({ systemPrompt, userMessage, expectJson, history, mediaBase64, mediaMimeType, mediaItems, useVision }),
        });
    };
    const addCloudflare = () => {
        if (!CLOUDFLARE_API_TOKEN || !CLOUDFLARE_ACCOUNT_ID) return;
        candidates.push({
            name: `cloudflare:${CLOUDFLARE_MODEL}`,
            fn: () => callCloudflareAI({ systemPrompt, userMessage, expectJson, history, model: CLOUDFLARE_MODEL }),
        });
        if (CLOUDFLARE_FALLBACK_MODEL && CLOUDFLARE_FALLBACK_MODEL !== CLOUDFLARE_MODEL) {
            candidates.push({
                name: `cloudflare:${CLOUDFLARE_FALLBACK_MODEL}`,
                fn: () => callCloudflareAI({ systemPrompt, userMessage, expectJson, history, model: CLOUDFLARE_FALLBACK_MODEL }),
            });
        }
    };
    const addOpenRouter = () => {
        if (!OPENROUTER_API_KEY) return;
        candidates.push({
            name: 'openrouter',
            fn: () => callOpenRouter({ systemPrompt, userMessage, expectJson, history }),
        });
    };
    const addNvidia = () => {
        if (!NVIDIA_API_KEY) return;
        candidates.push({
            name: `nvidia:${NVIDIA_MODEL}`,
            fn: () => callNvidia({ systemPrompt, userMessage, expectJson, history }),
        });
    };

    if (hasMedia || resolvedTask === 'vision') {
        // Fotos/video/audio: Gemini primero; Mistral Pixtral como respaldo si son imágenes
        addGemini();
        if (hasOnlyImages) {
            addMistral(true);
        }
    } else if (resolvedTask === 'fast_json') {
        // Voz, autocategorización y JSON rápido: Cloudflare 70B -> OpenRouter -> Mistral -> Gemini
        addCloudflare();
        addOpenRouter();
        addMistral(false);
        addNvidia();
        addGemini();
    } else {
        // Consultor IA, Nutricionista IA y chat analítico
        addCloudflare();
        addGemini();
        addOpenRouter();
        addMistral(false);
        addNvidia();
    }

    for (const candidate of candidates) {
        try {
            const result = await candidate.fn();
            console.log(`[AI] OK via ${result.provider} (task=${resolvedTask})`);
            return result;
        } catch (err) {
            const status = err.response?.status || err.statusCode || 500;
            const msg = err.response?.data?.error?.message || err.message;
            console.error(`[AI] ${candidate.name} error ${status}:`, msg);
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
            mistralConfigured: Boolean(MISTRAL_API_KEY),
            mistralModel: MISTRAL_MODEL,
            cloudflareConfigured: Boolean(CLOUDFLARE_API_TOKEN && CLOUDFLARE_ACCOUNT_ID),
            cloudflareModel: CLOUDFLARE_MODEL,
            openRouterConfigured: Boolean(OPENROUTER_API_KEY),
            openRouterModels: OPENROUTER_MODELS,
            nvidiaConfigured: Boolean(NVIDIA_API_KEY),
        },
        cloudBackupConfigured: Boolean(DATABASE_URL),
    });
});

// ─── Endpoints de IA ──────────────────────────────────────────────────────────

app.post('/api/parse-voice', async (req, res) => {
    try {
        const { systemPrompt, userMessage, taskType } = req.body;
        if (!systemPrompt || !userMessage) {
            return res.status(400).json({ error: 'Faltan parámetros: systemPrompt o userMessage' });
        }

        const expectJson = systemPrompt.includes('JSON EXACTO') ||
            systemPrompt.toLowerCase().includes('devuelve únicamente este objeto json');
        const result = await generateAIResponse({
            systemPrompt,
            userMessage,
            expectJson,
            taskType: taskType || (expectJson ? 'fast_json' : 'chat'),
        });
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
            taskType: 'fast_json',
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
            taskType = 'auto',
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
            taskType: String(taskType || 'auto'),
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
        const displayName = String(req.body.displayName || '').trim() || rawUser;
        const rawEmail = String(req.body.email || '').trim().toLowerCase();
        const email = rawEmail.includes('@') ? rawEmail : null;

        if (rawUser.length < 3) {
            return res.status(400).json({ error: 'El usuario debe tener al menos 3 caracteres.' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres.' });
        }

        const pool = getPool();
        const existing = await pool.query('SELECT id FROM wallet_users WHERE username = $1', [rawUser]);
        if (existing.rows.length > 0) {
            return res.status(409).json({ error: 'Ese nombre de usuario ya está registrado.' });
        }
        if (email) {
            const existingEmail = await pool.query('SELECT id FROM wallet_users WHERE LOWER(email) = $1', [email]);
            if (existingEmail.rows.length > 0) {
                return res.status(409).json({ error: 'Ese correo ya está vinculado a otra cuenta.' });
            }
        }

        const passwordHash = hashPassword(password);
        const recoveryKey = generateRecoveryKey();
        const recoveryKeyHash = hashPassword(normalizeRecoveryKey(recoveryKey));

        const inserted = await pool.query(
            `INSERT INTO wallet_users (username, password_hash, display_name, email, recovery_key_hash)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, username, display_name, email, recovery_key_hash, created_at`,
            [rawUser, passwordHash, displayName, email, recoveryKeyHash]
        );
        const user = inserted.rows[0];
        const token = signToken({ id: user.id, username: user.username });

        return res.status(201).json({
            token,
            user: formatPublicUser(user),
            recoveryKey,
            latestBackup: { exists: false },
            myLifeOSBackup: { exists: false },
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
            `SELECT id, username, password_hash, display_name, email, recovery_key_hash, created_at
             FROM wallet_users
             WHERE username = $1 OR (email IS NOT NULL AND LOWER(email) = $1)`,
            [rawUser]
        );

        if (result.rows.length === 0 || !verifyPassword(password, result.rows[0].password_hash)) {
            return res.status(401).json({ error: 'Usuario o contraseña incorrectos.' });
        }

        const user = result.rows[0];
        const token = signToken({ id: user.id, username: user.username });

        const [backupRes, myLifeRes] = await Promise.all([
            pool.query(
                `SELECT device_id, device_name, schema_version, accounts_count, transactions_count, categories_count, checksum, size_bytes, updated_at
                 FROM wallet_backups WHERE user_id = $1`,
                [user.id]
            ),
            pool.query(
                `SELECT device_id, device_name, schema_version, includes_photos, checksum, size_bytes, updated_at
                 FROM mylifeos_backups WHERE user_id = $1`,
                [user.id]
            ),
        ]);

        return res.json({
            token,
            user: formatPublicUser(user),
            latestBackup: formatBackupMeta(backupRes.rows[0]),
            myLifeOSBackup: formatMyLifeOSBackupMeta(myLifeRes.rows[0]),
        });
    } catch (error) {
        console.error('[AUTH] login error:', error.message);
        return res.status(500).json({ error: 'Error al iniciar sesión en la nube.' });
    }
});

app.get('/api/auth/me', requireAuth, async (req, res) => {
    try {
        if (!(await ensureCloudSchema())) {
            return res.status(503).json({ error: 'CLOUD_DB_NOT_CONFIGURED' });
        }
        const pool = getPool();
        const userRes = await pool.query(
            `SELECT id, username, display_name, email, recovery_key_hash, created_at
             FROM wallet_users WHERE id = $1`,
            [req.user.id]
        );
        if (userRes.rows.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado.' });
        }
        const [backupRes, myLifeRes] = await Promise.all([
            pool.query(
                `SELECT device_id, device_name, schema_version, accounts_count, transactions_count, categories_count, checksum, size_bytes, updated_at
                 FROM wallet_backups WHERE user_id = $1`,
                [req.user.id]
            ),
            pool.query(
                `SELECT device_id, device_name, schema_version, includes_photos, checksum, size_bytes, updated_at
                 FROM mylifeos_backups WHERE user_id = $1`,
                [req.user.id]
            ),
        ]);
        return res.json({
            user: formatPublicUser(userRes.rows[0]),
            latestBackup: formatBackupMeta(backupRes.rows[0]),
            myLifeOSBackup: formatMyLifeOSBackupMeta(myLifeRes.rows[0]),
        });
    } catch (error) {
        console.error('[AUTH] me error:', error.message);
        return res.status(500).json({ error: 'No se pudo consultar el perfil.' });
    }
});

app.patch('/api/auth/profile', requireAuth, async (req, res) => {
    try {
        if (!(await ensureCloudSchema())) {
            return res.status(503).json({ error: 'CLOUD_DB_NOT_CONFIGURED' });
        }
        const pool = getPool();
        const userRes = await pool.query(
            `SELECT id, username, password_hash, display_name, email, recovery_key_hash, created_at
             FROM wallet_users WHERE id = $1`,
            [req.user.id]
        );
        if (userRes.rows.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado.' });
        }
        const current = userRes.rows[0];

        const nextDisplayName = req.body.displayName !== undefined
            ? String(req.body.displayName || '').trim()
            : current.display_name;
        const nextEmailRaw = req.body.email !== undefined
            ? String(req.body.email || '').trim().toLowerCase()
            : (current.email || '');
        const nextEmail = nextEmailRaw.length > 0 ? nextEmailRaw : null;

        if (nextEmail && !nextEmail.includes('@')) {
            return res.status(400).json({ error: 'Ingresa un correo electrónico válido.' });
        }
        if (nextEmail && nextEmail !== (current.email || '').toLowerCase()) {
            const dupEmail = await pool.query(
                'SELECT id FROM wallet_users WHERE LOWER(email) = $1 AND id <> $2',
                [nextEmail, current.id]
            );
            if (dupEmail.rows.length > 0) {
                return res.status(409).json({ error: 'Ese correo ya está en uso en otra cuenta.' });
            }
        }

        let nextUsername = current.username;
        if (req.body.username !== undefined) {
            const candidate = String(req.body.username || '').trim().toLowerCase();
            if (candidate && candidate !== current.username) {
                if (candidate.length < 3) {
                    return res.status(400).json({ error: 'El usuario debe tener al menos 3 caracteres.' });
                }
                const currentPassword = String(req.body.currentPassword || '');
                if (!verifyPassword(currentPassword, current.password_hash)) {
                    return res.status(403).json({ error: 'Contraseña actual incorrecta para cambiar el nombre de usuario.' });
                }
                const dupUser = await pool.query(
                    'SELECT id FROM wallet_users WHERE username = $1 AND id <> $2',
                    [candidate, current.id]
                );
                if (dupUser.rows.length > 0) {
                    return res.status(409).json({ error: 'Ese nombre de usuario ya está ocupado.' });
                }
                nextUsername = candidate;
            }
        }

        const updated = await pool.query(
            `UPDATE wallet_users
             SET username = $1, display_name = $2, email = $3, updated_at = NOW()
             WHERE id = $4
             RETURNING id, username, display_name, email, recovery_key_hash, created_at`,
            [nextUsername, nextDisplayName || nextUsername, nextEmail, current.id]
        );
        const freshUser = updated.rows[0];
        const freshToken = signToken({ id: freshUser.id, username: freshUser.username });

        return res.json({
            success: true,
            token: freshToken,
            user: formatPublicUser(freshUser),
        });
    } catch (error) {
        console.error('[AUTH] profile patch error:', error.message);
        return res.status(500).json({ error: 'No se pudo actualizar el perfil.' });
    }
});

app.post('/api/auth/change-password', requireAuth, async (req, res) => {
    try {
        if (!(await ensureCloudSchema())) {
            return res.status(503).json({ error: 'CLOUD_DB_NOT_CONFIGURED' });
        }
        const currentPassword = String(req.body.currentPassword || '');
        const newPassword = String(req.body.newPassword || '');
        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 6 caracteres.' });
        }

        const pool = getPool();
        const userRes = await pool.query('SELECT id, password_hash FROM wallet_users WHERE id = $1', [req.user.id]);
        if (userRes.rows.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado.' });
        }
        if (!verifyPassword(currentPassword, userRes.rows[0].password_hash)) {
            return res.status(403).json({ error: 'La contraseña actual es incorrecta.' });
        }

        await pool.query(
            'UPDATE wallet_users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
            [hashPassword(newPassword), req.user.id]
        );
        return res.json({ success: true, message: 'Contraseña actualizada correctamente.' });
    } catch (error) {
        console.error('[AUTH] change-password error:', error.message);
        return res.status(500).json({ error: 'No se pudo cambiar la contraseña.' });
    }
});

app.post('/api/auth/recovery-key/regenerate', requireAuth, async (req, res) => {
    try {
        if (!(await ensureCloudSchema())) {
            return res.status(503).json({ error: 'CLOUD_DB_NOT_CONFIGURED' });
        }
        const currentPassword = String(req.body.currentPassword || '');
        const pool = getPool();
        const userRes = await pool.query('SELECT id, password_hash FROM wallet_users WHERE id = $1', [req.user.id]);
        if (userRes.rows.length === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado.' });
        }
        if (!verifyPassword(currentPassword, userRes.rows[0].password_hash)) {
            return res.status(403).json({ error: 'Contraseña actual incorrecta.' });
        }

        const recoveryKey = generateRecoveryKey();
        const recoveryKeyHash = hashPassword(normalizeRecoveryKey(recoveryKey));
        await pool.query(
            'UPDATE wallet_users SET recovery_key_hash = $1, updated_at = NOW() WHERE id = $2',
            [recoveryKeyHash, req.user.id]
        );
        return res.json({ success: true, recoveryKey });
    } catch (error) {
        console.error('[AUTH] recovery-key error:', error.message);
        return res.status(500).json({ error: 'No se pudo generar la clave de recuperación.' });
    }
});

app.post('/api/auth/recover-password', async (req, res) => {
    try {
        if (!(await ensureCloudSchema())) {
            return res.status(503).json({ error: 'CLOUD_DB_NOT_CONFIGURED' });
        }
        const identifier = String(req.body.identifier || req.body.username || '').trim().toLowerCase();
        const recoveryKey = normalizeRecoveryKey(req.body.recoveryKey);
        const newPassword = String(req.body.newPassword || '');

        if (!identifier || !recoveryKey) {
            return res.status(400).json({ error: 'Ingresa tu usuario/correo y tu clave de recuperación.' });
        }
        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 6 caracteres.' });
        }

        const pool = getPool();
        const userRes = await pool.query(
            `SELECT id, username, display_name, email, recovery_key_hash, created_at
             FROM wallet_users
             WHERE username = $1 OR (email IS NOT NULL AND LOWER(email) = $1)`,
            [identifier]
        );
        if (userRes.rows.length === 0 || !userRes.rows[0].recovery_key_hash) {
            return res.status(401).json({ error: 'Cuenta no encontrada o sin clave de recuperación configurada.' });
        }
        const user = userRes.rows[0];
        if (!verifyPassword(recoveryKey, user.recovery_key_hash)) {
            return res.status(401).json({ error: 'Clave de recuperación incorrecta.' });
        }

        await pool.query(
            'UPDATE wallet_users SET password_hash = $1, updated_at = NOW() WHERE id = $2',
            [hashPassword(newPassword), user.id]
        );
        const token = signToken({ id: user.id, username: user.username });
        return res.json({
            success: true,
            token,
            user: formatPublicUser(user),
            message: 'Contraseña restablecida correctamente.',
        });
    } catch (error) {
        console.error('[AUTH] recover-password error:', error.message);
        return res.status(500).json({ error: 'No se pudo restablecer la contraseña.' });
    }
});

app.post('/api/auth/recover-username', async (req, res) => {
    try {
        if (!(await ensureCloudSchema())) {
            return res.status(503).json({ error: 'CLOUD_DB_NOT_CONFIGURED' });
        }
        const email = String(req.body.email || '').trim().toLowerCase();
        const password = String(req.body.password || '');
        const recoveryKey = normalizeRecoveryKey(req.body.recoveryKey);

        if (!email || !email.includes('@')) {
            return res.status(400).json({ error: 'Ingresa el correo electrónico vinculado a tu cuenta.' });
        }
        if (!password && !recoveryKey) {
            return res.status(400).json({ error: 'Ingresa tu contraseña o tu clave de recuperación para verificar identidad.' });
        }

        const pool = getPool();
        const userRes = await pool.query(
            `SELECT id, username, display_name, password_hash, recovery_key_hash
             FROM wallet_users WHERE LOWER(email) = $1`,
            [email]
        );
        if (userRes.rows.length === 0) {
            return res.status(404).json({ error: 'No encontramos ninguna cuenta con ese correo vinculado.' });
        }

        const user = userRes.rows[0];
        const validPass = password && verifyPassword(password, user.password_hash);
        const validKey = recoveryKey && user.recovery_key_hash && verifyPassword(recoveryKey, user.recovery_key_hash);
        if (!validPass && !validKey) {
            return res.status(401).json({ error: 'La contraseña o clave de recuperación no coincide.' });
        }

        return res.json({
            success: true,
            username: user.username,
            displayName: user.display_name || user.username,
        });
    } catch (error) {
        console.error('[AUTH] recover-username error:', error.message);
        return res.status(500).json({ error: 'No se pudo recuperar el usuario.' });
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

// ─── Endpoints de Backup en la Nube de MyLifeOS ───────────────────────────────

app.get('/api/mylifeos/backup/status', requireAuth, async (req, res) => {
    try {
        if (!(await ensureCloudSchema())) {
            return res.status(503).json({ error: 'CLOUD_DB_NOT_CONFIGURED' });
        }
        const pool = getPool();
        const result = await pool.query(
            `SELECT device_id, device_name, schema_version, includes_photos, checksum, size_bytes, updated_at
             FROM mylifeos_backups WHERE user_id = $1`,
            [req.user.id]
        );
        return res.json({
            latestBackup: formatMyLifeOSBackupMeta(result.rows[0]),
        });
    } catch (error) {
        console.error('[MYLIFEOS-BACKUP] status error:', error.message);
        return res.status(500).json({ error: 'Error consultando el respaldo de MyLifeOS.' });
    }
});

app.post('/api/mylifeos/backup/upload', requireAuth, async (req, res) => {
    try {
        if (!(await ensureCloudSchema())) {
            return res.status(503).json({ error: 'CLOUD_DB_NOT_CONFIGURED' });
        }
        const {
            deviceId,
            deviceName,
            schemaVersion = 16,
            includesPhotos = false,
            checksum,
            payloadBase64,
            baseUpdatedAt,
            force = false,
        } = req.body || {};

        if (!deviceId || !checksum || !payloadBase64) {
            return res.status(400).json({ error: 'Faltan datos obligatorios del respaldo de MyLifeOS.' });
        }

        const pool = getPool();
        const existingRes = await pool.query(
            `SELECT device_id, device_name, schema_version, includes_photos, checksum, size_bytes, updated_at
             FROM mylifeos_backups WHERE user_id = $1`,
            [req.user.id]
        );

        if (existingRes.rows.length > 0 && !force) {
            const current = existingRes.rows[0];
            const serverIso = new Date(current.updated_at).toISOString();
            const isDifferentDevice = current.device_id !== deviceId;
            const clientKnowsVersion =
                baseUpdatedAt && new Date(baseUpdatedAt).getTime() >= new Date(current.updated_at).getTime();

            if (isDifferentDevice && !clientKnowsVersion) {
                return res.status(409).json({
                    error: 'CONFLICT_NEWER_BACKUP',
                    message: `Otro dispositivo (${current.device_name}) guardó una copia de MyLifeOS más reciente (${serverIso}).`,
                    latestBackup: formatMyLifeOSBackupMeta(current),
                });
            }
        }

        const sizeBytes = Buffer.byteLength(payloadBase64, 'base64');
        const upsert = await pool.query(
            `INSERT INTO mylifeos_backups (
                user_id, device_id, device_name, schema_version, includes_photos,
                checksum, payload_base64, size_bytes, updated_at
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
             ON CONFLICT (user_id) DO UPDATE SET
                device_id = EXCLUDED.device_id,
                device_name = EXCLUDED.device_name,
                schema_version = EXCLUDED.schema_version,
                includes_photos = EXCLUDED.includes_photos,
                checksum = EXCLUDED.checksum,
                payload_base64 = EXCLUDED.payload_base64,
                size_bytes = EXCLUDED.size_bytes,
                updated_at = NOW()
             RETURNING device_id, device_name, schema_version, includes_photos, checksum, size_bytes, updated_at`,
            [
                req.user.id,
                String(deviceId),
                String(deviceName || 'Android'),
                Number(schemaVersion) || 16,
                Boolean(includesPhotos),
                String(checksum),
                String(payloadBase64),
                sizeBytes,
            ]
        );

        return res.json({
            success: true,
            latestBackup: formatMyLifeOSBackupMeta(upsert.rows[0]),
        });
    } catch (error) {
        console.error('[MYLIFEOS-BACKUP] upload error:', error.message);
        return res.status(500).json({ error: 'No se pudo subir el respaldo de MyLifeOS.' });
    }
});

app.get('/api/mylifeos/backup/download', requireAuth, async (req, res) => {
    try {
        if (!(await ensureCloudSchema())) {
            return res.status(503).json({ error: 'CLOUD_DB_NOT_CONFIGURED' });
        }
        const pool = getPool();
        const result = await pool.query(
            `SELECT device_id, device_name, schema_version, includes_photos, checksum, payload_base64, size_bytes, updated_at
             FROM mylifeos_backups WHERE user_id = $1`,
            [req.user.id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Aún no hay respaldo de MyLifeOS en la nube.' });
        }
        const row = result.rows[0];
        return res.json({
            latestBackup: formatMyLifeOSBackupMeta(row),
            payloadBase64: row.payload_base64,
        });
    } catch (error) {
        console.error('[MYLIFEOS-BACKUP] download error:', error.message);
        return res.status(500).json({ error: 'No se pudo descargar el respaldo de MyLifeOS.' });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Backend running on port ${PORT}`);
});
