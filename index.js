require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');

const app = express();
const PORT = process.env.PORT || 3000;

// Configuración recomendada para aceptar JSON grandes (base64 imágenes)
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

const GROQ_API_KEY = process.env.GROQ_API_KEY;

app.get('/', (req, res) => {
    res.send('Aplicativo Gastos Backend is running! 🚀');
});

// Endpoint para Voz y Texto General
app.post('/api/parse-voice', async (req, res) => {
    try {
        const { systemPrompt, userMessage } = req.body;

        if (!systemPrompt || !userMessage) {
            return res.status(400).json({ error: 'Faltan parámetros: systemPrompt o userMessage' });
        }

        const payload = {
            model: 'llama-3.3-70b-versatile',
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: userMessage }
            ]
        };

        // Si el prompt explícitamente pide JSON (ej. parseVoiceTransaction), activamos el modo JSON de Groq
        if (systemPrompt.includes('JSON EXACTO')) {
            payload.response_format = { type: 'json_object' };
        }

        const response = await axios.post(
            'https://api.groq.com/openai/v1/chat/completions',
            payload,
            {
                headers: {
                    'Authorization': `Bearer ${GROQ_API_KEY}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        res.json(response.data);
    } catch (error) {
        console.error('Error in /api/parse-voice:', error.response?.data || error.message);
        const realError = error.response?.data?.error?.message || error.message || 'Error procesando la solicitud en la IA';
        res.status(500).json({ error: realError });
    }
});

// Endpoint para Visión (Base64 Receipts)
app.post('/api/parse-receipt', async (req, res) => {
    try {
        const { systemPrompt, textContent, base64Image } = req.body;

        // "base64Image" actually contains the raw OCR text coming from the legacy Flutter payload
        const ocrText = textContent || base64Image;

        if (!systemPrompt || !ocrText) {
            return res.status(400).json({ error: 'Faltan parámetros: systemPrompt o data del recibo' });
        }

        const response = await axios.post(
            'https://api.groq.com/openai/v1/chat/completions',
            {
                model: 'llama-3.3-70b-versatile',
                messages: [
                    { role: 'system', content: systemPrompt },
                    { role: 'user', content: ocrText }
                ],
                ...(systemPrompt.toLowerCase().includes('json') && { response_format: { type: 'json_object' } }),
            },
            {
                headers: {
                    'Authorization': `Bearer ${GROQ_API_KEY}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        res.json(response.data);
    } catch (error) {
        console.error('Error in /api/parse-receipt:', error.response?.data || error.message);
        const realError = error.response?.data?.error?.message || error.message || 'Error procesando el recibo visual';
        res.status(500).json({ error: realError });
    }
});

app.listen(PORT, () => {
    console.log(`🚀 Backend running on port ${PORT}`);
});
