import cors from 'cors';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { validateRuntimeConfig } from './database/supabase.js';
import { authRouter } from './routes/authRoutes.js';
import { eventRouter } from './routes/eventRoutes.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

validateRuntimeConfig();

const app = express();
app.set('trust proxy', 1);
const sdkCors = cors({
  origin: true,
  credentials: false,
  methods: ['GET', 'HEAD', 'OPTIONS']
});

app.use(express.json());
app.use('/sdk', sdkCors, express.static(path.join(__dirname, '../sdk')));
app.use('/api/auth', authRouter);
app.use('/api', eventRouter);
app.use('/', express.static(path.join(__dirname, '../dashboard')));

export { app };
