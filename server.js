import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { v4 as uuidv4 } from 'uuid';
import Database from 'better-sqlite3';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

// ---------- Config básica ----------
const app = express();
const PORT = process.env.PORT || 3000;
const ORIGIN = process.env.FRONTEND_ORIGIN || '';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Seguridad/CORS
app.use(helmet({
  crossOriginResourcePolicy: false,
}));
app.use(express.json());
app.use(cookieParser(process.env.COOKIE_SECRET || 'dev-secret'));

// Si servís frontend desde otro dominio, habilitalo:
if (ORIGIN) {
  app.use(cors({
    origin: ORIGIN,
    credentials: true
  }));
}

// Rate limit (protege POST /vote y creación de token inicial)
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minuto
  max: 60,             // 60 req/min/IP (ajustable)
});
app.use(limiter);

// ---------- DB (SQLite) ----------
const db = new Database('votes.db');
db.pragma('journal_mode = WAL');

// Tablas
db.exec(`
CREATE TABLE IF NOT EXISTS options (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS voters (
  token TEXT PRIMARY KEY,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS votes (
  token TEXT PRIMARY KEY,
  option_id TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  ip TEXT,
  ua TEXT,
  FOREIGN KEY(option_id) REFERENCES options(id)
);
`);

// Inicializá tus carrozas acá (EDITÁ ESTO con tus nombres reales)
const DEFAULT_OPTIONS = [
  { id: 'carroza_1', label: 'Carroza 1' },
  { id: 'carroza_2', label: 'Carroza 2' },
  { id: 'carroza_3', label: 'Carroza 3' }
];

const insertOption = db.prepare('INSERT OR IGNORE INTO options (id, label) VALUES (@id, @label)');
for (const opt of DEFAULT_OPTIONS) insertOption.run(opt);

// ---------- Utilidades ----------
const getCounts = () => {
  const opts = db.prepare('SELECT id, label FROM options').all();
  const counts = db.prepare(`
    SELECT option_id AS id, COUNT(*) AS count FROM votes GROUP BY option_id
  `).all();
  const map = Object.fromEntries(counts.map(c => [c.id, c.count]));
  const total = counts.reduce((a, c) => a + c.count, 0);

  return opts.map(o => ({
    id: o.id,
    label: o.label,
    count: map[o.id] || 0,
    total
  }));
};

const getClientIp = (req) => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString().split(',')[0].trim();

// ---------- Cookie de votante ----------
const ensureVoterCookie = (req, res, next) => {
  let token = req.signedCookies['voter'];
  if (!token) {
    token = uuidv4();
    // Guardamos el votante
    db.prepare('INSERT OR IGNORE INTO voters (token) VALUES (?)').run(token);
    // Cookie HTTP-Only firmada
    res.cookie('voter', token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: !!process.env.VERCEL || process.env.NODE_ENV === 'production',
      signed: true,
      maxAge: 1000 * 60 * 60 * 24 * 90 // 90 días
    });
  }
  req.voterToken = token;
  next();
};

// ---------- SSE (tiempo real) ----------
const sseClients = new Set();

const broadcast = () => {
  const data = JSON.stringify({ type: 'counts', payload: getCounts() });
  for (const res of sseClients) {
    res.write(`data: ${data}\n\n`);
  }
};

app.get('/events', (req, res) => {
  // Cabeceras SSE
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
  });
  res.flushHeaders?.();

  // Enviar snapshot inicial
  res.write(`data: ${JSON.stringify({ type: 'counts', payload: getCounts() })}\n\n`);

  sseClients.add(res);
  req.on('close', () => {
    sseClients.delete(res);
  });
});

// ---------- Rutas API ----------
app.get('/api/options', (req, res) => {
  const rows = db.prepare('SELECT id, label FROM options').all();
  res.json(rows);
});

app.get('/api/results', (req, res) => {
  res.json(getCounts());
});

app.post('/api/vote', ensureVoterCookie, (req, res) => {
  const { optionId } = req.body || {};
  if (!optionId) return res.status(400).json({ error: 'Falta optionId' });

  // Comprobar que la opción exista
  const opt = db.prepare('SELECT id FROM options WHERE id = ?').get(optionId);
  if (!opt) return res.status(404).json({ error: 'Opción inexistente' });

  const token = req.voterToken;
  const existing = db.prepare('SELECT token FROM votes WHERE token = ?').get(token);
  if (existing) {
    return res.status(409).json({ error: 'Ya votaste' });
  }

  // Guardar voto
  const ip = getClientIp(req);
  const ua = (req.headers['user-agent'] || '').slice(0, 255);
  try {
    db.prepare('INSERT INTO votes (token, option_id, ip, ua) VALUES (?, ?, ?, ?)').run(token, optionId, ip, ua);
  } catch (e) {
    return res.status(500).json({ error: 'No se pudo registrar el voto' });
  }

  // Notificar a todos por SSE
  broadcast();
  res.json({ ok: true });
});

// ---------- Servir frontend estático (opcional) ----------
app.use(express.static(path.join(__dirname, 'public')));

// Healthcheck
app.get('/health', (_, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`);
});
