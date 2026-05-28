const express = require('express');
const session = require('express-session');
const bcrypt  = require('bcryptjs');
const Database = require('better-sqlite3');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const fs   = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Database setup ────────────────────────────────────────────────
const DB_DIR = path.join(__dirname, 'db');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

const db = new Database(path.join(DB_DIR, 'porter.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    name      TEXT    NOT NULL,
    email     TEXT    NOT NULL UNIQUE,
    password  TEXT    NOT NULL,
    photo     TEXT,
    created   INTEGER DEFAULT (strftime('%s','now'))
  );
  CREATE TABLE IF NOT EXISTS user_data (
    user_id   INTEGER NOT NULL,
    key       TEXT    NOT NULL,
    value     TEXT,
    updated   INTEGER DEFAULT (strftime('%s','now')),
    PRIMARY KEY (user_id, key),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// ── Middleware ─────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: DB_DIR }),
  secret: process.env.SESSION_SECRET || 'porter-secret-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 days
}));

// ── Auth middleware ────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.status(401).json({ error: 'Not authenticated' });
}

// ── Auth routes ───────────────────────────────────────────────────
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be 6+ characters' });
  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
  if (existing) return res.status(409).json({ error: 'Account already exists with that email' });
  const hash = await bcrypt.hash(password, 10);
  const result = db.prepare('INSERT INTO users (name, email, password) VALUES (?, ?, ?)').run(name, email.toLowerCase(), hash);
  req.session.userId = result.lastInsertRowid;
  req.session.userEmail = email.toLowerCase();
  const user = db.prepare('SELECT id, name, email, photo FROM users WHERE id = ?').get(result.lastInsertRowid);
  res.json({ ok: true, user });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
  if (!user) return res.status(401).json({ error: 'No account found with that email' });
  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(401).json({ error: 'Incorrect password' });
  req.session.userId = user.id;
  req.session.userEmail = user.email;
  res.json({ ok: true, user: { id: user.id, name: user.name, email: user.email, photo: user.photo } });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, name, email, photo FROM users WHERE id = ?').get(req.session.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user });
});

app.put('/api/me', requireAuth, async (req, res) => {
  const { name, password, photo } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  let newHash = user.password;
  if (password && password.length >= 6) newHash = await bcrypt.hash(password, 10);
  db.prepare('UPDATE users SET name = ?, password = ?, photo = ? WHERE id = ?')
    .run(name || user.name, newHash, photo !== undefined ? photo : user.photo, user.id);
  const updated = db.prepare('SELECT id, name, email, photo FROM users WHERE id = ?').get(user.id);
  res.json({ ok: true, user: updated });
});

// ── Data sync routes (tasks, photos, comments, done days) ─────────
app.get('/api/data/:key', requireAuth, (req, res) => {
  const row = db.prepare('SELECT value FROM user_data WHERE user_id = ? AND key = ?')
    .get(req.session.userId, req.params.key);
  res.json({ value: row ? row.value : null });
});

app.put('/api/data/:key', requireAuth, (req, res) => {
  const { value } = req.body;
  db.prepare(`
    INSERT INTO user_data (user_id, key, value, updated) VALUES (?, ?, ?, strftime('%s','now'))
    ON CONFLICT(user_id, key) DO UPDATE SET value = excluded.value, updated = excluded.updated
  `).run(req.session.userId, req.params.key, value);
  res.json({ ok: true });
});

app.get('/api/data', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT key, value FROM user_data WHERE user_id = ?').all(req.session.userId);
  const data = {};
  rows.forEach(r => { data[r.key] = r.value; });
  res.json({ data });
});

// ── Serve app ──────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Porter app running on port ${PORT}`));
