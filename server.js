const express  = require('express');
const session  = require('express-session');
const bcrypt   = require('bcryptjs');
const Datastore = require('nedb');
const path     = require('path');
const fs       = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Database setup (NeDB — pure JS, no compilation needed) ────────
const DB_DIR = process.env.RENDER
  ? '/opt/render/project/src/db'
  : path.join(__dirname, 'db');

if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });

const users = new Datastore({ filename: path.join(DB_DIR, 'users.db'),    autoload: true });
const data  = new Datastore({ filename: path.join(DB_DIR, 'data.db'),     autoload: true });

users.ensureIndex({ fieldName: 'email', unique: true });
data.ensureIndex({  fieldName: 'userKey', unique: true });

// ── Middleware ─────────────────────────────────────────────────────
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'porter-secret-2026-ctcrm',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 }
}));

// ── Auth middleware ────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  res.status(401).json({ error: 'Not authenticated' });
}

// ── Promisify NeDB ─────────────────────────────────────────────────
function dbFind(db, query)      { return new Promise((r,e) => db.find(query,     (err,d) => err ? e(err) : r(d))); }
function dbFindOne(db, query)   { return new Promise((r,e) => db.findOne(query,  (err,d) => err ? e(err) : r(d))); }
function dbInsert(db, doc)      { return new Promise((r,e) => db.insert(doc,     (err,d) => err ? e(err) : r(d))); }
function dbUpdate(db, q, u, o)  { return new Promise((r,e) => db.update(q, u, o,(err,d) => err ? e(err) : r(d))); }

// ── Auth routes ───────────────────────────────────────────────────
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'All fields required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be 6+ characters' });
    const exists = await dbFindOne(users, { email: email.toLowerCase() });
    if (exists) return res.status(409).json({ error: 'Account already exists with that email' });
    const hash = await bcrypt.hash(password, 10);
    const user = await dbInsert(users, { name, email: email.toLowerCase(), password: hash, photo: null, created: Date.now() });
    req.session.userId  = user._id;
    req.session.userEmail = user.email;
    res.json({ ok: true, user: { id: user._id, name: user.name, email: user.email, photo: user.photo } });
  } catch(e) {
    console.error('Signup error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    const user = await dbFindOne(users, { email: email.toLowerCase() });
    if (!user) return res.status(401).json({ error: 'No account found with that email' });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Incorrect password' });
    req.session.userId    = user._id;
    req.session.userEmail = user.email;
    res.json({ ok: true, user: { id: user._id, name: user.name, email: user.email, photo: user.photo } });
  } catch(e) {
    console.error('Login error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ ok: true });
});

app.get('/api/me', requireAuth, async (req, res) => {
  const user = await dbFindOne(users, { _id: req.session.userId });
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ user: { id: user._id, name: user.name, email: user.email, photo: user.photo } });
});

app.put('/api/me', requireAuth, async (req, res) => {
  try {
    const { name, password, photo } = req.body;
    const user = await dbFindOne(users, { _id: req.session.userId });
    if (!user) return res.status(404).json({ error: 'User not found' });
    const update = { $set: {} };
    if (name)              update.$set.name  = name;
    if (photo !== undefined) update.$set.photo = photo;
    if (password && password.length >= 6) update.$set.password = await bcrypt.hash(password, 10);
    await dbUpdate(users, { _id: user._id }, update, {});
    const updated = await dbFindOne(users, { _id: user._id });
    res.json({ ok: true, user: { id: updated._id, name: updated.name, email: updated.email, photo: updated.photo } });
  } catch(e) {
    console.error('Update error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// ── Data sync ─────────────────────────────────────────────────────
app.get('/api/data/:key', requireAuth, async (req, res) => {
  const row = await dbFindOne(data, { userKey: req.session.userId + '_' + req.params.key });
  res.json({ value: row ? row.value : null });
});

app.put('/api/data/:key', requireAuth, async (req, res) => {
  const userKey = req.session.userId + '_' + req.params.key;
  await dbUpdate(data,
    { userKey },
    { $set: { userKey, value: req.body.value, updated: Date.now() } },
    { upsert: true }
  );
  res.json({ ok: true });
});

// ── Health check (keeps Render awake via UptimeRobot) ─────────────
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// ── Serve app ──────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => console.log(`Porter app running on port ${PORT}`));
    
