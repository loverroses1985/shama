/**
 * Basic Express backend
 * - Serves static frontend from /public
 * - REST API: /api/auth/register, /api/auth/login
 * - CRUD /api/forms
 * - File upload /api/upload
 * - Uses SQLite (better-sqlite3)
 */
const express = require('express');
const cors = require('cors');
const path = require('path');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'replace_this_with_a_secure_secret';

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve frontend static files
app.use(express.static(path.join(__dirname, 'public')));

// Initialize DB
const dbFile = path.join(__dirname, 'data.db');
const db = new Database(dbFile);
db.pragma('journal_mode = WAL');

// Create tables if not exist
db.prepare(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password_hash TEXT,
  role TEXT DEFAULT 'user',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS forms (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  title TEXT,
  data TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id)
)`).run();

// Simple seed: create admin user if none exists
const adminExists = db.prepare("SELECT COUNT(*) AS c FROM users WHERE role='admin'").get();
if (adminExists.c === 0) {
  const hash = bcrypt.hashSync('admin123', 10);
  db.prepare("INSERT OR IGNORE INTO users (username, password_hash, role) VALUES (?, ?, ?)").run('admin', hash, 'admin');
  console.log('Seeded admin / password: admin123 (change immediately in production)');
}

// Auth helpers
function generateToken(user) {
  const payload = { id: user.id, username: user.username, role: user.role };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
}

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
  const token = auth.slice(7);
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Routes
app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  const exists = db.prepare("SELECT id FROM users WHERE username = ?").get(username);
  if (exists) return res.status(409).json({ error: 'username already exists' });
  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").run(username, hash);
  const user = db.prepare("SELECT id, username, role FROM users WHERE id = ?").get(info.lastInsertRowid);
  const token = generateToken(user);
  res.json({ user, token });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  const user = db.prepare("SELECT id, username, password_hash, role FROM users WHERE username = ?").get(username);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  const ok = bcrypt.compareSync(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
  const token = generateToken(user);
  res.json({ user: { id: user.id, username: user.username, role: user.role }, token });
});

// CRUD for forms
app.get('/api/forms', authMiddleware, (req, res) => {
  const rows = db.prepare("SELECT * FROM forms WHERE user_id = ? ORDER BY created_at DESC").all(req.user.id);
  res.json(rows);
});
app.post('/api/forms', authMiddleware, (req, res) => {
  const { title, data } = req.body;
  const info = db.prepare("INSERT INTO forms (user_id, title, data) VALUES (?, ?, ?)").run(req.user.id, title || null, data ? JSON.stringify(data) : null);
  const row = db.prepare("SELECT * FROM forms WHERE id = ?").get(info.lastInsertRowid);
  res.json(row);
});
app.get('/api/forms/:id', authMiddleware, (req, res) => {
  const row = db.prepare("SELECT * FROM forms WHERE id = ? AND user_id = ?").get(req.params.id, req.user.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(row);
});
app.put('/api/forms/:id', authMiddleware, (req, res) => {
  const { title, data } = req.body;
  db.prepare("UPDATE forms SET title = ?, data = ? WHERE id = ? AND user_id = ?").run(title || null, data ? JSON.stringify(data) : null, req.params.id, req.user.id);
  const row = db.prepare("SELECT * FROM forms WHERE id = ?").get(req.params.id);
  res.json(row);
});
app.delete('/api/forms/:id', authMiddleware, (req, res) => {
  db.prepare("DELETE FROM forms WHERE id = ? AND user_id = ?").run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// File uploads
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
const storage = multer.diskStorage({
  destination: function (req, file, cb) { cb(null, uploadDir); },
  filename: function (req, file, cb) { cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g,'_')); }
});
const upload = multer({ storage });
app.post('/api/upload', authMiddleware, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'file required' });
  res.json({ filename: req.file.filename, path: '/uploads/' + req.file.filename });
});
app.use('/uploads', express.static(uploadDir));

// Fallback to index.html for SPA routing
app.get('*', (req, res) => {
  const index = path.join(__dirname, 'public', 'index.html');
  if (require('fs').existsSync(index)) return res.sendFile(index);
  res.status(404).send('Not found');
});

app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});