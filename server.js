const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = 3000;
const DB_PATH = path.join(__dirname, 'db.json');
const JWT_SECRET = 'ielts_secret_key_2025';

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── DB helpers ──
function readDB() {
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}
function writeDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

// ── Auth middleware ──
function auth(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// ── Routes ──

// Register
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const db = readDB();
  if (db.users.find(u => u.username.toLowerCase() === username.toLowerCase()))
    return res.status(409).json({ error: 'Username already taken' });
  const hash = await bcrypt.hash(password, 10);
  const user = { id: Date.now().toString(), username, password: hash, startDate: new Date().toISOString().slice(0, 10) };
  db.users.push(user);
  writeDB(db);
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username: user.username, startDate: user.startDate });
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const db = readDB();
  const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (!user) return res.status(401).json({ error: 'User not found' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: 'Wrong password' });
  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, username: user.username, startDate: user.startDate });
});

// Get checks for a date
app.get('/api/checks/:date', auth, (req, res) => {
  const db = readDB();
  const key = `${req.user.id}_${req.params.date}`;
  res.json(db.checks[key] || {});
});

// Save checks for a date
app.post('/api/checks/:date', auth, (req, res) => {
  const db = readDB();
  const key = `${req.user.id}_${req.params.date}`;
  db.checks[key] = req.body;
  writeDB(db);
  res.json({ ok: true });
});

// Get all dates with data for this user (for calendar)
app.get('/api/calendar', auth, (req, res) => {
  const db = readDB();
  const prefix = `${req.user.id}_`;
  const result = {};
  for (const [k, v] of Object.entries(db.checks)) {
    if (k.startsWith(prefix)) {
      const date = k.slice(prefix.length);
      const total = Object.keys(v).length;
      const done = Object.values(v).filter(Boolean).length;
      result[date] = { total, done };
    }
  }
  res.json(result);
});

// Overall stats: all users, per day
app.get('/api/stats', auth, (req, res) => {
  const db = readDB();
  // Per-day completion across all users
  const byDate = {};
  for (const [k, v] of Object.entries(db.checks)) {
    const parts = k.split('_');
    const date = parts[parts.length - 1];
    const userId = parts.slice(0, parts.length - 1).join('_');
    const user = db.users.find(u => u.id === userId);
    if (!user) continue;
    if (!byDate[date]) byDate[date] = { users: 0, totalTasks: 0, doneTasks: 0, completedUsers: [] };
    const total = Object.keys(v).length;
    const done = Object.values(v).filter(Boolean).length;
    byDate[date].users++;
    byDate[date].totalTasks += total;
    byDate[date].doneTasks += done;
    if (total > 0 && done === total) byDate[date].completedUsers.push(user.username);
  }
  const userList = db.users.map(u => {
    // calc streak
    let streak = 0;
    const today = new Date();
    for (let i = 0; i < 60; i++) {
      const d = new Date(today.getTime() - i * 86400000).toISOString().slice(0, 10);
      const key = `${u.id}_${d}`;
      const v = db.checks[key] || {};
      const total = Object.keys(v).length;
      const done = Object.values(v).filter(Boolean).length;
      if (total > 0 && done === total) streak++;
      else if (i > 0) break;
    }
    return { username: u.username, startDate: u.startDate, streak };
  });
  res.json({ byDate, users: userList });
});

app.listen(PORT, () => console.log(`IELTS Tracker running on http://localhost:${PORT}`));
