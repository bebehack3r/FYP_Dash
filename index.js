import express from 'express';
import sqlite3 from 'sqlite3';
import multer from 'multer';
import path from 'path';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import readline from 'readline';

const secretKey = 'dash_super_secret_key';
const pathToDB = 'database.db';

const app = express();
const port = 8000;

const db = new sqlite3.Database(pathToDB);

// ------ ANALYSIS MIDDLEWARE

const analyzeLogEntry = (logEntry, analysis_res) => {
  const defaultChecks = ['ET SCAN', 'ET POLICY', 'ET INFO'];
  const spots = defaultChecks.map(check => logEntry.includes(check));
  analysis_res.push(spots[0]);
};

// ------ FILESTORAGE MIDDLEWARE

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const timestamp = Date.now();
    cb(null, `${timestamp}-${file.originalname}`);
  }
});
const upload = multer({ storage: storage });

// ------ AUTHENTICATION MIDDLEWARE

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'ERROR', data: 'Unauthorized' });
  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'ERROR', data: 'Forbidden' });
    req.user = decoded.user;
    next();
  });
}

function authenticateRole(roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) return res.status(403).json({ message: 'ERROR', data: 'Insufficient permissions' });
    next();
  };
}

// ------ HEALTHCHECK

app.get('/healthcheck', (req, res) => {
  res.json({ message: 'OK', data: null });
});

// ------ USERS

app.post('/login', (req, res) => {
  const email = req.params.email;
  const pass  = req.params.pass;
  const query = 'SELECT * FROM users WHERE email = ? AND pass = ?';
  db.get(query, [email, pass], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    jwt.sign({ pass: null, ...row }, secretKey, { expiresIn: '24h' }, (err, token) => {
      if (err) return res.status(500).json({ message: 'ERROR', data: 'Failed to generate token' });
      res.json({ message: 'OK', data: token });
    });
  });
});

app.post('/logout', authenticateToken, (req, res) => {
  res.json({ message: 'OK', data: null });
});

app.post('/register', (req, res) => {
  const name  = req.body.name;
  const email = req.body.email;
  const pass  = req.body.pass;
  if (!name || !email || !pass) return res.status(400).json({ message: 'ERROR', data: 'Name, email, and password are required' });
  const query = 'INSERT INTO users (name, email, pass, role) VALUES (?, ?, ?, "user")';
  db.run(query, [name, email, pass], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    res.json({ message: 'OK', data: this.lastID });
  });
});

app.get('/list_users', authenticateToken, (req, res) => {
  let query = 'SELECT * FROM users';
  db.get(query, [], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: row });
  });
});

app.get('/get_user_profile/:id', authenticateToken, (req, res) => {
  const id = req.params.id;
  const query = 'SELECT * FROM users WHERE id = ?';
  db.get(query, [id], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: row });
  });
});

// accessible by all roles
app.post('/update_user_profile', authenticateToken, (req, res) => {
  const id    = req.body.id;
  const name  = req.body.name;
  const email = req.body.email;
  const pass  = req.body.pass;
  const query = 'UPDATE users SET name = ?, email = ?, pass = ? WHERE id = ?';
  db.run(query, [name, email, pass, id], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: null });
  });
});

// accessible by admin role
app.post('/update_user_role', authenticateToken, (req, res) => {
  const id    = req.body.id;
  const role  = req.body.role;
  const query = 'UPDATE users SET role = ? WHERE id = ?';
  db.run(query, [role, id], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: null });
  });
});

app.post('/suspend_user_profile', authenticateToken, (req, res) => {
  const id    = req.body.id;
  const role  = 'suspended';
  const query = 'UPDATE users SET role = ? WHERE id = ?';
  db.run(query, [role, id], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: null });
  });
});

// ------- THREATS

app.post('/create_threat_notification', authenticateToken, (req, res) => {
  const type = req.body.type;
  const desc = req.body.desc;
  const date = req.body.date;
  if (!type || !desc || !date) return res.status(400).json({ message: 'ERROR', data: 'Type, description and date are required' });
  const query = 'INSERT INTO threats (type, desc, date) VALUES (?, ?, ?)';
  db.run(query, [type, desc, date], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    res.json({ message: 'OK', data: this.lastID });
  });
});

app.get('/list_threat_notifications', authenticateToken, (req, res) => {
  let query = 'SELECT * FROM threats';
  db.get(query, [], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: row });
  });
});

app.get('/get_threat_notification/:uuid', authenticateToken, (req, res) => {
  const uuid = req.params.uuid;
  const query = 'SELECT * FROM threats WHERE uuid = ?';
  db.get(query, [uuid], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: row });
  });
});

app.post('/update_threat_notification', authenticateToken, (req, res) => {
  const uuid = req.body.uuid;
  const type = req.body.type;
  const desc = req.body.desc;
  const date = req.body.date;
  const query = 'UPDATE threats SET type = ?, desc = ?, date = ? WHERE uuid = ?';
  db.run(query, [type, desc, date, uuid], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: null });
  });
});

app.post('/remove_threat_notification', authenticateToken, (req, res) => {
  const uuid = req.body.uuid;
  if (!uuid) return res.status(400).json({ message: 'ERROR', data: 'UUID is required' });
  const query = 'DELETE FROM threats WHERE uuid = ?';
  db.run(query, [uuid], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: null });
  });
});

// ------- LOGS

// upload logs
app.post('/upload_log', authenticateToken, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
  const filename = req.file.filename
  if (!filename) return res.status(400).json({ message: 'ERROR', data: 'Filename is required' });
  const query = 'INSERT INTO logs (fname) VALUES (?)';
  db.run(query, [filename], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    res.json({ message: 'OK', data: this.lastID });
  });
});

app.get('/list_logs', authenticateToken, (req, res) => {
  let query = 'SELECT * FROM logs';
  db.get(query, [], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: row });
  });
});

app.get('/get_log/:uuid', authenticateToken, (req, res) => {
  const uuid = req.params.uuid;
  const query = 'SELECT * FROM logs WHERE uuid = ?';
  db.get(query, [uuid], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: row });
  });
});

// ----------
// NO UPDATE FOR LOGS
// ----------

// delete logs
app.post('/remove_log', authenticateToken, (req, res) => {
  const uuid = req.body.uuid;
  if (!uuid) return res.status(400).json({ message: 'ERROR', data: 'UUID is required' });
  const query = 'DELETE FROM logs WHERE uuid = ?';
  db.run(query, [uuid], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: null });
  });
});

// ------- ANALYSIS

app.post('/analyze_log', authenticateToken, (req, res) => {
  const uuid = req.body.uuid;
  if (!uuid) return res.status(400).json({ message: 'ERROR', data: 'UUID is required' });
  const query = 'SELECT * FROM logs WHERE uuid = ?';
  db.get(query, [uuid], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    const analysis_res = [];
    const readInterface = readline.createInterface({
      input: fs.createReadStream(row.fname),
      output: process.stdout,
      console: false
    });
    readInterface.on('line', line => {
      if (line.trim() === '') return;
      analyzeLogEntry(line, analysis_res);
    });
    readInterface.on('close', () => {
      res.json({ message: 'OK', data: analysis_res });
    });
  });
});

app.listen(port, () => console.log(`Server running at http://localhost:${port}`));

