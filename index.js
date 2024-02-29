import express from 'express';
import sqlite3 from 'sqlite3';

const app = express();
const port = 8000;

const db = new sqlite3.Database('database.db');

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  }
});
const upload = multer({ storage: storage });

app.get('/', (req, res) => {
  res.json({ message: 'Hello, world!' });
});

// ------ USERS

app.post('/login', (req, res) => {

});

app.post('/logout', (req, res) => {

});

app.post('/register', (req, res) => {

});

app.get('/list_users', (req, res) => {
  let query = 'SELECT * FROM users';
  db.get(query, [], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: row });
  });
});

app.get('/get_user_profile/:id', (req, res) => {
  const id = req.params.id;
  const query = 'SELECT * FROM users WHERE id = ?';
  db.get(query, [id], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: row });
  });
});

// accessible by all roles
app.post('/update_user_profile', (req, res) => {
  const id    = req.body.id;
  const name  = req.body.name;
  const email = req.body.email;
  const pass  = req.body.pass;
  const query = 'UPDATE threats SET name = ?, email = ?, pass = ? WHERE id = ?';
  db.run(query, [name, email, pass, id], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: null });
  });
});

// accessible by admin role
app.post('/update_user_role', (req, res) => {
  const id    = req.body.id;
  const role  = req.body.role;
  const query = 'UPDATE threats SET role = ? WHERE id = ?';
  db.run(query, [role, id], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: null });
  });
});

app.post('/suspend_user_profile', (req, res) => {
  const id    = req.body.id;
  const role  = 'suspended';
  const query = 'UPDATE threats SET role = ? WHERE id = ?';
  db.run(query, [role, id], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: null });
  });
});

// ------- THREATS

app.post('/create_threat_notification', (req, res) => {

});

app.get('/list_threat_notifications', (req, res) => {
  let query = 'SELECT * FROM threats';
  db.get(query, [], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: row });
  });
});

app.get('/get_threat_notification/:uuid', (req, res) => {
  const uuid = req.params.uuid;
  const query = 'SELECT * FROM threats WHERE uuid = ?';
  db.get(query, [uuid], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: row });
  });
});

app.post('/update_threat_notification', (req, res) => {
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

app.post('/remove_threat_notification', (req, res) => {
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
app.post('/upload_log', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
  res.json({ message: 'File uploaded successfully', filename: req.file.originalname });
});

app.get('/list_logs', (req, res) => {
  let query = 'SELECT * FROM logs';
  db.get(query, [], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: row });
  });
});

app.get('/get_log/:uuid', (req, res) => {
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
app.post('/remove_log', (req, res) => {
  const uuid = req.body.uuid;
  if (!uuid) return res.status(400).json({ message: 'ERROR', data: 'UUID is required' });
  const query = 'DELETE FROM logs WHERE uuid = ?';
  db.run(query, [uuid], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: null });
  });
});

app.listen(port, () => console.log(`Server running at http://localhost:${port}`));

