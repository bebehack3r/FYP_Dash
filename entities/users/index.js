import 'dotenv/config';
import jwt from 'jsonwebtoken';

const secretKey = process.env.SECRET_KEY;

export const login = (req, res) => {
  const { email, pass } = req.body;
  if (!email || !pass) return res.status(400).json({ message: 'ERROR', data: 'email, and password are required' });
  const query = 'SELECT * FROM users WHERE email = ? AND pass = ?';
  req.databaseConnection.get(query, [email, pass], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    if (row.role === 'suspended') res.json({ message: 'ERROR', data: 'Your account has been suspended, please contact your admin for further asssistance.' });
    jwt.sign({ ...row, pass: null }, secretKey, { expiresIn: '24h' }, (err, token) => {
      if (err) return res.status(500).json({ message: 'ERROR', data: 'Failed to generate token' });
      res.json({ message: 'OK', data: token });
    });
  });
};

export const logout = (req, res) => {
  res.json({ message: 'OK', data: null });
};

export const create = (req, res) => {
  const { name, email, pass, role } = req.body;
  const companyID = req.user.companyID;
  if (!name || !email || !pass || !role) return res.status(400).json({ message: 'ERROR', data: 'Name, email, and password are required' });
  const check = 'SELECT name FROM users WHERE email = ?';
  req.databaseConnection.get(check, [email], (cerr, row) => {
    if(cerr) return res.status(500).json({message: 'ERROR', data: cerr.message});
    if(row) return res.status(400).json({message: 'ERROR', data: 'E-mail already in use.'});
    const query = 'INSERT INTO users (name, email, pass, role, companyID) VALUES (?, ?, ?, ?, ?)';
    req.databaseConnection.run(query, [name, email, pass, role, companyID], function(err) {
      if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
      res.json({ message: 'OK', data: this.lastID });
    });
  });
};

export const list = (req, res) => {
  const companyID = req.user.companyID;
  let query = 'SELECT * FROM users WHERE companyID = ?';
  req.databaseConnection.all(query, [companyID], (err, rows) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!rows) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: rows });
  });
};

export const superList = (req, res) => {
  let query = 'SELECT * FROM users';
  req.databaseConnection.all(query, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!rows) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: rows });
  });
};

export const get = (req, res) => {
  const { id } = req.params;
  if (!id) return res.status(400).json({ message: 'ERROR', data: 'ID is required' });
  const query = 'SELECT * FROM users WHERE id = ?';
  req.databaseConnection.get(query, [id], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: { ...row, pass: null } });
  });
};

export const update = (req, res) => {
  const { id, name, email, pass } = req.body;
  if (!id || !name || !email || !pass) return res.status(400).json({ message: 'ERROR', data: 'All fields are required' });
  const query = 'UPDATE users SET name = ?, email = ?, pass = ? WHERE id = ?';
  req.databaseConnection.run(query, [name, email, pass, id], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: null });
  });
};

export const promote = (req, res) => {
  const { id, role } = req.body;
  if (!id || !role) return res.status(400).json({ message: 'ERROR', data: 'ID and role are required' });
  const query = 'UPDATE users SET role = ? WHERE id = ?';
  req.databaseConnection.run(query, [role, id], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: null });
  });
};

export const suspend = (req, res) => {
  const { id } = req.body;
  const role  = 'suspended';
  if (!id) return res.status(400).json({ message: 'ERROR', data: 'ID is required' });
  const query = 'UPDATE users SET role = ? WHERE id = ?';
  req.databaseConnection.run(query, [role, id], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: null });
  });
};