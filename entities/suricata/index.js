import axios from 'axios';

export const create = (req, res) => {
  const { url } = req.body;
  const { companyID } = req.user;
  if(!url) return res.status(400).json({ message: 'ERROR', data: 'URL is required' });
  const query = 'INSERT INTO apis (url, companyID) VALUES (?, ?)';
  req.databaseConnection.run(query, [url, companyID], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    res.json({ message: 'OK', data: this.lastID });
  });
};

export const list = (req, res) => {
  const { companyID } = req.user;
  if(!url) return res.status(400).json({ message: 'ERROR', data: 'URL is required' });
  const query = 'SELECT * FROM apis WHERE companyID = ?';
  req.databaseConnection.all(query, [companyID], (err, rows) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!rows) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: rows });
  });
};

export const get = (req, res) => {
  const { id } = req.params;
  if(!id) return res.status(400).json({ message: 'ERROR', data: 'ID is required' });
  const query = 'SELECT * FROM apis WHERE id = ?';
  req.databaseConnection.get(query, [id], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: row });
  });
};

export const remove = (req, res) => {
  const { id } = req.body;
  if(!id) return res.status(400).json({ message: 'ERROR', data: 'ID is required' });
  const query = 'DELETE FROM apis WHERE id = ?';
  req.databaseConnection.run(query, [id], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: null });
  });
};

export const analyze = (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ message: 'ERROR', data: 'ID is required' });
  const query = 'SELECT * FROM apis WHERE id = ?';
  req.databaseConnection.get(query, [id], async (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    const response = await axios.get(`${row.url}/eve.json`);
    const logs = response.data;
    res.json(logs);
  });
};