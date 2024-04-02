export const create = (req, res) => {
  const { logID, type, desc } = req.body;
  const date  = Date.now();
  if (!type || !desc) return res.status(400).json({ message: 'ERROR', data: 'Type and description are required' });
  const query = 'INSERT INTO threats (type, description, date) VALUES (?, ?, ?)';
  req.databaseConnection.run(query, [type, desc, date], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    const query = 'INSERT INTO threatLog (threatID, logID) VALUES (?, ?)';
    req.databaseConnection.run(query, [this.lastID, logID], function(err) {
      if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
      res.json({ message: 'OK', data: this.lastID });
    });
  });
};

export const list = (req, res) => {
  const { id } = req.params;
  if (!id) return res.status(400).json({ message: 'ERROR', data: 'ID is required' });
  let query = 'SELECT * FROM threats WHERE id IN (SELECT threatID FROM threatLog WHERE logID = ?)';
  req.databaseConnection.all(query, [id], (err, rows) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!rows) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: rows });
  });
};

export const get = (req, res) => {
  const { id } = req.params;
  if (!id) return res.status(400).json({ message: 'ERROR', data: 'ID is required' });
  const query = 'SELECT * FROM threats WHERE id = ?';
  req.databaseConnection.get(query, [id], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: row });
  });
};

export const update = (req, res) => {
  const { id, type, desc } = req.body;
  if (!id || !type || !desc) return res.status(400).json({ message: 'ERROR', data: 'All fields are required' });
  const query = 'UPDATE threats SET type = ?, description = ? WHERE id = ?';
  req.databaseConnection.run(query, [type, desc, id], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: null });
  });
};


export const remove = (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ message: 'ERROR', data: 'ID is required' });
  const query = 'DELETE FROM threats WHERE id = ?';
  req.databaseConnection.run(query, [id], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: null });
  });
};