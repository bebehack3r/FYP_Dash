export const create = (req, res) => {
  const { 
    name, email, pass, verifyPass,
    companyName, companyPosition, companyEmployeeAmount
  } = req.body;
  if (
    !name || !email || !pass || !verifyPass || 
    !companyName || !companyPosition || !companyEmployeeAmount
  ) return res.status(400).json({ message: 'ERROR', data: 'All fields are required' });
  if (pass != verifyPass) return res.status(400).json({ message: 'ERROR', data: 'Passwords do not match' });
  let query = 'INSERT INTO companies (companyName, companyPosition, companyEmployeeAmount, approved) VALUES (?, ?, ?, ?)';
  req.databaseConnection.run(query, [companyName, companyPosition, companyEmployeeAmount, false], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    query = 'INSERT INTO users (name, email, pass, role, companyID) VALUES (?, ?, ?, ?, ?)';
    req.databaseConnection.run(query, [name, email, pass, 'superAdmin', this.lastID], function(err) {
      if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
      res.json({ message: 'OK', data: this.lastID });
    });
  });
};

export const list = (req, res) => {
  let query = 'SELECT * FROM companies';
  req.databaseConnection.all(query, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!rows) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: rows });
  });
};

export const get = (req, res) => {
  const { id } = req.params;
  const query = 'SELECT * FROM companies WHERE id = ?';
  req.databaseConnection.get(query, [id], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: row });
  });
};

export const approve = (req, res) => {
  const { id, decision } = req.body;
  if (!id || !decision) return res.status(400).json({ message: 'ERROR', data: 'All fields are required' });
  let query = 'UPDATE companies SET approved = ? WHERE id = ?';
  req.databaseConnection.run(query, [id, decision], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    res.json({ message: 'OK', data: null });
  });
};