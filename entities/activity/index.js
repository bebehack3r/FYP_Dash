export const list = (req, res) => {
  let query = 'SELECT * FROM activity';
  req.databaseConnection.all(query, [], (err, rows) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!rows) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: rows });
  });
};