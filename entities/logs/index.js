import fs from 'fs';
import path from 'path';
import readline from 'readline';
import ipLocation from 'iplocation';

const filterIP = (line) => {
  const ipReg = /\} (.*) \-\>/;
  const ipAddr = line.match(ipReg);
  return ipAddr[1];
};

const fetchIPLocation = async (source) => {
  const ip = source.split(':')[0];
  const split = ip.split('.');
  if(split[0] == '10' || split[0] == '100') return null;
  if((split[0] == '172' && (+split[1] >= 16 && +split[1] <= 31)) || (split[0] == '192' && split[1] == '168')) return null;
  try {
    const location = await ipLocation(source.split(':')[0]);
    if(location.latitude) return [location.latitude, location.longitude].join(',');
    return null;
  } catch(err) {
    return null;
  }
};

const analyzeLogEntry = async (logEntry, lineNum, analysis_res) => {
  const defaultChecks = [
    { entry: 'ET SCAN', type: 'scan' },
    { entry: 'ET POLICY', type: 'policy' },
    { entry: 'ET INFO', type: 'sus' }
  ];
  const spots = [];
  for(let i = 0; i < defaultChecks.length; i++) {
    if(logEntry.includes(defaultChecks[i].entry)) {
      console.log('HUH?');
      const ip = filterIP(logEntry);
      console.log(ip);
      spots.push({ 
        threatType: defaultChecks[i].type, 
        sourceLine: logEntry, 
        lineNumber: lineNum,
        ipAddress: ip,
        ipLocation: await fetchIPLocation(ip)
      });
    }
  };
  spots.map(spot => { if(spot) analysis_res.push(spot) });
};

export const create = (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
  const { companyID } = req.user;
  const { filename } = req.file;
  if (!filename) return res.status(400).json({ message: 'ERROR', data: 'Filename is required' });
  const query = 'INSERT INTO logs (fname, companyID) VALUES (?, ?)';
  req.databaseConnection.run(query, [filename, companyID], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    res.json({ message: 'OK', data: this.lastID });
  });
};

export const list = (req, res) => {
  let query = 'SELECT * FROM logs WHERE companyID = ?';
  req.databaseConnection.all(query, [req.user.companyID], (err, rows) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!rows) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: rows });
  });
};

export const get = (req, res) => {
  const { id } = req.params;
  if(!id) return res.status(400).json({ message: 'ERROR', data: 'ID is required' });
  const query = 'SELECT * FROM logs WHERE id = ?';
  req.databaseConnection.get(query, [id], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    const p = path.join(path.resolve(), `uploads/${row.fname}`);
    fs.readFile(p, { encoding: 'utf-8' }, (err, data) => {
      if (!err) res.json({ message: 'OK', data: data });
      else res.status(500).json({ message: 'ERROR', data: err });
    });
  });
};

export const remove = (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ message: 'ERROR', data: 'ID is required' });
  const query = 'DELETE FROM logs WHERE id = ?';
  req.databaseConnection.run(query, [id], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (this.changes === 0) return res.status(404).json({ message: 'NULL', data: null });
    res.json({ message: 'OK', data: null });
  });
};

export const analyze = (req, res) => {
  let inc = 0;
  const { id } = req.body;
  if (!id) return res.status(400).json({ message: 'ERROR', data: 'ID is required' });
  let query = 'SELECT * FROM logs WHERE id = ?';
  req.databaseConnection.get(query, [id], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    query = 'SELECT * FROM autodetected WHERE logID = ?';
    req.databaseConnection.all(query, [id], (err, rows) => {
      if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
      if (!rows.length) {
        const p = path.join(path.resolve(), `uploads/${row.fname}`);
        const analysis_res = [];
        const readInterface = readline.createInterface({
          input: fs.createReadStream(p),
          output: process.stdout,
          console: false
        });
        readInterface.on('line', line => {
          inc++;
          if (line.trim() === '') return;
          analyzeLogEntry(line, inc, analysis_res);
        });
        readInterface.on('close', () => {
          req.databaseConnection.serialize(() => {
            req.databaseConnection.run('BEGIN TRANSACTION');
            const stmt = req.databaseConnection.prepare('INSERT INTO autodetected (logID, threatType, sourceLine, lineNumber, ipAddress, ipLocation) VALUES (?, ?, ?, ?, ?, ?)');
            analysis_res.forEach(obj => stmt.run(id, obj.threatType, obj.sourceLine, obj.lineNumber, obj.ipAddress, obj.ipLocation));
            req.databaseConnection.run('COMMIT', (err) => {
              if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
            });
            stmt.finalize();
          });
          res.json({ message: 'OK', data: analysis_res });
        });
      } else return res.json({ message: 'OK', data: rows });
    });
  });
};