import axios from 'axios';
import { v4 as uuidv4 } from 'uuid';


export const create = (req, res) => {
  const { url } = req.body;
  const { companyID } = req.user;
  if(!url) return res.status(400).json({ message: 'ERROR', data: 'URL is required' });
  const query = 'INSERT INTO apis (url, companyID, uuid) VALUES (?, ?, ?)';
  req.databaseConnection.run(query, [url, companyID, uuidv4()], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    res.json({ message: 'OK', data: this.lastID });
  });
};

export const list = (req, res) => {
  const { companyID } = req.user || -1;
  if(companyID === -1) return res.status(400).json({ message: 'ERROR', data: 'companyID is required' });
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

//function to get severity level based on severity score
const getSeverityLevel = (severity) => {
  if (severity >= 7) {
    return 'High';
  } else if (severity >= 4) {
    return 'Medium';
  } else {
    return 'Low';
  }
};

export const analyze = (req, res) => {
  const { id } = req.body;
  if (!id) return res.status(400).json({ message: 'ERROR', data: 'ID is required' });
  const query = 'SELECT * FROM apis WHERE id = ?';
  req.databaseConnection.get(query, [id], async (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });

    const alerts = [];
    const threatCounts = {};
    const ipCounts = {};
    const topThreats = {};

    try {
      let reqURL = row.url;
      if(!(/https?:\/\//.test(row.url))) reqURL = `http://${row.url}`;
      if(!row.url.includes('.json')) reqURL = `${reqURL}/eve.json`;
      const response = await axios.get(reqURL);
      const logs = response.data;
      const jsons = logs.split('\n');

      for (const raw of jsons) {
        if(raw.length > 0) {
          const entry = JSON.parse(raw);
          const { src_ip, dest_ip, alert, timestamp } = entry;

          // Count occurrences of IP addresses
          ipCounts[src_ip] = (ipCounts[src_ip] || 0) + 1;

          if (alert) {
            const { signature, severity } = alert;
            threatCounts[signature] = (threatCounts[signature] || 0) + severity;
            alerts.push({
              timestamp,
              src_ip,
              dest_ip,
              signature,
              severity,
              severity_level: getSeverityLevel(severity) // Adding severity level
            });
          }
        }
      }


      // console.log('Alerts:', alerts);

      // Calculate top threats
      Object.entries(threatCounts)
        .sort(([, count1], [, count2]) => count2 - count1)
        .forEach(([signature, count]) => {
          topThreats[signature] = count;
        });

      res.json({ 
        message: 'OK', 
        data: { 
          alerts: alerts, 
          contents: logs,
          topThreats: topThreats,
          ipCounts: ipCounts
        } 
      });
    } catch (error) {
      console.error('Error fetching or processing data:', error);
      return res.status(500).json({ message: 'ERROR', data: error.message });
    }
  });
};