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

export const analyze = async (req, res) => {
  try{
    const { id } = req.body;
    if (!id) {
    return res.status(400).json({ message: 'ERROR', data: 'ID is required' });
  }
  const query = 'SELECT * FROM apis WHERE id = ?';
  req.databaseConnection.get(query, [id], async (err, row) => {
    if (err) {
      return res.status(500).json({ message: 'ERROR', data: err.message });
    }
    if (!row) {
      return res.status(404).json({ message: 'NULL', data: null });
    }
    
    
    const response = await axios.get(`${row.url}/eve.json`);
    const logs = response.data;
    //peform detailed analysis on the logs
    const analyzedData = analyzeLogs(logs);

    //Store the analyzed data to the database or perform further processing
    //for demo purpose,, assume storing the analyzed data in a variable
    const alerts = analyzedData.filter(log => log.event_type === 'alert');
    const droppedPackets = analyzedData.filter(log => log.event_type === 'drop');

    // Generate visualizations or reports summarizing the findings
    const visualizationData = generateVisualizationData(analyzedData);
    res.json({ message: 'OK', data: { alerts: alerts.length, droppedPackets: droppedPackets.length, visualizationData } });
    });
  } catch (error) {
    res.status(500).json({ message: 'ERROR', data: error.message });
  }
};

// Function to perform detailed analysis on the logs and extract relevant information
const analyzeLogs = (logs) => {
  return logs.map(entry => {
    const { timestamp, src_ip, dest_ip, proto, alert, event_type } = entry;
    let details = {};
    if (alert) {
      const { signature, category, severity } = alert;
      details = { signature, category, severity };
    }
    return {
      timestamp,
      src_ip,
      dest_ip,
      proto,
      event_type,
      alert: details
    };
  });
};

const generateVisualizationData = (analyzedData) => {
  // Initialize variables to store summary data
  let alertCounts = {};
  let totalAlerts = 0;

  // Count the number of alerts for each category
  analyzedData.forEach(log => {
    if (log.event_type === 'alert') {
      const category = log.alert.category || 'Uncategorized';
      alertCounts[category] = (alertCounts[category] || 0) + 1;
      totalAlerts++;
    }
  });

  // Generate a summary report
  const summaryReport = {
    totalAlerts,
    alertCounts
  };

  return summaryReport;
};