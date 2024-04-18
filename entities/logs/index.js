import fs from 'fs';
import path from 'path';
import ipLocation from 'iplocation';
import { v4 as uuidv4 } from 'uuid';

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

//	const analyzeLogEntry = async (logEntry, lineNum, analysis_res) => {
//	  const defaultChecks = [
//		{ entry: 'ET SCAN', type: 'scan' },
//		{ entry: 'ET POLICY', type: 'policy' },
//		{ entry: 'ET INFO', type: 'sus' }
//	  ];
//	  const spots = [];
//	  for(let i = 0; i < defaultChecks.length; i++) {
//		if(logEntry.includes(defaultChecks[i].entry)) {
//		  const reg = /(.*)\[\*\*\] \[[ 0-9:]*\] (.*) \[\*\*\](.*)\{.*\}(.*)->([ 0-9.:]*)(.*)/;
//		  const matches = logEntry.match(reg);
//		  const r = `${matches[matches.length-1]} ${matches[2]} ${matches[3]}`;
//		  const ip = filterIP(logEntry);
//		  console.log(ip);
//		  spots.push({ 
//			threatType: defaultChecks[i].type, 
//			sourceLine: r,
//			lineNumber: lineNum,
//			ipAddress: ip,
//			ipLocation: await fetchIPLocation(ip)
//		  });
//		}
//	  };
//	  spots.map(spot => { if(spot) analysis_res.push(spot) });
//	};

const analyzeLogEntry = async (logEntry, lineNum, analysis_res) => {
  try {
    // Extract relevant fields from the parsed JSON data
    const {
      EventReceivedTime,
      SourceModuleName,
      SourceModuleType,
      EventName,
      Classification,
      EventTime,
      SourceIPAddress,
      DestinationIPAddress
    } = logEntry;

    // Determine threat type based on Classification
    let threatType  = 'Unknown';
    if (Classification === 'Generic ICMP event') {
      threatType = 'ICMP'; // Set threat type to 'ICMP' for Generic ICMP events
    }

    // Construct the analysis result object
    const analysisResult = {
      threatType: threatType,
      sourceLine: EventName,
      lineNumber: lineNum,
      ipAddress: SourceIPAddress,
      ipLocation: await fetchIPLocation(SourceIPAddress), // Assuming async IP location lookup
      eventReceivedTime: EventReceivedTime,
      sourceModuleName: SourceModuleName,
      sourceModuleType: SourceModuleType,
      eventTime: EventTime,
      destinationIPAddress: DestinationIPAddress
    };

    // Push the analysis result into the analysis_res array
    analysis_res.push(analysisResult);
  } catch (error) {
    console.error('Error parsing or analyzing log entry:', error);
    // Handle error (e.g., log or throw error)
  }
};

export const create = (req, res) => {
  if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
  const { companyID } = req.user;
  const { filename } = req.file;
  if (!filename) return res.status(400).json({ message: 'ERROR', data: 'Filename is required' });
  const query = 'INSERT INTO logs (fname, companyID, uuid) VALUES (?, ?, ?)';
  req.databaseConnection.run(query, [filename, companyID, uuidv4()], function(err) {
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
  const analysis_res = [];
  const { id } = req.body;
  if (!id) return res.status(400).json({ message: 'ERROR', data: 'ID is required' });
  let query = 'SELECT * FROM logs WHERE id = ?';
  req.databaseConnection.get(query, [id], (err, row) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!row) return res.status(404).json({ message: 'NULL', data: null });
    const p = path.join(path.resolve(), `uploads/${row.fname}`);
    fs.readFile(p, { encoding: 'utf-8' }, (err, contents) => {
      if(err) return res.status(500).json({ message: 'ERROR', data: err });
      try {
        let parsed = JSON.parse(contents);
        if(!Array.isArray(parsed)) parsed = [parsed]; // converting a single entry log file into an array
        const pr = new Promise((resolve, reject) => {
          parsed.forEach((el, i, arr) => {
            analyzeLogEntry(el, ++inc, analysis_res);
            if (i === arr.length -1) resolve();
          });
        });
        pr.then(() => res.json({ message: 'OK', data: { contents, alerts: analysis_res }}));
      } catch(error) {
        return res.status(500).json({ message: 'ERROR', data: error });
      }
    });
  });
};