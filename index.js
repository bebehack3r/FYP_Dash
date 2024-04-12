import 'dotenv/config';
import express from 'express';
import { json } from 'express';
import path from 'path';
import cors from 'cors';
import sqlite3 from 'sqlite3';
import multer from 'multer';
import jwt from 'jsonwebtoken';
import requestIp from 'request-ip';

import { 
  login as loginUser, logout as logoutUser, create as createUser, 
  list as listUsers, superList as superListUsers, get as getUser, 
  update as updateUser, promote as promoteUser, suspend as suspendUser 
} from './entities/users/index.js';
import { 
  create as createCompany, list as listCompanies, 
  get as getCompany, approve as approveCompany 
} from './entities/companies/index.js';
import {
  create as createThreat, list as listThreats,
  get as getThreat, update as updateThreat,
  remove as removeThreat
} from './entities/threats/index.js';
import {
  create as createLog, list as listLogs,
  get as getLog, remove as removeLog,
  analyze as analyzeLogs
} from './entities/logs/index.js';
import {
  create as createAPI, list as listAPIs,
  get as getAPI, remove as removeAPI,
  analyze as analyzeAPI
} from './entities/suricata/index.js';

const secretKey = process.env.SECRET_KEY;
const app = express();
app.use(cors());
app.use(json());
// app.use(requestIp.mw());
const port = process.env.DEVEL_PORT;
console.log(process.env.PATH_TO_DB);
const db = new sqlite3.Database(process.env.PATH_TO_DB);

// ------ FILESTORAGE
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    const timestamp = Date.now();
    cb(null, `${timestamp}-${file.originalname}`);
  }
});
const upload = multer({ storage: storage });
// ------ MIDDLEWARE
function supplyDatabase(req, res, next) {
  if(!db) return res.status(401).json({ message: 'ERROR', data: 'Backend down' });
  req.databaseConnection = db;
  next();
};
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'ERROR', data: 'Unauthorized' });
  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) return res.status(403).json({ message: 'ERROR', data: 'Forbidden' });
    req.user = decoded;
    next();
  });
};
function authenticateRole(roles) {
  return (req, res, next) => {
    if (!req.user || !roles.includes(req.user.role)) return res.status(403).json({ 
      message: 'ERROR', data: 'Insufficient permissions' 
    });
    next();
  };
};
function logRequest(req, res, next) {
  const query = 'INSERT INTO activity (ip, body, endpoint, date) VALUES (?, ?, ?, ?)';
  req.databaseConnection.run(query, [req.clientIp, req.body || req.params, req.originalUrl, Date.now()], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    next();
  });
};
// ------ HEALTHCHECK
app.get('/healthcheck', supplyDatabase, logRequest, (req, res) => {
  res.json({ message: 'OK', data: null });
});
// ------ SAMPLE EVE
app.get('/eve.json', (req, res) => {
  res.sendFile(path.join(process.cwd(), 'eve.json'));
});
// ------ INIT
app.get('/initiate_work', supplyDatabase, logRequest, (req, res) => {
  const query = 'INSERT INTO users (name, email, pass, role, companyID) VALUES (?, ?, ?, ?, ?)';
  req.databaseConnection.run(query, ['admin', 'admin@dash.org', 'dashdashdash', 'gigaAdmin', 0], function(err) {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    res.json({ message: 'OK', data: this.lastID });
  });
});
// ------- PROMO
app.get('/promo_data', (req, res) => {
  const amountOfCompanies = 'SELECT * FROM users WHERE role = ?';
  const amountOfThreats = 'SELECT * FROM threats';
  let amountOfAttacks = 0;
  db.all(amountOfCompanies, ['admin'], (err, companies) => {
    if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
    if (!companies) return res.status(404).json({ message: 'NULL', data: null });
    db.all(amountOfThreats, [], (err, threats) => {
      if (err) return res.status(500).json({ message: 'ERROR', data: err.message });
      if (!threats) return res.status(404).json({ message: 'NULL', data: null });
      amountOfAttacks = (threats.length * 100) / companies.length;
      res.json({ message: 'OK', data: { 
        companies: companies.length * 30, 
        threats: threats.length * 200, 
        attacks: amountOfAttacks 
      } });
    });
  });
});

app.post('/register_company',             authenticateToken, supplyDatabase, logRequest, createCompany);
app.get('/list_companies',                authenticateToken, supplyDatabase, logRequest, listCompanies);
app.get('/get_company/:id',               authenticateToken, supplyDatabase, logRequest, getCompany);
app.post('/approve_company',                                 supplyDatabase, logRequest, approveCompany);

app.post('/login',                                           supplyDatabase, logRequest, loginUser);
app.post('/logout',                       authenticateToken, supplyDatabase, logRequest, logoutUser);
app.post('/register',                     authenticateToken, supplyDatabase, logRequest, createUser);
app.get('/list_users',                    authenticateToken, supplyDatabase, logRequest, listUsers);
app.get('/get_user_profile/:id',          authenticateToken, supplyDatabase, logRequest, getUser);
app.post('/update_user_profile',          authenticateToken, supplyDatabase, logRequest, updateUser);
app.post('/update_user_role',             authenticateToken, supplyDatabase, logRequest, promoteUser);
app.post('/suspend_user_profile',         authenticateToken, supplyDatabase, logRequest, suspendUser);

app.post('/create_threat_notification',   authenticateToken, supplyDatabase, logRequest, createThreat);
app.get('/list_threat_notifications/:id', authenticateToken, supplyDatabase, logRequest, listThreats);
app.get('/get_threat_notification/:id',   authenticateToken, supplyDatabase, logRequest, getThreat);
app.post('/update_threat_notification',   authenticateToken, supplyDatabase, logRequest, updateThreat);
app.post('/remove_threat_notification',   authenticateToken, supplyDatabase, logRequest, removeThreat);

app.post('/upload_log',                   authenticateToken, supplyDatabase, logRequest, upload.single('file'), createLog);
app.get('/list_logs',                     authenticateToken, supplyDatabase, logRequest, listLogs);
app.get('/get_log/:id',                   authenticateToken, supplyDatabase, logRequest, getLog);
app.post('/remove_log',                   authenticateToken, supplyDatabase, logRequest, removeLog);
app.post('/analyze_log',                  authenticateToken, supplyDatabase, logRequest, analyzeLogs);

app.post('/add_endpoint',                 authenticateToken, supplyDatabase, createAPI);
app.get('/list_endpoints',                authenticateToken, supplyDatabase, logRequest, listAPIs);
app.get('/get_endpoint/:id',              authenticateToken, supplyDatabase, logRequest, getAPI);
app.post('/remove_endpoint',              authenticateToken, supplyDatabase, logRequest, removeAPI);
app.post('/analyze_endpoint',             authenticateToken, supplyDatabase, logRequest, analyzeAPI);

app.listen(port, () => console.log(`Server running at http://localhost:${port}`));

