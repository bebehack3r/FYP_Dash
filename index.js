import 'dotenv/config';
import express from 'express';
import { json } from 'express';
import cors from 'cors';
import sqlite3 from 'sqlite3';
import multer from 'multer';
import jwt from 'jsonwebtoken';

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
const port = process.env.DEVEL_PORT;
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
// ------ HEALTHCHECK
app.get('/healthcheck', (req, res) => {
  res.json({ message: 'OK', data: null });
});
// ------ INIT
app.get('/initiate_work', (req, res) => {
  const query = 'INSERT INTO users (name, email, pass, role, companyID) VALUES (?, ?, ?, ?, ?)';
  db.run(query, ['admin', 'admin@dash.org', 'dashdashdash', 'gigaAdmin', 0], function(err) {
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

app.post('/register_company',             authenticateToken, supplyDatabase, createCompany);
app.get('/list_companies',                authenticateToken, supplyDatabase, listCompanies);
app.get('/get_company/:id',               authenticateToken, supplyDatabase, getCompany);
app.post('/approve_company',                                 supplyDatabase, approveCompany);

app.post('/login',                                           supplyDatabase, loginUser);
app.post('/logout',                       authenticateToken, supplyDatabase, logoutUser);
app.post('/register',                     authenticateToken, supplyDatabase, createUser);
app.get('/list_users',                    authenticateToken, supplyDatabase, listUsers);
app.get('/get_user_profile/:id',          authenticateToken, supplyDatabase, getUser);
app.post('/update_user_profile',          authenticateToken, supplyDatabase, updateUser);
app.post('/update_user_role',             authenticateToken, supplyDatabase, promoteUser);
app.post('/suspend_user_profile',         authenticateToken, supplyDatabase, suspendUser);

app.post('/create_threat_notification',   authenticateToken, supplyDatabase, createThreat);
app.get('/list_threat_notifications/:id', authenticateToken, supplyDatabase, listThreats);
app.get('/get_threat_notification/:id',   authenticateToken, supplyDatabase, getThreat);
app.post('/update_threat_notification',   authenticateToken, supplyDatabase, updateThreat);
app.post('/remove_threat_notification',   authenticateToken, supplyDatabase, removeThreat);

app.post('/upload_log',                   authenticateToken, supplyDatabase, upload.single('file'), createLog);
app.get('/list_logs',                     authenticateToken, supplyDatabase, listLogs);
app.get('/get_log/:id',                   authenticateToken, supplyDatabase, getLog);
app.post('/remove_log',                   authenticateToken, supplyDatabase, removeLog);
app.post('/analyze_log',                  authenticateToken, supplyDatabase, analyzeLogs);

app.post('/add_endpoint',                 authenticateToken, supplyDatabase, createAPI);
app.get('/list_endpoints',                authenticateToken, supplyDatabase, listAPIs);
app.get('/get_endpoint/:id',              authenticateToken, supplyDatabase, getAPI);
app.post('/remove_endpoint',              authenticateToken, supplyDatabase, removeAPI);
app.post('/analyze_endpoint',             authenticateToken, supplyDatabase, analyzeAPI);

app.listen(port, () => console.log(`Server running at http://localhost:${port}`));

