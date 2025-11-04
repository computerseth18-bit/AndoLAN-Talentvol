// AndoLAN demo server with OIDC + SQLite users
// Run: node server.js
require('dotenv').config();
const express = require('express');
const cookie = require('cookie-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const { Issuer, generators } = require('openid-client');
const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
const SECRET = process.env.JWT_SECRET || 'change-me';
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

const db = new Database('andolan.db');
db.prepare(`CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sub TEXT UNIQUE,
  provider TEXT,
  username TEXT UNIQUE,
  name TEXT,
  email TEXT UNIQUE,
  role TEXT DEFAULT 'leerling',
  password_hash TEXT
);`).run();
// === GLOBAL PASSWORD RESET (per request) ===
// Zet voor alle gebruikers het wachtwoord op 'welkom2025' (of DEFAULT_PASSWORD uit .env)
try {
  const defaultPassword = process.env.DEFAULT_PASSWORD || 'welkom2025';
  const newHash = bcrypt.hashSync(defaultPassword, 10);
  const info = db.prepare('UPDATE users SET password_hash = ?').run(newHash);
  console.log(`Alle wachtwoorden gereset naar '${defaultPassword}' voor ${info.changes} gebruikers.`);
} catch (e) {
  console.warn('Reset van wachtwoorden mislukt:', e.message);
}


app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookie());
app.use(express.static(__dirname));

const sign = (uid) => jwt.sign({ sub: uid }, SECRET, { expiresIn: '7d' });
const setSession = (res, token) => res.cookie('ando_token', token, { httpOnly: true, sameSite: 'lax', secure: false, maxAge: 7*24*3600*1000 });
const auth = (req, res, next)=>{
  const t = req.cookies['ando_token'];
  if(!t) return res.status(401).json({message:'Niet ingelogd'});
  try { req.userId = jwt.verify(t, SECRET).sub; next(); } catch { return res.status(401).json({message:'Niet ingelogd'}); }
};

async function getClient(kind){
  if(kind==='microsoft'){
    const issuer = await Issuer.discover(process.env.OIDC_MS_ISSUER);
    return new issuer.Client({
      client_id: process.env.OIDC_MS_CLIENT_ID,
      client_secret: process.env.OIDC_MS_CLIENT_SECRET,
      redirect_uris: [`${BASE_URL}/auth/microsoft/callback`],
      response_types: ['code']
    });
  }
  if(kind==='google'){
    const issuer = await Issuer.discover(process.env.OIDC_GOOGLE_ISSUER || 'https://accounts.google.com');
    return new issuer.Client({
      client_id: process.env.OIDC_GOOGLE_CLIENT_ID,
      client_secret: process.env.OIDC_GOOGLE_CLIENT_SECRET,
      redirect_uris: [`${BASE_URL}/auth/google/callback`],
      response_types: ['code']
    });
  }
  throw new Error('Unknown provider');
}

async function startAuth(kind, req, res){
  try{
    const client = await getClient(kind);
    const state = generators.state();
    const url = client.authorizationUrl({
      scope: (kind==='microsoft'? process.env.OIDC_MS_SCOPE : (process.env.OIDC_GOOGLE_SCOPE || 'openid profile email')),
      state
    });
    res.cookie(`state_${kind}`, state, { httpOnly:true, sameSite:'lax' });
    res.redirect(url);
  }catch(e){
    console.error(e);
    res.status(500).send('Kon niet verbinden met provider');
  }
}

async function finishAuth(kind, req, res){
  try{
    const client = await getClient(kind);
    const state = req.cookies[`state_${kind}`];
    const params = client.callbackParams(req);
    const tokenSet = await client.callback(`${BASE_URL}/auth/${kind}/callback`, params, { state });
    const claims = tokenSet.claims();
    const sub = claims.sub;
    const email = claims.email || claims.preferred_username;
    const name = claims.name || email || 'Gebruiker';

    const row = db.prepare('SELECT * FROM users WHERE sub=?').get(sub);
    let id;
    if(row){ id = row.id; }
    else {
      const info = db.prepare('INSERT INTO users(sub, provider, name, email, role) VALUES(?,?,?,?,?)')
        .run(sub, kind, name, email, 'leerling');
      id = info.lastInsertRowid;
    }

    const token = sign(id);
    setSession(res, token);
    res.redirect('/');
  }catch(e){
    console.error(e);
    res.status(500).send('Callback mislukt');
  }
}

app.get('/auth/microsoft', (req,res)=> startAuth('microsoft', req, res));
app.get('/auth/google', (req,res)=> startAuth('google', req, res));
app.get('/auth/microsoft/callback', (req,res)=> finishAuth('microsoft', req, res));
app.get('/auth/google/callback', (req,res)=> finishAuth('google', req, res));

// Optional local login for testing
app.post('/api/login', async (req, res)=>{
  const { username, password } = req.body || {};
  if(!username || !password) return res.status(400).json({message:'Vul alle velden in'});
  const user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if(!user) return res.status(401).json({message:'Onjuiste gegevens'});
  const ok = await bcrypt.compare(password, user.password_hash || '');
  if(!ok) return res.status(401).json({message:'Onjuiste gegevens'});
  const token = sign(user.id);
  setSession(res, token);
  res.json({ user: { name: user.name, email: user.email, role: user.role } });
});

app.post('/api/logout', (req, res)=>{ res.clearCookie('ando_token'); res.json({ok:true}); });

app.get('/api/me', auth, (req, res)=>{
  const user = db.prepare('SELECT id, name, email, role FROM users WHERE id=?').get(req.userId);
  if(!user) return res.status(404).json({message:'Onbekende gebruiker'});
  res.json({ user });
});

// Seed a local test user if none exists
try {
  const count = db.prepare('SELECT COUNT(*) as c FROM users WHERE username IS NOT NULL').get().c;
  if(count === 0){
    const hash = bcrypt.hashSync(process.env.DEFAULT_PASSWORD || 'welkom2025', 10);
    db.prepare('INSERT INTO users(username, name, email, role, password_hash) VALUES(?,?,?,?,?)')
      .run('student1', 'Student Eén', 'student1@school.nl', 'leerling', hash);
    console.log('Demo gebruiker aangemaakt: student1 / wachtwoord1');
  }
} catch(e){ console.warn('Kon demo-gebruiker niet seeden:', e.message); }

// Seed Admin account
try {
  const adminExists = db.prepare('SELECT * FROM users WHERE username = ?').get('Admin-Talentvol');
  if (!adminExists) {
    const hash = bcrypt.hashSync(process.env.DEFAULT_PASSWORD || 'welkom2025', 10);
    db.prepare('INSERT INTO users(username, name, email, role, password_hash) VALUES(?,?,?,?,?)')
      .run('Admin-Talentvol', 'Talentvol Beheerder', 'admin@talentvol.nl', 'admin', hash);
    console.log('Admin account aangemaakt: Admin-Talentvol / seth');
  }
} catch (err) {
  console.warn('Kon admin niet aanmaken:', err.message);
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log(`AndoLAN demo draait op ${BASE_URL}`));
