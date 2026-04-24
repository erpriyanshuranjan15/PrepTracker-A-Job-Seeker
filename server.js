/**
 * PrepTracker — Full Dynamic Backend (MongoDB Atlas)
 * Fixes: 405 on PUT/DELETE, findOneAndUpdate v6 return, ObjectId validation
 * npm install && node server.js
 */
const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const { MongoClient, ObjectId } = require('mongodb');

const PORT      = process.env.PORT       || 3000;
const MONGO_URI = process.env.MONGO_URI  || 'mongodb+srv://erpriyanshuranjan0515_db_user:ylWAGcXksoMZ088l@cluster0.tkione7.mongodb.net/?appName=Cluster0';
const DB_NAME   = process.env.DB_NAME    || 'preptracker';
const SECRET    = process.env.JWT_SECRET || 'preptracker-secret-2025';

// ─────────────────────────────────────────────
// MongoDB
// ─────────────────────────────────────────────
let db;
async function connectMongo() {
  const client = new MongoClient(MONGO_URI, { serverSelectionTimeoutMS: 10000 });
  await client.connect();
  db = client.db(DB_NAME);
  await db.collection('users').createIndex({ email: 1 }, { unique: true });
  await db.collection('goals').createIndex({ userId: 1 });
  await db.collection('companies').createIndex({ userId: 1 });
  await db.collection('notes').createIndex({ userId: 1 });
  await db.collection('skills').createIndex({ userId: 1, category: 1 });
  await db.collection('checklists').createIndex({ userId: 1 }, { unique: true });
  await db.collection('resumes').createIndex({ userId: 1 });
  console.log('✅  MongoDB connected →', DB_NAME);
}

// ─────────────────────────────────────────────
// Safe ObjectId — returns null if invalid string
// ─────────────────────────────────────────────
function toOid(id) {
  try { return new ObjectId(id); } catch { return null; }
}

// ─────────────────────────────────────────────
// JWT (no extra deps)
// ─────────────────────────────────────────────
function signToken(payload) {
  const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const b = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const s = crypto.createHmac('sha256', SECRET).update(`${h}.${b}`).digest('base64url');
  return `${h}.${b}.${s}`;
}
function verifyToken(token) {
  try {
    const [h, b, s] = token.split('.');
    const expected = crypto.createHmac('sha256', SECRET).update(`${h}.${b}`).digest('base64url');
    if (s !== expected) return null;
    const p = JSON.parse(Buffer.from(b, 'base64url').toString());
    if (p.exp && Date.now() > p.exp) return null;
    return p;
  } catch { return null; }
}
function hashPw(pw) { return crypto.createHmac('sha256', SECRET).update(pw).digest('hex'); }

// ─────────────────────────────────────────────
// HTTP helpers
// ─────────────────────────────────────────────
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let d = '';
    req.on('data', c => (d += c));
    req.on('end', () => { try { resolve(d ? JSON.parse(d) : {}); } catch { reject(new Error('Invalid JSON')); } });
    req.on('error', reject);
  });
}

function send(res, status, body) {
  const json = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(json),
  });
  res.end(json);
}

function getAuth(req) {
  const a = req.headers['authorization'] || '';
  const t = a.startsWith('Bearer ') ? a.slice(7) : null;
  return t ? verifyToken(t) : null;
}

// Serialise Mongo doc → plain object with string ids
function serial(doc) {
  if (!doc) return null;
  const d = { ...doc };
  if (d._id)    d._id    = d._id.toString();
  if (d.userId && typeof d.userId !== 'string') d.userId = d.userId.toString();
  return d;
}

// ─────────────────────────────────────────────
// findOneAndUpdate helper — MongoDB v6 returns
// the doc directly (not {value: doc})
// ─────────────────────────────────────────────
async function findAndUpdate(col, filter, update, options = {}) {
  // returnDocument:'after' returns the updated doc directly in driver v6
  const result = await col.findOneAndUpdate(filter, update, {
    returnDocument: 'after',
    ...options,
  });
  // driver v5 wraps in {value}, driver v6 returns directly
  if (result && result.value !== undefined) return result.value;
  return result;
}

// ─────────────────────────────────────────────
// Static file server
// ─────────────────────────────────────────────
const MIME = {
  '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript',
  '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.woff2': 'font/woff2', '.woff': 'font/woff',
};
function serveStatic(req, res) {
  const fp = path.join(__dirname, req.url === '/' ? 'index.html' : req.url).split('?')[0];
  fs.readFile(fp, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/html' }); res.end('<h2>404 Not Found</h2>'); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(fp).toLowerCase()] || 'application/octet-stream' });
    res.end(data);
  });
}

// ─────────────────────────────────────────────
// Auth  POST /api/auth/register|login
// ─────────────────────────────────────────────
async function handleAuth(req, res, action) {
  if (req.method !== 'POST') return send(res, 405, { error: 'Method not allowed' });

  if (action === 'register') {
    const { name, email, password } = await parseBody(req);
    if (!name || !email || !password) return send(res, 400, { error: 'name, email and password required' });
    if (password.length < 6) return send(res, 400, { error: 'Password must be at least 6 characters' });
    try {
      const r = await db.collection('users').insertOne({ name, email, password: hashPw(password), createdAt: new Date() });
      const user = { _id: r.insertedId.toString(), name, email };
      return send(res, 201, { token: signToken({ userId: user._id, email, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 }), user });
    } catch (e) {
      if (e.code === 11000) return send(res, 409, { error: 'Email already registered' });
      throw e;
    }
  }

  if (action === 'login') {
    const { email, password } = await parseBody(req);
    if (!email || !password) return send(res, 400, { error: 'email and password required' });
    const doc = await db.collection('users').findOne({ email, password: hashPw(password) });
    if (!doc) return send(res, 401, { error: 'Invalid credentials' });
    const user = { _id: doc._id.toString(), name: doc.name, email: doc.email };
    return send(res, 200, { token: signToken({ userId: user._id, email, exp: Date.now() + 30 * 24 * 60 * 60 * 1000 }), user });
  }

  return send(res, 404, { error: 'Auth action not found' });
}

// ─────────────────────────────────────────────
// Goals  GET|POST /api/goals   PUT|DELETE /api/goals/:id
// ─────────────────────────────────────────────
async function handleGoals(req, res, id, userId) {
  const col = db.collection('goals');

  if (req.method === 'GET' && !id) {
    const docs = await col.find({ userId }).sort({ createdAt: -1 }).toArray();
    return send(res, 200, docs.map(serial));
  }

  if (req.method === 'POST' && !id) {
    const { goalTitle, category, status, deadline } = await parseBody(req);
    if (!goalTitle) return send(res, 400, { error: 'goalTitle required' });
    const doc = {
      userId, goalTitle,
      category: category || 'dsa',
      status: status || 'pending',
      deadline: deadline || null,
      createdAt: new Date(), updatedAt: new Date(),
    };
    const r = await col.insertOne(doc);
    return send(res, 201, serial({ ...doc, _id: r.insertedId }));
  }

  if (req.method === 'PUT' && id) {
    const oid = toOid(id);
    if (!oid) return send(res, 400, { error: 'Invalid id' });
    const body = await parseBody(req);
    delete body._id; delete body.userId;
    body.updatedAt = new Date();
    const updated = await findAndUpdate(col, { _id: oid, userId }, { $set: body });
    if (!updated) return send(res, 404, { error: 'Goal not found' });
    return send(res, 200, serial(updated));
  }

  if (req.method === 'DELETE' && id) {
    const oid = toOid(id);
    if (!oid) return send(res, 400, { error: 'Invalid id' });
    const r = await col.deleteOne({ _id: oid, userId });
    if (!r.deletedCount) return send(res, 404, { error: 'Goal not found' });
    return send(res, 200, { deleted: true });
  }

  return send(res, 405, { error: 'Method not allowed' });
}

// ─────────────────────────────────────────────
// Companies
// ─────────────────────────────────────────────
async function handleCompanies(req, res, id, userId) {
  const col = db.collection('companies');

  if (req.method === 'GET' && !id) {
    const docs = await col.find({ userId }).sort({ createdAt: -1 }).toArray();
    return send(res, 200, docs.map(serial));
  }

  if (req.method === 'POST' && !id) {
    const { companyName, role, applicationStatus, prep, emoji, color, topics, notes } = await parseBody(req);
    if (!companyName || !role) return send(res, 400, { error: 'companyName and role required' });
    const doc = {
      userId, companyName, role,
      applicationStatus: applicationStatus || 'prep',
      prep: Number(prep) || 0,
      emoji: emoji || companyName.charAt(0).toUpperCase(),
      color: color || '#7A3F91',
      topics: topics || [],
      notes: notes || '',
      createdAt: new Date(), updatedAt: new Date(),
    };
    const r = await col.insertOne(doc);
    return send(res, 201, serial({ ...doc, _id: r.insertedId }));
  }

  if (req.method === 'PUT' && id) {
    const oid = toOid(id);
    if (!oid) return send(res, 400, { error: 'Invalid id' });
    const body = await parseBody(req);
    delete body._id; delete body.userId;
    body.updatedAt = new Date();
    const updated = await findAndUpdate(col, { _id: oid, userId }, { $set: body });
    if (!updated) return send(res, 404, { error: 'Company not found' });
    return send(res, 200, serial(updated));
  }

  if (req.method === 'DELETE' && id) {
    const oid = toOid(id);
    if (!oid) return send(res, 400, { error: 'Invalid id' });
    const r = await col.deleteOne({ _id: oid, userId });
    if (!r.deletedCount) return send(res, 404, { error: 'Company not found' });
    return send(res, 200, { deleted: true });
  }

  return send(res, 405, { error: 'Method not allowed' });
}

// ─────────────────────────────────────────────
// Notes
// ─────────────────────────────────────────────
async function handleNotes(req, res, id, userId) {
  const col = db.collection('notes');

  if (req.method === 'GET' && !id) {
    const docs = await col.find({ userId }).sort({ updatedAt: -1 }).toArray();
    return send(res, 200, docs.map(serial));
  }

  if (req.method === 'POST' && !id) {
    const { title, content, tag } = await parseBody(req);
    const doc = {
      userId,
      title: title || 'Untitled',
      content: content || '',
      tag: tag || 'General',
      createdAt: new Date(), updatedAt: new Date(),
    };
    const r = await col.insertOne(doc);
    return send(res, 201, serial({ ...doc, _id: r.insertedId }));
  }

  if (req.method === 'PUT' && id) {
    const oid = toOid(id);
    if (!oid) return send(res, 400, { error: 'Invalid id' });
    const body = await parseBody(req);
    delete body._id; delete body.userId;
    body.updatedAt = new Date();
    const updated = await findAndUpdate(col, { _id: oid, userId }, { $set: body });
    if (!updated) return send(res, 404, { error: 'Note not found' });
    return send(res, 200, serial(updated));
  }

  if (req.method === 'DELETE' && id) {
    const oid = toOid(id);
    if (!oid) return send(res, 400, { error: 'Invalid id' });
    const r = await col.deleteOne({ _id: oid, userId });
    if (!r.deletedCount) return send(res, 404, { error: 'Note not found' });
    return send(res, 200, { deleted: true });
  }

  return send(res, 405, { error: 'Method not allowed' });
}

// ─────────────────────────────────────────────
// Skills
// ─────────────────────────────────────────────
async function handleSkills(req, res, id, userId) {
  const col = db.collection('skills');
  const COLOR_MAP = { dsa: '#7A3F91', sd: '#C59DD9', cs: '#3b82f6', apt: '#E8C36A', soft: '#5ECEA0' };

  if (req.method === 'GET' && !id) {
    const docs = await col.find({ userId }).sort({ category: 1, name: 1 }).toArray();
    return send(res, 200, docs.map(serial));
  }

  if (req.method === 'POST' && !id) {
    const { category, name, pct } = await parseBody(req);
    if (!category || !name) return send(res, 400, { error: 'category and name required' });
    const doc = {
      userId, category, name,
      pct: Math.min(100, Math.max(0, Number(pct) || 0)),
      color: COLOR_MAP[category] || '#7A3F91',
      createdAt: new Date(), updatedAt: new Date(),
    };
    const r = await col.insertOne(doc);
    return send(res, 201, serial({ ...doc, _id: r.insertedId }));
  }

  if (req.method === 'PUT' && id) {
    const oid = toOid(id);
    if (!oid) return send(res, 400, { error: 'Invalid id' });
    const body = await parseBody(req);
    delete body._id; delete body.userId;
    if (body.pct !== undefined) body.pct = Math.min(100, Math.max(0, Number(body.pct) || 0));
    if (body.category) body.color = COLOR_MAP[body.category] || '#7A3F91';
    body.updatedAt = new Date();
    const updated = await findAndUpdate(col, { _id: oid, userId }, { $set: body });
    if (!updated) return send(res, 404, { error: 'Skill not found' });
    return send(res, 200, serial(updated));
  }

  if (req.method === 'DELETE' && id) {
    const oid = toOid(id);
    if (!oid) return send(res, 400, { error: 'Invalid id' });
    const r = await col.deleteOne({ _id: oid, userId });
    if (!r.deletedCount) return send(res, 404, { error: 'Skill not found' });
    return send(res, 200, { deleted: true });
  }

  return send(res, 405, { error: 'Method not allowed' });
}

// ─────────────────────────────────────────────
// Checklist  GET|PUT /api/checklist
// ─────────────────────────────────────────────
async function handleChecklist(req, res, userId) {
  const col = db.collection('checklists');

  if (req.method === 'GET') {
    const doc = await col.findOne({ userId });
    return send(res, 200, { checked: (doc && doc.checked) || {} });
  }

  if (req.method === 'PUT') {
    const { checked } = await parseBody(req);
    await col.updateOne(
      { userId },
      { $set: { userId, checked: checked || {}, updatedAt: new Date() } },
      { upsert: true }
    );
    return send(res, 200, { checked: checked || {} });
  }

  return send(res, 405, { error: 'Method not allowed' });
}

// ─────────────────────────────────────────────
// Resume  GET|PUT /api/resume
// ─────────────────────────────────────────────
async function handleResume(req, res, userId) {
  const col = db.collection('resumes');

  if (req.method === 'GET') {
    const doc = await col.findOne({ userId });
    return send(res, 200, doc
      ? serial(doc)
      : { userId, score: 0, scoreItems: [], versions: [], currentVersion: '', doc: {} }
    );
  }

  if (req.method === 'PUT') {
    const body = await parseBody(req);
    delete body._id;
    body.updatedAt = new Date();
    const updated = await findAndUpdate(
      col,
      { userId },
      { $set: { ...body, userId } },
      { upsert: true }
    );
    // upsert may return null on insert in some drivers — fetch manually if so
    if (!updated) {
      const fetched = await col.findOne({ userId });
      return send(res, 200, serial(fetched));
    }
    return send(res, 200, serial(updated));
  }

  return send(res, 405, { error: 'Method not allowed' });
}

// ─────────────────────────────────────────────
// Dashboard aggregate  GET /api/dashboard
// ─────────────────────────────────────────────
async function handleDashboard(req, res, userId) {
  if (req.method !== 'GET') return send(res, 405, { error: 'Method not allowed' });

  const [goals, companies, notes] = await Promise.all([
    db.collection('goals').find({ userId }).sort({ updatedAt: -1 }).toArray(),
    db.collection('companies').find({ userId }).sort({ createdAt: -1 }).toArray(),
    db.collection('notes').find({ userId }).sort({ updatedAt: -1 }).toArray(),
  ]);

  // Streak: consecutive days (incl. today) with ≥1 done goal
  const doneDates = new Set(
    goals
      .filter(g => g.status === 'done' && g.updatedAt)
      .map(g => { const d = new Date(g.updatedAt); return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`; })
  );
  let streak = 0;
  const cur = new Date();
  while (true) {
    const k = `${cur.getFullYear()}-${cur.getMonth()}-${cur.getDate()}`;
    if (!doneDates.has(k)) break;
    streak++;
    cur.setDate(cur.getDate() - 1);
  }

  // Weekly activity Mon–Sun
  const now = new Date();
  const dow = now.getDay();
  const mon = new Date(now);
  mon.setDate(now.getDate() - ((dow + 6) % 7));
  mon.setHours(0, 0, 0, 0);
  const weekCounts = [0, 0, 0, 0, 0, 0, 0];
  const todayIdx = (dow + 6) % 7;
  goals.filter(g => g.status === 'done' && g.updatedAt).forEach(g => {
    const diff = Math.floor((new Date(g.updatedAt) - mon) / 86400000);
    if (diff >= 0 && diff < 7) weekCounts[diff]++;
  });

  // Per-category stats
  const CATS = ['dsa', 'sd', 'cs', 'apt', 'hr'];
  const catBreakdown = {};
  CATS.forEach(c => {
    const cg   = goals.filter(g => g.category === c);
    const done = cg.filter(g => g.status === 'done').length;
    const total = cg.length;
    catBreakdown[c] = { done, total, pending: total - done, pct: total ? Math.round(done / total * 100) : 0 };
  });

  const technical = Math.round(['dsa', 'sd', 'cs'].map(c => catBreakdown[c].pct).reduce((a, b) => a + b, 0) / 3);
  const aptitude  = catBreakdown['apt'].pct;
  const soft      = catBreakdown['hr'].pct;
  const readiness = goals.length === 0 ? 0 : Math.round(technical * 0.5 + aptitude * 0.25 + soft * 0.25);

  const todayStr   = new Date().toDateString();
  const todayGoals = goals.filter(g => {
    const d = g.updatedAt || g.createdAt;
    return d && new Date(d).toDateString() === todayStr;
  }).slice(0, 6);

  return send(res, 200, {
    goalsDone:      goals.filter(g => g.status === 'done').length,
    goalsTotal:     goals.length,
    companiesTotal: companies.length,
    offersCount:    companies.filter(c => c.applicationStatus === 'offer').length,
    notesTotal:     notes.length,
    streak, readiness, technical, aptitude, soft,
    weeklyActivity: { counts: weekCounts, todayIndex: todayIdx },
    catBreakdown,
    todayGoals:       todayGoals.map(serial),
    recentCompanies:  companies.slice(0, 5).map(serial),
  });
}

// ─────────────────────────────────────────────
// Main router
// ─────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const parts = new URL(req.url, `http://localhost:${PORT}`).pathname
    .split('/')
    .filter(Boolean);

  if (parts[0] === 'api') {
    try {
      // Public
      if (parts[1] === 'auth') return await handleAuth(req, res, parts[2]);

      // Protected — verify JWT
      const payload = getAuth(req);
      if (!payload) return send(res, 401, { error: 'Unauthorized — please login' });
      const userId = payload.userId;

      if (parts[1] === 'dashboard')  return await handleDashboard(req, res, userId);
      if (parts[1] === 'goals')      return await handleGoals(req, res, parts[2], userId);
      if (parts[1] === 'companies')  return await handleCompanies(req, res, parts[2], userId);
      if (parts[1] === 'notes')      return await handleNotes(req, res, parts[2], userId);
      if (parts[1] === 'skills')     return await handleSkills(req, res, parts[2], userId);
      if (parts[1] === 'checklist')  return await handleChecklist(req, res, userId);
      if (parts[1] === 'resume')     return await handleResume(req, res, userId);

      return send(res, 404, { error: 'API route not found' });
    } catch (err) {
      console.error('[API Error]', req.method, req.url, err.message);
      return send(res, 500, { error: err.message || 'Internal server error' });
    }
  }

  serveStatic(req, res);
});

// ─────────────────────────────────────────────
// Boot
// ─────────────────────────────────────────────
connectMongo()
  .then(() => server.listen(PORT, '0.0.0.0', () =>
    console.log(`🚀  PrepTracker running on port ${PORT}`)
  ))
  .catch(err => {
    console.error('❌  MongoDB connection failed:', err.message);
    process.exit(1);
  });
