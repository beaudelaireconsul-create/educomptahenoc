 require('dotenv').config();
const express = require('express'), cors = require('cors'), crypto = require('crypto');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const { Pool } = require('pg'), fs = require('fs');
const { Webhook } = require('fedapay');

const { DATABASE_URL, JWT_SECRET, FEDAPAY_SECRET_KEY, FEDAPAY_WEBHOOK_SECRET, FEDAPAY_API, PUBLIC_URL } = process.env;
if (!DATABASE_URL) { console.error('ERREUR : la variable DATABASE_URL est manquante.'); process.exit(1); }
if (!JWT_SECRET) { console.error('ERREUR : la variable JWT_SECRET est manquante.'); process.exit(1); }

const pool = new Pool({ connectionString: DATABASE_URL,
  ssl: /localhost|127\.0\.0\.1/.test(DATABASE_URL) ? false : { rejectUnauthorized: false } });
const q = (text, params) => pool.query(text, params);
const h = fn => (req, res, next) => fn(req, res).catch(next);
const COUNTRIES = {
  BJ: { name: 'Bénin', dial: '229', cur: 'XOF', keep0: true, pay: 'fedapay' },
  TG: { name: 'Togo', dial: '228', cur: 'XOF', pay: 'fedapay' },
  CI: { name: "Côte d'Ivoire", dial: '225', cur: 'XOF', keep0: true, pay: 'fedapay' },
  SN: { name: 'Sénégal', dial: '221', cur: 'XOF', pay: 'fedapay' },
  ML: { name: 'Mali', dial: '223', cur: 'XOF', pay: 'fedapay' },
  BF: { name: 'Burkina Faso', dial: '226', cur: 'XOF', pay: 'fedapay' },
  NE: { name: 'Niger', dial: '227', cur: 'XOF', pay: 'fedapay' },
  GN: { name: 'Guinée', dial: '224', cur: 'GNF', pay: 'fedapay' },
  CM: { name: 'Cameroun', dial: '237', cur: 'XAF' },
  GA: { name: 'Gabon', dial: '241', cur: 'XAF' },
  CG: { name: 'Congo', dial: '242', cur: 'XAF' },
  CD: { name: 'RD Congo', dial: '243', cur: 'CDF' },
  NG: { name: 'Nigeria', dial: '234', cur: 'NGN' },
  GH: { name: 'Ghana', dial: '233', cur: 'GHS' },
  KE: { name: 'Kenya', dial: '254', cur: 'KES' },
  UG: { name: 'Ouganda', dial: '256', cur: 'UGX' },
  RW: { name: 'Rwanda', dial: '250', cur: 'RWF' },
  TZ: { name: 'Tanzanie', dial: '255', cur: 'TZS' },
  MA: { name: 'Maroc', dial: '212', cur: 'MAD' }
};
const country = cc => COUNTRIES[cc] ? cc : 'BJ';
// Numéro canonique = indicatif + numéro national (sert à retrouver un parent quel que soit le format saisi)
const normPhone = (p, cc) => {
  const c = COUNTRIES[country(cc)];
  let d = String(p || '').replace(/\D/g, '');
  if (d.startsWith('00')) d = d.slice(2);
  if (d.startsWith(c.dial) && d.length >= c.dial.length + 8) d = d.slice(c.dial.length);
  if (c.keep0) { if (country(cc) === 'BJ' && d.length === 8) d = '01' + d; }
  else d = d.replace(/^0+/, '');
  return c.dial + d;
};
const ccOf = req => country(req.user && req.user.cc);
const ALPHA = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';
const newCode = () => Array.from({ length: 6 }, () => ALPHA[crypto.randomInt(ALPHA.length)]).join('');
const normCode = c => String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
const fails = new Map(); // anti-devinette : 10 échecs / 15 min / adresse IP
const blocked = req => (fails.get(req.ip) || []).filter(t => Date.now() - t < 900000).length >= 10;
const failed = req => fails.set(req.ip, [...(fails.get(req.ip) || []).filter(t => Date.now() - t < 900000), Date.now()]);
const isId = v => Number.isInteger(Number(v)) && Number(v) > 0;
const paidSum = `COALESCE((SELECT SUM(amount) FROM payments WHERE student_id=s.id AND status='paid'),0)::int`;

const SCHEMA = `
CREATE TABLE IF NOT EXISTS schools (
  id SERIAL PRIMARY KEY, name TEXT NOT NULL, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY, school_id INTEGER NOT NULL REFERENCES schools(id),
  email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'director' CHECK (role IN ('director','accountant')));
CREATE TABLE IF NOT EXISTS students (
  id SERIAL PRIMARY KEY, school_id INTEGER NOT NULL REFERENCES schools(id),
  name TEXT NOT NULL, class TEXT, parent_phone TEXT NOT NULL,
  total_fee INTEGER NOT NULL CHECK (total_fee >= 0),
  created_at TIMESTAMPTZ DEFAULT now());
CREATE INDEX IF NOT EXISTS idx_students_school ON students(school_id);
CREATE INDEX IF NOT EXISTS idx_students_phone ON students(parent_phone);
CREATE TABLE IF NOT EXISTS payments (
  id SERIAL PRIMARY KEY, school_id INTEGER NOT NULL REFERENCES schools(id),
  student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
  amount INTEGER NOT NULL CHECK (amount > 0), method TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'paid' CHECK (status IN ('pending','paid','failed')),
  provider_ref TEXT UNIQUE, created_at TIMESTAMPTZ DEFAULT now());
CREATE INDEX IF NOT EXISTS idx_pay_student ON payments(student_id);
ALTER TABLE schools ADD COLUMN IF NOT EXISTS country TEXT NOT NULL DEFAULT 'BJ';
ALTER TABLE schools ADD COLUMN IF NOT EXISTS currency TEXT NOT NULL DEFAULT 'XOF';
ALTER TABLE students ADD COLUMN IF NOT EXISTS access_code TEXT;
UPDATE students SET access_code = upper(substr(md5(random()::text || id::text), 1, 6)) WHERE access_code IS NULL;
`;

const app = express(); app.set('trust proxy', 1); app.use(cors());

// ---- Webhook FedaPay (corps brut, AVANT express.json) ----
app.post('/api/webhooks/fedapay', express.raw({ type: '*/*' }), h(async (req, res) => {
  const body = req.body.toString('utf8');
  try { Webhook.constructEvent(body, req.get('x-fedapay-signature') || '', FEDAPAY_WEBHOOK_SECRET || ''); }
  catch (e) { console.error('Signature webhook invalide'); return res.sendStatus(400); }
  const ev = JSON.parse(body), tx = ev.entity || {};
  const status = ['transaction.approved', 'transaction.transferred'].includes(ev.name) ? 'paid'
    : ['transaction.canceled', 'transaction.declined'].includes(ev.name) ? 'failed' : null;
  if (status) await q('UPDATE payments SET status=$1 WHERE provider_ref=$2', [status, String(tx.id)]);
  res.sendStatus(200);
}));

app.use(express.json());

// ---- Auth ----
const sign = u => jwt.sign({ uid: u.id, sid: u.school_id, role: u.role, cc: u.cc }, JWT_SECRET, { expiresIn: '7d' });
const auth = (req, res, next) => {
  try { req.user = jwt.verify((req.get('authorization') || '').replace('Bearer ', ''), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Non autorisé' }); }
};

app.post('/api/auth/register', h(async (req, res) => {
  const { school, email, password } = req.body;
  if (!school || !email || !password || password.length < 8) return res.status(400).json({ error: 'Champs invalides (mot de passe 8+ car.)' });
  if ((await q('SELECT 1 FROM users WHERE email=$1', [email])).rowCount) return res.status(409).json({ error: 'Email déjà utilisé' });
  const cc = country(req.body.country);
  const sid = (await q('INSERT INTO schools(name,country,currency) VALUES($1,$2,$3) RETURNING id', [school, cc, COUNTRIES[cc].cur])).rows[0].id;
  const uid = (await q('INSERT INTO users(school_id,email,password_hash) VALUES($1,$2,$3) RETURNING id',
    [sid, email, bcrypt.hashSync(password, 10)])).rows[0].id;
  res.json({ token: sign({ id: uid, school_id: sid, role: 'director', cc }) });
}));

app.post('/api/auth/login', h(async (req, res) => {
  const u = (await q('SELECT u.*, s.country AS cc FROM users u JOIN schools s ON s.id=u.school_id WHERE u.email=$1', [req.body.email])).rows[0];
  if (!u || !bcrypt.compareSync(req.body.password || '', u.password_hash)) return res.status(401).json({ error: 'Identifiants incorrects' });
  res.json({ token: sign(u) });
}));

app.get('/api/countries', (req, res) => res.json(Object.entries(COUNTRIES).map(([code, c]) =>
  ({ code, name: c.name, dial: c.dial, currency: c.cur, online: c.pay === 'fedapay' }))));

app.get('/api/me', auth, h(async (req, res) => {
  const r = (await q('SELECT name, country, currency FROM schools WHERE id=$1', [req.user.sid])).rows[0];
  res.json({ school: r.name, country: r.country, currency: r.currency, dial: COUNTRIES[country(r.country)].dial });
}));

// ---- Élèves (directeur) ----
app.get('/api/students', auth, h(async (req, res) => {
  res.json((await q(`SELECT s.*, ${paidSum} AS paid FROM students s WHERE school_id=$1 ORDER BY name`, [req.user.sid])).rows);
}));

app.post('/api/students', auth, h(async (req, res) => {
  const { name, class: cls, parent_phone, total_fee } = req.body;
  if (!name || !parent_phone || !(total_fee >= 0)) return res.status(400).json({ error: 'Champs invalides' });
  const code = newCode();
  const r = await q('INSERT INTO students(school_id,name,class,parent_phone,total_fee,access_code) VALUES($1,$2,$3,$4,$5,$6) RETURNING id',
    [req.user.sid, name, cls || '', normPhone(parent_phone, ccOf(req)), Math.round(total_fee), code]);
  res.status(201).json({ id: r.rows[0].id, access_code: code });
}));

app.delete('/api/students/:id', auth, h(async (req, res) => {
  if (!isId(req.params.id)) return res.status(400).json({ error: 'Identifiant invalide' });
  await q('DELETE FROM students WHERE id=$1 AND school_id=$2', [req.params.id, req.user.sid]);
  res.sendStatus(204);
}));

// ---- Paiements manuels ----
app.post('/api/payments', auth, h(async (req, res) => {
  const { student_id, amount, method } = req.body;
  if (!isId(student_id)) return res.status(400).json({ error: 'Élève invalide' });
  const s = (await q(`SELECT s.total_fee, ${paidSum} AS paid FROM students s WHERE id=$1 AND school_id=$2`, [student_id, req.user.sid])).rows[0];
  if (!s) return res.status(404).json({ error: 'Élève introuvable' });
  if (!(amount > 0) || amount > s.total_fee - s.paid) return res.status(400).json({ error: 'Montant invalide' });
  const r = await q('INSERT INTO payments(school_id,student_id,amount,method) VALUES($1,$2,$3,$4) RETURNING id',
    [req.user.sid, student_id, Math.round(amount), method || 'Espèces']);
  res.status(201).json({ id: r.rows[0].id, remaining: s.total_fee - s.paid - amount });
}));

app.get('/api/dashboard', auth, h(async (req, res) => {
  const due = (await q('SELECT COALESCE(SUM(total_fee),0)::int AS v FROM students WHERE school_id=$1', [req.user.sid])).rows[0].v;
  const paid = (await q("SELECT COALESCE(SUM(amount),0)::int AS v FROM payments WHERE school_id=$1 AND status='paid'", [req.user.sid])).rows[0].v;
  res.json({ due, paid, remaining: due - paid, rate: due ? Math.round(paid / due * 100) : 0 });
}));

// ---- Espace parent (téléphone + code d'accès) ----
app.get('/api/parent/students', h(async (req, res) => {
  if (blocked(req)) return res.status(429).json({ error: 'Trop de tentatives. Réessayez dans 15 minutes.' });
  const cc = country(req.query.cc);
  const rows = (await q(`SELECT s.id, s.name, s.class, s.total_fee, sc.currency, sc.country, ${paidSum} AS paid
    FROM students s JOIN schools sc ON sc.id=s.school_id WHERE s.parent_phone=$1 AND s.access_code=$2`,
    [normPhone(req.query.phone, cc), normCode(req.query.code)])).rows;
  if (!rows.length) failed(req);
  res.json(rows.map(r => ({ ...r, online: COUNTRIES[country(r.country)].pay === 'fedapay' })));
}));

app.post('/api/parent/pay', h(async (req, res) => {
  const { student_id, amount, phone } = req.body, cc = country(req.body.cc);
  if (blocked(req)) return res.status(429).json({ error: 'Trop de tentatives. Réessayez dans 15 minutes.' });
  if (!isId(student_id)) return res.status(400).json({ error: 'Demande invalide' });
  const s = (await q(`SELECT s.*, sc.currency, sc.country, ${paidSum} AS paid FROM students s JOIN schools sc ON sc.id=s.school_id
    WHERE s.id=$1 AND s.parent_phone=$2 AND s.access_code=$3`, [student_id, normPhone(phone, cc), normCode(req.body.code)])).rows[0];
  if (!s) failed(req);
  if (!s || !(amount > 0) || amount > s.total_fee - s.paid) return res.status(400).json({ error: 'Demande invalide' });
  if (COUNTRIES[country(s.country)].pay !== 'fedapay')
    return res.status(400).json({ error: "Paiement en ligne bientôt disponible dans votre pays. Payez directement auprès de l'école." });
  try {
    const H = { 'Content-Type': 'application/json', Authorization: `Bearer ${FEDAPAY_SECRET_KEY}` };
    const tx = await (await fetch(`${FEDAPAY_API}/transactions`, { method: 'POST', headers: H, body: JSON.stringify({
      description: `Scolarité - ${s.name}`, amount: Math.round(amount), currency: { iso: s.currency },
      callback_url: `${PUBLIC_URL}/` }) })).json();
    const id = (tx['v1/transaction'] || tx).id;
    const tk = await (await fetch(`${FEDAPAY_API}/transactions/${id}/token`, { method: 'POST', headers: H })).json();
    await q("INSERT INTO payments(school_id,student_id,amount,method,status,provider_ref) VALUES($1,$2,$3,'FedaPay','pending',$4)",
      [s.school_id, s.id, Math.round(amount), String(id)]);
    res.json({ payment_url: tk.url });
  } catch (e) { res.status(502).json({ error: 'Passerelle de paiement indisponible' }); }
}));

// ---- Pages et erreurs ----
const pub = fs.existsSync(__dirname + '/public/index.html') ? __dirname + '/public/index.html' : __dirname + '/index.html';
app.get('/', (req, res) => res.sendFile(pub));
app.use(express.static(__dirname + '/public'));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.code === '23505' ? 409 : 500).json({ error: err.code === '23505' ? 'Déjà existant' : 'Erreur serveur' });
});

(async () => {
  await q(SCHEMA);
  app.listen(process.env.PORT || 3000, () => console.log('EduCompta API prête (PostgreSQL)'));
})().catch(e => { console.error('Connexion à la base impossible :', e.message); process.exit(1); });
