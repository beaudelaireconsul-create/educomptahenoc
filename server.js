require('dotenv').config();
const express = require('express'), cors = require('cors'), crypto = require('crypto');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const Database = require('better-sqlite3'), fs = require('fs');

const db = new Database('educompta.db');
db.exec(fs.readFileSync(__dirname + '/schema.sql', 'utf8'));
const app = express(); app.use(cors());
const { JWT_SECRET, FEDAPAY_SECRET_KEY, FEDAPAY_WEBHOOK_SECRET, FEDAPAY_API, PUBLIC_URL } = process.env;
const normPhone = p => String(p || '').replace(/\D/g, '');
const paidSum = `COALESCE((SELECT SUM(amount) FROM payments WHERE student_id=s.id AND status='paid'),0)`;

// ---- Webhook FedaPay (corps brut, AVANT express.json) ----
app.post('/api/webhooks/fedapay', express.raw({ type: '*/*' }), (req, res) => {
  const sig = req.get('x-fedapay-signature') || '';
  const t = (sig.match(/t=(\d+)/) || [])[1], s = (sig.match(/s=([a-f0-9]+)/) || [])[1];
  const expected = crypto.createHmac('sha256', FEDAPAY_WEBHOOK_SECRET || '').update(`${t}.${req.body}`).digest('hex');
  if (!s || s.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(expected)))
    return res.sendStatus(400);
  const ev = JSON.parse(req.body);
  const tx = ev.entity || {};
  const status = ev.name === 'transaction.approved' ? 'paid' : ev.name === 'transaction.declined' ? 'failed' : null;
  if (status) db.prepare('UPDATE payments SET status=? WHERE provider_ref=?').run(status, String(tx.id));
  res.sendStatus(200);
});

app.use(express.json());

// ---- Auth ----
const sign = u => jwt.sign({ uid: u.id, sid: u.school_id, role: u.role }, JWT_SECRET, { expiresIn: '7d' });
const auth = (req, res, next) => {
  try { req.user = jwt.verify((req.get('authorization') || '').replace('Bearer ', ''), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Non autorisé' }); }
};

app.post('/api/auth/register', (req, res) => {
  const { school, email, password } = req.body;
  if (!school || !email || !password || password.length < 8) return res.status(400).json({ error: 'Champs invalides (mot de passe 8+ car.)' });
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) return res.status(409).json({ error: 'Email déjà utilisé' });
  const sid = db.prepare('INSERT INTO schools(name) VALUES(?)').run(school).lastInsertRowid;
  const uid = db.prepare('INSERT INTO users(school_id,email,password_hash) VALUES(?,?,?)').run(sid, email, bcrypt.hashSync(password, 10)).lastInsertRowid;
  res.json({ token: sign({ id: uid, school_id: sid, role: 'director' }) });
});

app.post('/api/auth/login', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(req.body.email);
  if (!u || !bcrypt.compareSync(req.body.password || '', u.password_hash)) return res.status(401).json({ error: 'Identifiants incorrects' });
  res.json({ token: sign(u) });
});

// ---- Élèves (directeur) ----
app.get('/api/students', auth, (req, res) => res.json(db.prepare(
  `SELECT s.*, ${paidSum} AS paid FROM students s WHERE school_id=? ORDER BY name`).all(req.user.sid)));

app.post('/api/students', auth, (req, res) => {
  const { name, class: cls, parent_phone, total_fee } = req.body;
  if (!name || !parent_phone || !(total_fee >= 0)) return res.status(400).json({ error: 'Champs invalides' });
  const id = db.prepare('INSERT INTO students(school_id,name,class,parent_phone,total_fee) VALUES(?,?,?,?,?)')
    .run(req.user.sid, name, cls || '', normPhone(parent_phone), Math.round(total_fee)).lastInsertRowid;
  res.status(201).json({ id });
});

app.delete('/api/students/:id', auth, (req, res) => {
  db.prepare('DELETE FROM students WHERE id=? AND school_id=?').run(req.params.id, req.user.sid);
  res.sendStatus(204);
});

// ---- Paiements manuels (espèces, dépôt) ----
app.post('/api/payments', auth, (req, res) => {
  const { student_id, amount, method } = req.body;
  const s = db.prepare(`SELECT s.total_fee, ${paidSum} AS paid FROM students s WHERE id=? AND school_id=?`).get(student_id, req.user.sid);
  if (!s) return res.status(404).json({ error: 'Élève introuvable' });
  if (!(amount > 0) || amount > s.total_fee - s.paid) return res.status(400).json({ error: 'Montant invalide' });
  const id = db.prepare('INSERT INTO payments(school_id,student_id,amount,method) VALUES(?,?,?,?)')
    .run(req.user.sid, student_id, Math.round(amount), method || 'Espèces').lastInsertRowid;
  res.status(201).json({ id, remaining: s.total_fee - s.paid - amount });
});

app.get('/api/dashboard', auth, (req, res) => {
  const r = db.prepare(`SELECT COALESCE(SUM(total_fee),0) AS due,
    COALESCE(SUM(${paidSum}),0) AS paid FROM students s WHERE school_id=?`).get(req.user.sid);
  res.json({ ...r, remaining: r.due - r.paid, rate: r.due ? Math.round(r.paid / r.due * 100) : 0 });
});

// ---- Espace parent (par téléphone) ----
// TODO production : ajouter un code OTP par SMS avant d'afficher ces données.
app.get('/api/parent/students', (req, res) => res.json(db.prepare(
  `SELECT s.id, s.name, s.class, s.total_fee, ${paidSum} AS paid FROM students s WHERE parent_phone=?`)
  .all(normPhone(req.query.phone))));

app.post('/api/parent/pay', async (req, res) => {
  const { student_id, amount, phone } = req.body;
  const s = db.prepare(`SELECT s.*, ${paidSum} AS paid FROM students s WHERE id=? AND parent_phone=?`).get(student_id, normPhone(phone));
  if (!s || !(amount > 0) || amount > s.total_fee - s.paid) return res.status(400).json({ error: 'Demande invalide' });
  try {
    const H = { 'Content-Type': 'application/json', Authorization: `Bearer ${FEDAPAY_SECRET_KEY}` };
    const tx = await (await fetch(`${FEDAPAY_API}/transactions`, { method: 'POST', headers: H, body: JSON.stringify({
      description: `Scolarité - ${s.name}`, amount: Math.round(amount), currency: { iso: 'XOF' },
      callback_url: `${PUBLIC_URL}/api/webhooks/fedapay` }) })).json();
    const id = (tx['v1/transaction'] || tx).id;
    const tk = await (await fetch(`${FEDAPAY_API}/transactions/${id}/token`, { method: 'POST', headers: H })).json();
    db.prepare("INSERT INTO payments(school_id,student_id,amount,method,status,provider_ref) VALUES(?,?,?,?, 'pending', ?)")
      .run(s.school_id, s.id, Math.round(amount), 'FedaPay', String(id));
    res.json({ payment_url: tk.url });
  } catch (e) { res.status(502).json({ error: 'Passerelle de paiement indisponible' }); }
});

const pub = fs.existsSync(__dirname + '/public/index.html') ? __dirname + '/public/index.html' : __dirname + '/index.html';
app.get('/', (req, res) => res.sendFile(pub));
app.use(express.static(__dirname + '/public'));
app.listen(process.env.PORT || 3000, () => console.log('EduCompta API prête'));
