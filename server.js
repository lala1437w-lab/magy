const express  = require('express');
const { DatabaseSync } = require('node:sqlite');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const multer   = require('multer');
const { parse } = require('csv-parse/sync');
const path     = require('path');
const fs       = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'change-me-before-production';

// ── Database ────────────────────────────────────────────────────────────────

const DATA_DIR = process.env.DATA_DIR || '.';
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync('uploads', { recursive: true });

const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, 'magy.db');
const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');

function transaction(fn) {
  db.exec('BEGIN');
  try { const r = fn(); db.exec('COMMIT'); return r; }
  catch (e) { db.exec('ROLLBACK'); throw e; }
}

// ── Schema migrations ──────────────────────────────────────────────

function tableExists(name) {
  return !!db.prepare(
    `SELECT name FROM sqlite_master WHERE type='table' AND name=?`
  ).get(name);
}
function hasColumn(table, col) {
  if (!tableExists(table)) return false;
  return db.prepare(`PRAGMA table_info(${table})`).all().some(c => c.name === col);
}

// v1 → v2: activities.year single field → template_type + date ranges
if (tableExists('activities') && !hasColumn('activities', 'template_type')) {
  console.log('⚠  Migrating schema v1 → v2');
  db.exec(`
    DROP TABLE IF EXISTS enrollments;
    DROP TABLE IF EXISTS students;
    DROP TABLE IF EXISTS activities;
  `);
}

// v2 → v3: certificates.student_id → name + id_last4 lookup
if (tableExists('certificates') && hasColumn('certificates', 'student_id')) {
  console.log('⚠  Migrating schema v2 → v3 (學號 → 姓名/身分證後4碼)');
  db.exec(`DROP TABLE IF EXISTS certificates;`);
}

db.exec(`
  CREATE TABLE IF NOT EXISTS activities (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    template_type TEXT    NOT NULL,               -- 'volunteer' | 'training'
    name          TEXT    NOT NULL,

    start_year    INTEGER NOT NULL,
    start_month   INTEGER NOT NULL,
    start_day     INTEGER NOT NULL,
    end_year      INTEGER,
    end_month     INTEGER,
    end_day       INTEGER,

    role          TEXT,                           -- 志工：職位
    hours         REAL,                           -- 志工：時數（選填）
    content       TEXT,                           -- 研習：課程內容
    organizer     TEXT,                           -- 研習：主辦單位

    doc_prefix    TEXT    NOT NULL,               -- '科教謝字' / '物教證字'

    issue_year    INTEGER NOT NULL,
    issue_month   INTEGER NOT NULL,
    issue_day     INTEGER NOT NULL,

    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS certificates (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    activity_id    INTEGER NOT NULL,
    name           TEXT    NOT NULL,              -- 姓名（必填）
    school         TEXT    NOT NULL,              -- 學校（必填）
    id_last4       TEXT,                          -- 身分證字號後4碼（選填，用於姓名重複辨識）
    serial_number  TEXT    NOT NULL,
    FOREIGN KEY (activity_id) REFERENCES activities(id) ON DELETE CASCADE,
    UNIQUE(activity_id, name, id_last4)
  );
  CREATE INDEX IF NOT EXISTS idx_cert_name     ON certificates(name);
  CREATE INDEX IF NOT EXISTS idx_cert_id_last4 ON certificates(id_last4);
  CREATE TABLE IF NOT EXISTS admins (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL
  );
`);

// Seed default admin on first run
if (db.prepare('SELECT COUNT(*) AS c FROM admins').get().c === 0) {
  db.prepare('INSERT INTO admins VALUES (?, ?)').run('admin', bcrypt.hashSync('admin123', 10));
  console.log('預設帳號：admin / admin123  ← 請登入後立即修改密碼');
}

// ── Middleware ──────────────────────────────────────────────────────────────

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({ dest: 'uploads/', limits: { fileSize: 20 * 1024 * 1024 } });

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: '請先登入' });
  try { req.user = jwt.verify(h.slice(7), SECRET); next(); }
  catch { res.status(401).json({ error: 'Token 無效或已過期' }); }
}

// ── Public: Student Lookup ──────────────────────────────────────────────────

// GET /api/student/:key  →  { name, school, certificates: [...] }
// key 可以是「姓名」或「身分證字號後4碼」
app.get('/api/student/:key', (req, res) => {
  const key = req.params.key.trim();
  if (!key) return res.status(400).json({ error: '請輸入姓名或身分證字號後4碼' });

  const rows = db.prepare(`
    SELECT
      c.id            AS cert_id,
      c.activity_id,
      c.name,
      c.school,
      c.id_last4,
      c.serial_number,
      a.template_type,
      a.name          AS activity_name,
      a.start_year, a.start_month, a.start_day,
      a.end_year, a.end_month, a.end_day,
      a.role, a.hours,
      a.content, a.organizer,
      a.doc_prefix,
      a.issue_year, a.issue_month, a.issue_day
    FROM certificates c
    JOIN activities a ON a.id = c.activity_id
    WHERE c.name = ? OR c.id_last4 = ?
    ORDER BY a.start_year DESC, a.start_month DESC, a.start_day DESC
  `).all(key, key);

  if (!rows.length) {
    return res.status(404).json({ error: '查無資料，請確認姓名或身分證字號後4碼是否正確，或聯絡承辦人員' });
  }

  // 判斷是否對應到多位不同的人（姓名撞名）
  const distinct = new Set(rows.map(r => `${r.name}|${r.id_last4 || ''}|${r.school}`));
  if (distinct.size > 1) {
    return res.status(409).json({
      error: '查詢到多位同名者，請改用「身分證字號後4碼」查詢'
    });
  }

  res.json({
    name: rows[0].name,
    school: rows[0].school,
    id_last4: rows[0].id_last4,
    certificates: rows
  });
});

// ── Admin Auth ──────────────────────────────────────────────────────────────

app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body || {};
  const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(username);
  if (!admin || !bcrypt.compareSync(password, admin.password_hash))
    return res.status(401).json({ error: '帳號或密碼錯誤' });
  res.json({ token: jwt.sign({ username }, SECRET, { expiresIn: '8h' }), username });
});

app.put('/api/admin/password', auth, (req, res) => {
  const { current, next: newPass } = req.body;
  const admin = db.prepare('SELECT * FROM admins WHERE username = ?').get(req.user.username);
  if (!bcrypt.compareSync(current, admin.password_hash))
    return res.status(400).json({ error: '目前密碼不正確' });
  db.prepare('UPDATE admins SET password_hash = ? WHERE username = ?')
    .run(bcrypt.hashSync(newPass, 10), req.user.username);
  res.json({ ok: true });
});

// ── Admin: Activities ───────────────────────────────────────────────────────

app.get('/api/admin/activities', auth, (_req, res) => {
  const rows = db.prepare(`
    SELECT a.*, (SELECT COUNT(*) FROM certificates c WHERE c.activity_id = a.id) AS cert_count
    FROM activities a
    ORDER BY a.start_year DESC, a.start_month DESC, a.start_day DESC, a.id DESC
  `).all();
  res.json(rows);
});

app.get('/api/admin/activities/:id', auth, (req, res) => {
  const act = db.prepare('SELECT * FROM activities WHERE id = ?').get(req.params.id);
  if (!act) return res.status(404).json({ error: '找不到活動' });
  res.json(act);
});

app.post('/api/admin/activities', auth, (req, res) => {
  const b = req.body || {};
  if (!b.template_type || !b.name || !b.start_year || !b.start_month || !b.start_day
      || !b.issue_year || !b.issue_month || !b.issue_day || !b.doc_prefix) {
    return res.status(400).json({ error: '缺少必填欄位' });
  }
  const r = db.prepare(`
    INSERT INTO activities
      (template_type, name,
       start_year, start_month, start_day,
       end_year,   end_month,   end_day,
       role, hours, content, organizer, doc_prefix,
       issue_year, issue_month, issue_day)
    VALUES (?,?, ?,?,?, ?,?,?, ?,?,?,?,?, ?,?,?)
  `).run(
    b.template_type, b.name,
    b.start_year, b.start_month, b.start_day,
    b.end_year || null, b.end_month || null, b.end_day || null,
    b.role || null, b.hours == null ? null : +b.hours, b.content || null, b.organizer || null, b.doc_prefix,
    b.issue_year, b.issue_month, b.issue_day
  );
  res.json({ id: r.lastInsertRowid });
});

app.put('/api/admin/activities/:id', auth, (req, res) => {
  const b = req.body || {};
  db.prepare(`
    UPDATE activities SET
      template_type=?, name=?,
      start_year=?, start_month=?, start_day=?,
      end_year=?,   end_month=?,   end_day=?,
      role=?, hours=?, content=?, organizer=?, doc_prefix=?,
      issue_year=?, issue_month=?, issue_day=?
    WHERE id=?
  `).run(
    b.template_type, b.name,
    b.start_year, b.start_month, b.start_day,
    b.end_year || null, b.end_month || null, b.end_day || null,
    b.role || null, b.hours == null ? null : +b.hours, b.content || null, b.organizer || null, b.doc_prefix,
    b.issue_year, b.issue_month, b.issue_day,
    req.params.id
  );
  res.json({ ok: true });
});

app.delete('/api/admin/activities/:id', auth, (req, res) => {
  db.prepare('DELETE FROM activities WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ── Admin: Certificates ─────────────────────────────────────────────────────

app.get('/api/admin/activities/:id/certificates', auth, (req, res) => {
  const rows = db.prepare(
    'SELECT * FROM certificates WHERE activity_id = ? ORDER BY CAST(serial_number AS INTEGER), serial_number'
  ).all(req.params.id);
  res.json(rows);
});

app.post('/api/admin/certificates', auth, (req, res) => {
  const b = req.body || {};
  if (!b.activity_id || !b.name || !b.school || !b.serial_number) {
    return res.status(400).json({ error: '缺少必填欄位' });
  }
  try {
    const r = db.prepare(
      'INSERT INTO certificates (activity_id, name, school, id_last4, serial_number) VALUES (?,?,?,?,?)'
    ).run(b.activity_id, String(b.name), String(b.school), b.id_last4 ? String(b.id_last4) : null, String(b.serial_number));
    res.json({ id: r.lastInsertRowid });
  } catch (e) {
    res.status(e.message.includes('UNIQUE') ? 409 : 500).json({ error: e.message });
  }
});

app.put('/api/admin/certificates/:id', auth, (req, res) => {
  const b = req.body || {};
  db.prepare(
    'UPDATE certificates SET name=?, school=?, id_last4=?, serial_number=? WHERE id=?'
  ).run(String(b.name), String(b.school), b.id_last4 ? String(b.id_last4) : null, String(b.serial_number), req.params.id);
  res.json({ ok: true });
});

app.delete('/api/admin/certificates/:id', auth, (req, res) => {
  db.prepare('DELETE FROM certificates WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// Bulk import certificates for a specific activity (CSV)
// Required columns (supports Chinese headers):
//   姓名 / name
//   學校 / school
// Optional:
//   身分證後4碼 / 身分證字號後4碼 / id_last4   (姓名撞名時用於區別；同時也可作為查詢關鍵字)
//   流水編號 / 文號 / serial_number            (若未提供則自動遞增，3 位數補零)
app.post('/api/admin/activities/:id/certificates/import', auth, upload.single('file'), (req, res) => {
  const activity_id = +req.params.id;
  const act = db.prepare('SELECT id FROM activities WHERE id = ?').get(activity_id);
  if (!act) { if (req.file) fs.unlinkSync(req.file.path); return res.status(404).json({ error: '活動不存在' }); }

  const raw = fs.readFileSync(req.file.path, 'utf8');
  fs.unlinkSync(req.file.path);
  const rows = parse(raw, { columns: true, skip_empty_lines: true, trim: true, bom: true });

  // Current max serial for auto-numbering
  let nextSerial = (db.prepare(
    'SELECT MAX(CAST(serial_number AS INTEGER)) AS m FROM certificates WHERE activity_id = ?'
  ).get(activity_id).m || 0) + 1;

  let inserted = 0, skipped = 0;
  const ins = db.prepare(
    'INSERT OR IGNORE INTO certificates (activity_id, name, school, id_last4, serial_number) VALUES (?,?,?,?,?)'
  );

  transaction(() => {
    for (const r of rows) {
      const name    = r.name     ?? r['姓名'];
      const school  = r.school   ?? r['學校'];
      const idLast4 = r.id_last4 ?? r['身分證後4碼'] ?? r['身分證字號後4碼'] ?? r['身分證後四碼'] ?? '';
      let serial    = r.serial_number ?? r['流水編號'] ?? r['文號'] ?? '';
      if (!name || !school) { skipped++; continue; }
      if (!serial) { serial = String(nextSerial).padStart(3, '0'); nextSerial++; }
      else { serial = String(serial); }
      const result = ins.run(
        activity_id,
        String(name).trim(),
        String(school).trim(),
        idLast4 ? String(idLast4).trim() : null,
        serial
      );
      result.changes > 0 ? inserted++ : skipped++;
    }
  });
  res.json({ inserted, skipped, total: rows.length });
});

// ── Admin: Template Upload ──────────────────────────────────────────────────

app.post('/api/admin/template/:type', auth, upload.single('template'), (req, res) => {
  const type = req.params.type;
  if (!['volunteer', 'training'].includes(type))
    return res.status(400).json({ error: '模板類型錯誤' });
  if (!req.file) return res.status(400).json({ error: '未收到檔案' });
  fs.copyFileSync(req.file.path, path.join(__dirname, 'public', `${type}.pdf`));
  fs.unlinkSync(req.file.path);
  res.json({ ok: true });
});

// ── SPA Routes ──────────────────────────────────────────────────────────────

app.get('/admin', (_req, res) =>
  res.sendFile(path.join(__dirname, 'public', 'admin.html'))
);

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: '伺服器錯誤' });
});

app.listen(PORT, () => {
  console.log(`✅  Server: http://localhost:${PORT}`);
  console.log(`   學生端: http://localhost:${PORT}/`);
  console.log(`   後台:   http://localhost:${PORT}/admin`);
});
