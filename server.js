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

fs.mkdirSync('uploads', { recursive: true });

const db = new DatabaseSync(process.env.DB_PATH || 'magy.db');
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');

// Transaction helper (node:sqlite has no built-in transaction())
function transaction(fn) {
  db.exec('BEGIN');
  try { fn(); db.exec('COMMIT'); }
  catch (e) { db.exec('ROLLBACK'); throw e; }
}

db.exec(`
  CREATE TABLE IF NOT EXISTS activities (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL,
    year       INTEGER NOT NULL,
    month      INTEGER NOT NULL,
    day        INTEGER NOT NULL,
    hours      REAL    NOT NULL,
    role       TEXT    NOT NULL DEFAULT '攤位志工',
    doc_number TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS students (
    student_id TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    school     TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS enrollments (
    student_id  TEXT    NOT NULL,
    activity_id INTEGER NOT NULL,
    PRIMARY KEY (student_id, activity_id),
    FOREIGN KEY (student_id)  REFERENCES students(student_id)  ON DELETE CASCADE,
    FOREIGN KEY (activity_id) REFERENCES activities(id)        ON DELETE CASCADE
  );
  CREATE TABLE IF NOT EXISTS admins (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL
  );
`);

// Seed default admin (admin / admin123) on first run
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

// GET /api/student/:id  →  { student_id, name, school, activities: [...] }
app.get('/api/student/:id', (req, res) => {
  const student = db.prepare('SELECT * FROM students WHERE student_id = ?').get(req.params.id);
  if (!student) return res.status(404).json({ error: '找不到此學號，請確認後重試，或聯絡承辦人員' });

  const activities = db.prepare(`
    SELECT a.* FROM activities a
    JOIN enrollments e ON e.activity_id = a.id
    WHERE e.student_id = ?
    ORDER BY a.year DESC, a.month DESC, a.day DESC
  `).all(req.params.id);

  res.json({ ...student, activities });
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

app.get('/api/admin/activities', auth, (_req, res) =>
  res.json(db.prepare('SELECT * FROM activities ORDER BY year DESC, month DESC, day DESC').all())
);

app.post('/api/admin/activities', auth, (req, res) => {
  const { name, year, month, day, hours, role, doc_number } = req.body;
  const r = db.prepare(
    'INSERT INTO activities (name,year,month,day,hours,role,doc_number) VALUES (?,?,?,?,?,?,?)'
  ).run(name, year, month, day, hours, role || '攤位志工', doc_number || null);
  res.json({ id: r.lastInsertRowid });
});

app.put('/api/admin/activities/:id', auth, (req, res) => {
  const { name, year, month, day, hours, role, doc_number } = req.body;
  db.prepare(
    'UPDATE activities SET name=?,year=?,month=?,day=?,hours=?,role=?,doc_number=? WHERE id=?'
  ).run(name, year, month, day, hours, role, doc_number, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/admin/activities/:id', auth, (req, res) => {
  db.prepare('DELETE FROM activities WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ── Admin: Students ─────────────────────────────────────────────────────────

app.get('/api/admin/students', auth, (_req, res) =>
  res.json(db.prepare('SELECT * FROM students ORDER BY student_id').all())
);

app.post('/api/admin/students', auth, (req, res) => {
  const { student_id, name, school } = req.body;
  try {
    db.prepare('INSERT INTO students VALUES (?,?,?)').run(student_id, name, school);
    res.json({ ok: true });
  } catch (e) {
    res.status(e.message.includes('UNIQUE') ? 409 : 500).json({ error: e.message });
  }
});

app.put('/api/admin/students/:id', auth, (req, res) => {
  const { name, school } = req.body;
  db.prepare('UPDATE students SET name=?, school=? WHERE student_id=?').run(name, school, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/admin/students/:id', auth, (req, res) => {
  db.prepare('DELETE FROM students WHERE student_id=?').run(req.params.id);
  res.json({ ok: true });
});

// Import students from CSV  (支援中文欄位名：學號,姓名,學校)
app.post('/api/admin/students/import', auth, upload.single('file'), (req, res) => {
  const raw = fs.readFileSync(req.file.path, 'utf8');
  fs.unlinkSync(req.file.path);
  const rows = parse(raw, { columns: true, skip_empty_lines: true, trim: true });

  let inserted = 0, skipped = 0;
  const ins = db.prepare('INSERT OR IGNORE INTO students VALUES (?,?,?)');
  transaction(() => {
    for (const r of rows) {
      const sid    = r.student_id    ?? r['學號'];
      const name   = r.name          ?? r['姓名'];
      const school = r.school        ?? r['學校'];
      if (!sid || !name || !school) { skipped++; continue; }
      const result = ins.run(sid, name, school);
      result.changes > 0 ? inserted++ : skipped++;
    }
  });
  res.json({ inserted, skipped, total: rows.length });
});

// ── Admin: Enrollments ──────────────────────────────────────────────────────

app.get('/api/admin/enrollments/:activityId', auth, (req, res) =>
  res.json(db.prepare(`
    SELECT s.* FROM students s
    JOIN enrollments e ON e.student_id = s.student_id
    WHERE e.activity_id = ?
    ORDER BY s.student_id
  `).all(req.params.activityId))
);

app.post('/api/admin/enrollments', auth, (req, res) => {
  const { student_id, activity_id } = req.body;
  try {
    db.prepare('INSERT INTO enrollments VALUES (?,?)').run(student_id, activity_id);
    res.json({ ok: true });
  } catch (e) {
    res.status(e.message.includes('UNIQUE') ? 409 : 500).json({ error: e.message });
  }
});

app.delete('/api/admin/enrollments', auth, (req, res) => {
  const { student_id, activity_id } = req.body;
  db.prepare('DELETE FROM enrollments WHERE student_id=? AND activity_id=?').run(student_id, activity_id);
  res.json({ ok: true });
});

// Bulk enroll from CSV  (欄位：學號,活動名稱)
app.post('/api/admin/enrollments/import', auth, upload.single('file'), (req, res) => {
  const raw = fs.readFileSync(req.file.path, 'utf8');
  fs.unlinkSync(req.file.path);
  const rows = parse(raw, { columns: true, skip_empty_lines: true, trim: true });

  let inserted = 0, skipped = 0;
  const ins    = db.prepare('INSERT OR IGNORE INTO enrollments VALUES (?,?)');
  const getAct = db.prepare('SELECT id FROM activities WHERE name = ?');
  transaction(() => {
    for (const row of rows) {
      const sid   = row.student_id    ?? row['學號'];
      const aName = row.activity_name ?? row['活動名稱'];
      const act   = getAct.get(aName);
      if (!sid || !act) { skipped++; continue; }
      const result = ins.run(sid, act.id);
      result.changes > 0 ? inserted++ : skipped++;
    }
  });
  res.json({ inserted, skipped, total: rows.length });
});

// ── Admin: Template ─────────────────────────────────────────────────────────

app.post('/api/admin/template', auth, upload.single('template'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: '未收到檔案' });
  fs.copyFileSync(req.file.path, path.join(__dirname, 'public', 'template.pdf'));
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
