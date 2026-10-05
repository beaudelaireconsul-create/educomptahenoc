PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS schools (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, school_id INTEGER NOT NULL REFERENCES schools(id),
  email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'director' CHECK(role IN ('director','accountant')));
CREATE TABLE IF NOT EXISTS students (
  id INTEGER PRIMARY KEY, school_id INTEGER NOT NULL REFERENCES schools(id),
  name TEXT NOT NULL, class TEXT, parent_phone TEXT NOT NULL,
  total_fee INTEGER NOT NULL CHECK(total_fee >= 0),
  created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_students_school ON students(school_id);
CREATE INDEX IF NOT EXISTS idx_students_phone ON students(parent_phone);
CREATE TABLE IF NOT EXISTS payments (
  id INTEGER PRIMARY KEY, school_id INTEGER NOT NULL REFERENCES schools(id),
  student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE,
  amount INTEGER NOT NULL CHECK(amount > 0), method TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'paid' CHECK(status IN ('pending','paid','failed')),
  provider_ref TEXT UNIQUE, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS idx_pay_student ON payments(student_id);
