CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  iterations INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS calendars (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  color TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  calendar_id TEXT NOT NULL,
  title TEXT NOT NULL,
  location TEXT,
  icon TEXT,                 -- e.g. "mdi-stethoscope"
  start_ts INTEGER NOT NULL, -- epoch ms
  end_ts INTEGER NOT NULL,   -- epoch ms
  all_day INTEGER NOT NULL DEFAULT 0,
  rrule TEXT,                -- e.g. "FREQ=WEEKLY;INTERVAL=1;BYDAY=MO,WE;UNTIL=20261231T235959Z"
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(calendar_id) REFERENCES calendars(id),
  FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_events_calendar_start ON events (calendar_id, start_ts);
