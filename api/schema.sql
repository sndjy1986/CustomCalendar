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

CREATE TABLE IF NOT EXISTS kids (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  avatar TEXT,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS chores (
  id TEXT PRIMARY KEY,
  kid_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'assigned',
  due_ts INTEGER NOT NULL,
  completed_at INTEGER,
  rewarded_at INTEGER,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(kid_id) REFERENCES kids(id),
  FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS gift_cards (
  id TEXT PRIMARY KEY,
  code TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'available',
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  issued_to_kid_id TEXT,
  issued_for_chore_id TEXT,
  issued_at INTEGER,
  FOREIGN KEY(created_by) REFERENCES users(id),
  FOREIGN KEY(issued_to_kid_id) REFERENCES kids(id),
  FOREIGN KEY(issued_for_chore_id) REFERENCES chores(id)
);

CREATE INDEX IF NOT EXISTS idx_kids_created_by ON kids (created_by, created_at);
CREATE INDEX IF NOT EXISTS idx_chores_kid_status_due ON chores (kid_id, status, due_ts);
CREATE INDEX IF NOT EXISTS idx_chores_created_by ON chores (created_by, due_ts);
CREATE INDEX IF NOT EXISTS idx_gift_cards_created_by_status ON gift_cards (created_by, status, created_at);

