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
  color TEXT,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL, -- epoch ms
  active INTEGER NOT NULL DEFAULT 1,
  FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS chores (
  id TEXT PRIMARY KEY,
  kid_id TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  due_ts INTEGER NOT NULL,      -- epoch ms
  status TEXT NOT NULL,
  reward_value INTEGER NOT NULL,
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,  -- epoch ms
  completed_at INTEGER,         -- epoch ms
  completed_by TEXT,
  FOREIGN KEY(kid_id) REFERENCES kids(id),
  FOREIGN KEY(created_by) REFERENCES users(id),
  FOREIGN KEY(completed_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS gift_cards (
  id TEXT PRIMARY KEY,
  code_or_token TEXT NOT NULL,
  provider TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  status TEXT NOT NULL,
  kid_id TEXT,
  redeemed_at INTEGER,         -- epoch ms
  created_by TEXT NOT NULL,
  created_at INTEGER NOT NULL, -- epoch ms
  FOREIGN KEY(kid_id) REFERENCES kids(id),
  FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS reward_redemptions (
  id TEXT PRIMARY KEY,
  kid_id TEXT NOT NULL,
  chore_id TEXT NOT NULL,
  gift_card_id TEXT NOT NULL,
  issued_at INTEGER NOT NULL, -- epoch ms
  issued_by TEXT NOT NULL,
  FOREIGN KEY(kid_id) REFERENCES kids(id),
  FOREIGN KEY(chore_id) REFERENCES chores(id),
  FOREIGN KEY(gift_card_id) REFERENCES gift_cards(id),
  FOREIGN KEY(issued_by) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_chores_kid_status_due_ts ON chores (kid_id, status, due_ts);
CREATE INDEX IF NOT EXISTS idx_gift_cards_kid_status ON gift_cards (kid_id, status);
