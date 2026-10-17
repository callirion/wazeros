-- New staging database only. Not a migration of existing PostgreSQL users.
CREATE TABLE users (
 id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 verified INTEGER NOT NULL DEFAULT 0 CHECK(verified IN (0,1)), locale TEXT NOT NULL DEFAULT 'en'
);
CREATE TABLE sessions (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);
CREATE TABLE action_tokens (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 purpose TEXT NOT NULL CHECK(purpose IN ('verify','reset')), expires_at INTEGER NOT NULL,
 UNIQUE(user_id,purpose)
);
CREATE TABLE legal_acceptances (
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, version TEXT NOT NULL,
 created_at TEXT NOT NULL, PRIMARY KEY(user_id,version)
);
CREATE TABLE organizations (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, industry TEXT NOT NULL, currency TEXT NOT NULL
);
CREATE TABLE memberships (
 org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 role TEXT NOT NULL CHECK(role IN ('owner','admin','manager','member')),
 PRIMARY KEY(org_id,user_id)
);
CREATE INDEX memberships_user ON memberships(user_id);
CREATE TABLE entitlements (
 org_id TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL, reference TEXT NOT NULL
);
CREATE TABLE snapshots (
 id TEXT PRIMARY KEY, org_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
 name TEXT NOT NULL, data TEXT NOT NULL CHECK(json_valid(data)), created_at TEXT NOT NULL
);
CREATE INDEX snapshots_org ON snapshots(org_id,created_at);
CREATE TRIGGER snapshots_limit BEFORE INSERT ON snapshots
WHEN (SELECT count(*) FROM snapshots WHERE org_id=NEW.org_id)>=50
BEGIN SELECT RAISE(ABORT,'snapshot_limit'); END;
CREATE TABLE audit_events (
 id TEXT PRIMARY KEY, org_id TEXT REFERENCES organizations(id) ON DELETE CASCADE,
 actor_id TEXT REFERENCES users(id) ON DELETE SET NULL, action TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE rate_limits (key TEXT PRIMARY KEY, count INTEGER NOT NULL, reset_at INTEGER NOT NULL);

-- A unique consumption guard makes token use atomic inside a D1 batch.
CREATE TABLE token_uses (token_hash TEXT NOT NULL PRIMARY KEY, used_at INTEGER NOT NULL);
