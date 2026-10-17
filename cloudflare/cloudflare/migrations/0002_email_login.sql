CREATE TABLE IF NOT EXISTS email_login_challenges (
 token_hash TEXT PRIMARY KEY,
 email TEXT NOT NULL,
 browser_hash TEXT NOT NULL,
 legal_version TEXT,
 expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS email_login_expiry ON email_login_challenges(expires_at);
DELETE FROM sessions;
DELETE FROM action_tokens;
