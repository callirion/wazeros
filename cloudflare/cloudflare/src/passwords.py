"""Password authentication retired in v29; no password hashes are computed."""
def encode(*args, **kwargs):
    raise RuntimeError("Password authentication disabled; use email-link login")
def verify(*args, **kwargs):
    raise RuntimeError("Password authentication disabled; use email-link login")
