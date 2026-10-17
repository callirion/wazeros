"""Generate an unverified, passwordless test account SQL statement. Staging only."""
import argparse
import re
import uuid
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--staging-only',action='store_true',required=True)
p.add_argument('--email',required=True)
a=p.parse_args()
email=a.email.strip().lower()
if len(email)>254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+",email):p.error('Invalid email')
def quote(value):return "'"+value.replace("'","''")+"'"
print("INSERT INTO users(id,email,password_hash,verified,locale) VALUES ("+quote(str(uuid.uuid4()))+","+quote(email)+",'!email-link-only',0,'en') ON CONFLICT(email) DO NOTHING;")
