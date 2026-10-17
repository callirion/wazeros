"""Generate SQL for a NEW isolated staging database. No built-in credentials."""
import argparse,getpass,sys,time,uuid
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from src.passwords import encode
from src.schemas import Credentials
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--staging-only',action='store_true',required=True)
p.add_argument('--email',required=True)
a=p.parse_args()
password=getpass.getpass('New staging tester password (12-128 characters): ')
credentials=Credentials(email=a.email,password=password)
def quote(s):return "'"+str(s).replace("'","''")+"'"
u=str(uuid.uuid4());org=str(uuid.uuid4())
print('-- STAGING ONLY. Verified test account and seven-day manually granted access.')
print('INSERT INTO users(id,email,password_hash,verified) VALUES ('+','.join(map(quote,[u,credentials.email,encode(password)]))+',1);')
print('INSERT INTO organizations VALUES ('+','.join(map(quote,[org,'M1 staging workspace','general','USD']))+');')
print('INSERT INTO memberships VALUES ('+','.join(map(quote,[org,u,'owner']))+');')
print('INSERT INTO entitlements VALUES ('+quote(org)+','+str(int(time.time())+604800)+",'MANUAL STAGING TEST ONLY');")
