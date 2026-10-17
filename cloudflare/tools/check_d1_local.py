"""Integration checks through Wrangler local D1, not a sqlite3 substitute.
Uses a fresh temporary persistence directory; never connects to remote resources.
"""
import argparse,json,os,subprocess,tempfile,uuid
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--wrangler',default='wrangler')
a=p.parse_args();root=Path(__file__).resolve().parents[1]
env={**os.environ,'CI':'true','WRANGLER_SEND_METRICS':'false'}
with tempfile.TemporaryDirectory(prefix='wazeros-d1-') as state:
    def run(args,ok=True):
        result=subprocess.run([a.wrangler,*args,'--local','--persist-to',state],cwd=root,env=env,text=True,capture_output=True,timeout=60)
        if ok and result.returncode:raise RuntimeError(result.stdout+'\n'+result.stderr)
        return result
    def sql(query,ok=True):
        result=run(['d1','execute','wazeros-m1-staging','--command',query,'--json'],ok)
        if not ok:return result
        return json.loads(result.stdout)[0]['results']
    run(['d1','migrations','apply','wazeros-m1-staging'])
    print('PASS migration applied through local D1')
    sql("INSERT INTO users(id,email,password_hash,verified) VALUES ('u1','one@example.com','test-only',1),('u2','two@example.com','test-only',1); INSERT INTO organizations VALUES ('o1','One','general','USD'),('o2','Two','general','USD'); INSERT INTO memberships VALUES ('o1','u1','owner'),('o2','u2','owner');")
    sql("INSERT INTO snapshots VALUES ('s1','o1','Test','{\"rows\":[]}','2026-10-17');")
    assert sql("SELECT id FROM snapshots WHERE id='s1' AND org_id='o1'")==[{'id':'s1'}]
    assert sql("SELECT id FROM snapshots WHERE id='s1' AND org_id='o2'")==[]
    print('PASS snapshot persisted across separate Wrangler processes; org-scoped query excludes other org')
    assert sql("SELECT o.id FROM organizations o JOIN memberships m ON m.org_id=o.id WHERE o.id='o1' AND m.user_id='u2'")==[]
    print('PASS membership isolation query')
    sql("INSERT INTO action_tokens VALUES ('verify-token','u1','verify',unixepoch()+3600);")
    consume="INSERT INTO token_uses VALUES ((SELECT token_hash FROM action_tokens WHERE token_hash='verify-token' AND purpose='verify' AND expires_at>unixepoch()),unixepoch()); DELETE FROM action_tokens WHERE token_hash='verify-token';"
    sql(consume)
    assert run(['d1','execute','wazeros-m1-staging','--command',consume,'--json'],False).returncode!=0
    print('PASS sequential token reuse rejected by database constraint')
    assert sql("INSERT INTO memberships VALUES ('missing','u1','owner')",False).returncode!=0
    print('PASS foreign-key constraint')
    sql(";".join("INSERT INTO snapshots VALUES ('s"+str(i+1)+"','o1','Test','{\"rows\":[]}','2026-10-17')" for i in range(1,50)))
    assert sql("INSERT INTO snapshots VALUES ('overflow','o1','Test','{\"rows\":[]}','2026-10-17')",False).returncode!=0
    print('PASS 50-snapshot database cap')
    assert sql("SELECT count(*) AS n FROM snapshots WHERE org_id='o1'")==[{'n':50}]
    print('PASS final persisted count')
print('Local D1 checks passed. This does not test the Python ASGI runtime, D1 binding batch(), or remote D1.')
