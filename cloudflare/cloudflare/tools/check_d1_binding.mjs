// Local binding integration only. Does not load the Python API or remote D1.
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';
const state=await mkdtemp(join(tmpdir(),'wazeros-binding-'));
const options={modules:true,script:'export default {fetch(){return new Response("test")}}',compatibilityDate:'2026-10-13',d1Databases:{DB:'m1-binding-tests'},d1Persist:state,cf:false};
let mf=new Miniflare(convertV4MiniflareOptions(options));
try {
 let db=await mf.getD1Database('DB');
 const schema=await readFile(new URL('../migrations/0001_m1.sql',import.meta.url),'utf8');
 const statements=schema.replace(/^--.*$/gm,'').split(/;(?=\s*(?:CREATE\b|$))/i).map(x=>x.trim()).filter(Boolean);
 await db.batch(statements.map(sql=>db.prepare(sql)));
 await db.prepare("INSERT INTO users(id,email,password_hash) VALUES ('u','test@example.com','test-only')").run();
 await assert.rejects(db.batch([
  db.prepare("INSERT INTO organizations VALUES ('rollback','Rollback','general','USD')"),
  db.prepare("INSERT INTO memberships VALUES ('rollback','missing-user','owner')")
 ]));
 assert.equal(await db.prepare("SELECT id FROM organizations WHERE id='rollback'").first(),null);
 console.log('PASS D1 binding batch rollback on foreign-key failure');
 await db.prepare("INSERT INTO action_tokens VALUES ('token','u','verify',unixepoch()+3600)").run();
 const consume=()=>db.batch([
  db.prepare("INSERT INTO token_uses VALUES ((SELECT token_hash FROM action_tokens WHERE token_hash='token' AND expires_at>unixepoch()),unixepoch())"),
  db.prepare("UPDATE users SET verified=1 WHERE id='u'"),
  db.prepare("DELETE FROM action_tokens WHERE token_hash='token'")
 ]);
 const outcomes=await Promise.allSettled([consume(),consume()]);
 assert.equal(outcomes.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(outcomes.filter(x=>x.status==='rejected').length,1);
 assert.equal((await db.prepare("SELECT verified FROM users WHERE id='u'").first()).verified,1);
 assert.equal((await db.prepare('SELECT count(*) AS n FROM token_uses').first()).n,1);
 console.log('PASS concurrent token consumption: one commit, one rejection');
 await db.prepare("INSERT INTO organizations VALUES ('o','Workspace','general','USD')").run();
 await db.prepare("INSERT INTO snapshots VALUES ('s','o','Report','{\"rows\":[]}','2026-10-17')").run();
 console.log('Snapshot restart persistence is covered separately by check_d1_local.py.');
 console.log('All local D1 binding checks passed; Python FFI and remote runtime remain unverified.');
} finally {await mf.dispose();await rm(state,{recursive:true,force:true});}
