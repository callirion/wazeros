"""Same-browser, explicit-confirmation email login. No password hashing."""
import asyncio
import hmac
import json
import logging
import re
import secrets
import time
from urllib.parse import urlsplit
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field, field_validator

router = APIRouter()
BROWSER_COOKIE = "wazeros_login_browser"
TTL = 600
GENERIC = {"message": "If eligible, a sign-in email will arrive. Open it in this same browser within 10 minutes."}

def core():
    from . import api
    return api

class EmailLoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    accept_terms: bool = False
    document_version: str = Field(default="", max_length=160)

    @field_validator("email")
    @classmethod
    def email_valid(cls, value):
        value = value.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("Invalid email")
        return value

class EmailLoginConfirm(BaseModel):
    token: str = Field(min_length=43, max_length=43, pattern=r"^[A-Za-z0-9_-]+$")

def public_origin(request):
    c = core()
    origin = c.setting(request, "AUTH_PUBLIC_ORIGIN").rstrip("/")
    p = urlsplit(origin)
    if p.scheme != "https" or not p.netloc or p.username or p.password or p.path or p.query or p.fragment:
        raise HTTPException(503, "Set AUTH_PUBLIC_ORIGIN to the Worker HTTPS origin")
    # Initial staging UI is same-origin only. Cross-origin frontend integration is deferred.
    if c.setting(request, "FRONTEND_URL").rstrip("/") != origin:
        raise HTTPException(503, "Email login staging requires matching FRONTEND_URL and AUTH_PUBLIC_ORIGIN")
    return origin

async def quota(store, key, limit, seconds):
    c = core(); current = c.now(); reset = (current // seconds + 1) * seconds
    row = await store.first(
        "INSERT INTO rate_limits VALUES (?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN reset_at<=? THEN 1 ELSE count+1 END,reset_at=CASE WHEN reset_at<=? THEN excluded.reset_at ELSE reset_at END RETURNING count",
        c.digest(key), reset, current, current,
    )
    if row["count"] > limit:
        raise HTTPException(429, "Too many requests. Try again later.")

# Only fixed, non-sensitive categories reach logs. Never log provider bodies,
# recipient addresses, Authorization headers, or sign-in tokens.
PROVIDER_CODES = frozenset({
    "validation_error", "missing_api_key", "restricted_api_key",
    "suspended_api_key", "invalid_permission", "invalid_idempotency_key",
    "daily_quota_exceeded", "monthly_quota_exceeded", "rate_limit_exceeded",
    "missing_required_field", "invalid_parameter", "application_error",
    "service_unavailable", "concurrent_idempotent_requests",
    "invalid_idempotent_request",
})

class EmailProviderError(RuntimeError):
    pass

def provider_diagnostic(status, text):
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    name = data.get("name")
    code = name if isinstance(name, str) and name in PROVIDER_CODES else "unknown"
    message = data.get("message", "")
    message = message.lower() if isinstance(message, str) else ""
    if "api key" in message and any(x in message for x in ("invalid", "missing", "not active", "suspended")):
        reason = "api_key_invalid_or_inactive"
    elif "only send testing emails" in message:
        reason = "testing_recipient_restricted"
    elif "domain" in message and "not verified" in message:
        reason = "sender_domain_unverified"
    elif status == 403 and "1010" in text:
        reason = "provider_access_blocked"
    elif status == 401:
        reason = "authentication_rejected"
    elif status == 429:
        reason = "provider_rate_or_quota_limit"
    elif status >= 500:
        reason = "provider_unavailable"
    else:
        reason = "provider_request_rejected"
    return code, reason

async def provider_send(payload, headers):
    # Native Worker fetch avoids unsupported socket transports in WebAssembly.
    from workers import fetch
    # Explicit User-Agent is required for direct Resend API requests.
    headers = {**headers, "User-Agent": "Wazeros/30.0.0"}
    async def perform():
        result = await fetch(
            "https://api.resend.com/emails", method="POST", headers=headers,
            body=json.dumps(payload),
        )
        return int(result.status), await result.text()
    # Include reading the response in the timeout, not just receiving headers.
    status, text = await asyncio.wait_for(perform(), timeout=15)
    if not 200 <= status < 300:
        code, reason = provider_diagnostic(status, text)
        logging.getLogger("wazeros.auth").error(
            "email_provider_rejected release=30.0.0 status=%s code=%s reason=%s",
            status, code, reason,
        )
        raise EmailProviderError("Email provider rejected request")

async def send_link(request, email, token):
    c = core()
    link = public_origin(request) + "/auth/email#token=" + token
    await provider_send(
        {"from": c.setting(request, "MAIL_FROM").strip(), "to": [email],
         "subject": "Your Wazeros sign-in link",
         "text": "Open this link in the browser where you requested it, then press Confirm sign-in. It expires in 10 minutes and works once.\n\n" + link + "\n\nIf you did not request this, ignore this email."},
        {"Authorization": "Bearer " + c.setting(request, "MAIL_API_KEY").strip(),
         "Content-Type": "application/json",
         "Idempotency-Key": "email-login/" + c.digest(token)},
    )

@router.post("/auth/email/request", status_code=202)
async def request_link(body: EmailLoginRequest, request: Request, response: Response):
    c = core(); public_origin(request)
    if not c.mail_ready(request):
        raise HTTPException(503, "Email delivery is not configured")
    started = time.monotonic(); store = c.db(request)
    ip = request.headers.get("cf-connecting-ip", request.client.host if request.client else "unknown")
    await quota(store, "email-ip:" + ip, 5, 900)
    await quota(store, "email-address:" + body.email, 5, 900)
    await quota(store, "email-global-day", 50, 86400)
    browser = request.cookies.get(BROWSER_COOKIE, "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", browser):
        browser = secrets.token_urlsafe(32)
    response.set_cookie(BROWSER_COOKIE, browser, max_age=TTL, secure=True, httponly=True, samesite="strict", path="/auth/email")
    token = secrets.token_urlsafe(32)
    user = await store.first("SELECT id FROM users WHERE email=?", body.email)
    legal = c.setting(request, "LEGAL_VERSION")
    new_allowed = c.setting(request, "REGISTRATION_ENABLED") == "true" and body.accept_terms and bool(legal) and body.document_version == legal
    # A dummy challenge follows the same DB path for ineligible addresses.
    await store.batch([
        ("DELETE FROM email_login_challenges WHERE expires_at<=?", (c.now(),)),
        ("DELETE FROM email_login_challenges WHERE email=?", (body.email,)),
        ("INSERT INTO email_login_challenges VALUES (?,?,?,?,?)", (c.digest(token), body.email, c.digest(browser), legal if new_allowed and not user else None, c.now()+TTL)),
    ])
    if user or new_allowed:
        try:
            await send_link(request, body.email, token)
        except Exception as exc:
            await store.batch([("DELETE FROM email_login_challenges WHERE token_hash=?", (c.digest(token),))])
            logging.getLogger("wazeros.auth").error("email_delivery_failed type=%s", type(exc).__name__)
    else:
        await store.batch([("DELETE FROM email_login_challenges WHERE token_hash=?", (c.digest(token),))])
    # Minimum response duration reduces easy timing enumeration, not a constant-time guarantee.
    await asyncio.sleep(max(0, 1.0 - (time.monotonic() - started)))
    return GENERIC

@router.post("/auth/email/confirm")
async def confirm_link(body: EmailLoginConfirm, request: Request, response: Response):
    c = core(); public_origin(request); store = c.db(request)
    ip = request.headers.get("cf-connecting-ip", request.client.host if request.client else "unknown")
    await quota(store, "email-confirm:" + ip, 10, 900)
    hashed = c.digest(body.token)
    row = await store.first("SELECT * FROM email_login_challenges WHERE token_hash=? AND expires_at>?", hashed, c.now())
    browser = request.cookies.get(BROWSER_COOKIE, "")
    if not row or not browser or not hmac.compare_digest(row["browser_hash"], c.digest(browser)):
        raise HTTPException(400, "Invalid or expired sign-in link; request another in this browser")
    user = await store.first("SELECT * FROM users WHERE email=?", row["email"])
    legal = row["legal_version"]
    if not user and (c.setting(request,"REGISTRATION_ENABLED") != "true" or not legal or legal != c.setting(request,"LEGAL_VERSION")):
        raise HTTPException(400, "Invalid or expired sign-in link; request another in this browser")
    user_id = user["id"] if user else c.uid()
    session = secrets.token_urlsafe(32)
    items = [
        ("INSERT INTO token_uses(token_hash,used_at) VALUES ((SELECT token_hash FROM email_login_challenges WHERE token_hash=? AND expires_at>?),?)", (hashed, c.now(), c.now())),
    ]
    if not user:
        items.extend([
            ("INSERT INTO users(id,email,password_hash,verified) VALUES (?,?,?,1)", (user_id, row["email"], "!email-link-only")),
            ("INSERT INTO legal_acceptances VALUES (?,?,?)", (user_id, legal, c.stamp())),
            c.audit(user_id, "account.created.email_link"),
        ])
    else:
        items.append(("UPDATE users SET verified=1 WHERE id=?", (user_id,)))
    items.extend([
        ("DELETE FROM email_login_challenges WHERE token_hash=?", (hashed,)),
        ("INSERT INTO sessions VALUES (?,?,?)", (c.digest(session), user_id, c.now()+604800)),
        c.audit(user_id, "session.created.email_link"),
    ])
    try:
        await store.batch(items)
    except Exception as exc:
        if any(x in str(exc).upper() for x in ("UNIQUE", "NOT NULL")):
            raise HTTPException(400, "Invalid or expired sign-in link; request another in this browser")
        raise
    c.cookie(request, response, session)
    response.delete_cookie(BROWSER_COOKIE, path="/auth/email", secure=True, httponly=True, samesite="strict")
    return c.user_data({"id":user_id,"email":row["email"],"locale":user["locale"] if user else "en","verified":1})

@router.get("/auth/email/status")
async def email_status(request: Request):
    c = core(); public_origin(request)
    return {"auth":"email_link", "version":"30.0.0", "email_configured":c.mail_ready(request), "registration_enabled":c.setting(request,"REGISTRATION_ENABLED")=="true", "legal_version":c.setting(request,"LEGAL_VERSION"), "remote_acceptance":"not_established"}

@router.post("/auth/login")
@router.post("/auth/signup")
@router.post("/auth/forgot-password")
@router.post("/auth/reset-password")
@router.post("/auth/verify")
@router.post("/auth/resend-verification")
async def password_disabled():
    raise HTTPException(410, "Password authentication is disabled. Use /auth/email")

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Wazeros staging email login</title></head><body>
<h1>Wazeros staging sign-in</h1><p>Request and open the email link in this same browser. Links expire in 10 minutes. Do not share them.</p>
<form id="request"><label>Email <input id="email" type="email" maxlength="254" required autocomplete="email"></label>
<p id="registration" hidden><label><input id="terms" type="checkbox"> I have reviewed and accept the current legal documents.</label> <span id="legal"></span> Do not register until those documents have been provided.</p>
<button>Send sign-in link</button></form><button id="confirm" hidden>Confirm sign-in</button><button id="me">Check session</button><button id="logout">Sign out</button><pre id="message" role="status"></pre>
<script nonce="NONCE">
const message=document.getElementById('message');let config={},token=new URLSearchParams(location.hash.slice(1)).get('token');history.replaceState(null,'','/auth/email');
const confirmButton=document.getElementById('confirm');confirmButton.hidden=!token;
async function call(path,body,method='POST'){const r=await fetch(path,{method,credentials:'same-origin',headers:{'Content-Type':'application/json'},...(method==='GET'?{}:{body:JSON.stringify(body||{})})});const data=await r.json();message.textContent=JSON.stringify(data,null,2);return {r,data};}
fetch('/auth/email/status').then(r=>r.json()).then(x=>{config=x;document.getElementById('registration').hidden=!x.registration_enabled;document.getElementById('legal').textContent='Document version: '+(x.legal_version||'unset');}).catch(()=>message.textContent='Configuration unavailable');
document.getElementById('request').onsubmit=async e=>{e.preventDefault();const b=e.submitter;b.disabled=true;try{await call('/auth/email/request',{email:document.getElementById('email').value,accept_terms:document.getElementById('terms').checked,document_version:config.legal_version||''});}catch{message.textContent='Request failed. Try later.';}finally{b.disabled=false;}};
confirmButton.onclick=async()=>{confirmButton.disabled=true;try{const x=await call('/auth/email/confirm',{token});if(x.r.ok){token=null;confirmButton.hidden=true;}}catch{message.textContent='Confirmation failed';}finally{confirmButton.disabled=false;}};
document.getElementById('me').onclick=()=>call('/auth/me',null,'GET');document.getElementById('logout').onclick=()=>call('/auth/logout');
</script></body></html>"""

@router.get("/auth/email", response_class=HTMLResponse, include_in_schema=False)
async def email_page(request: Request):
    public_origin(request)
    nonce = secrets.token_urlsafe(24)
    return HTMLResponse(PAGE.replace("NONCE", nonce), headers={
        "Content-Security-Policy": "default-src 'none'; script-src 'nonce-"+nonce+"'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
        "Referrer-Policy":"no-referrer", "Cache-Control":"no-store", "X-Frame-Options":"DENY",
    })
