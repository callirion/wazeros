import asyncio
import json
import logging
import sys
from types import SimpleNamespace
import pytest
from src import email_auth

@pytest.mark.parametrize("status,body,code,reason", [
    (401, '{"name":"validation_error","message":"API key is invalid"}', "validation_error", "api_key_invalid_or_inactive"),
    (403, '{"name":"validation_error","message":"You can only send testing emails to your own email address (private@example.com)"}', "validation_error", "testing_recipient_restricted"),
    (403, '{"name":"validation_error","message":"The private.example domain is not verified"}', "validation_error", "sender_domain_unverified"),
    (403, 'error code: 1010', "unknown", "provider_access_blocked"),
    (429, '{"name":"daily_quota_exceeded"}', "daily_quota_exceeded", "provider_rate_or_quota_limit"),
    (503, 'unavailable', "unknown", "provider_unavailable"),
    (400, '[]', "unknown", "provider_request_rejected"),
    (400, '{"name":["unexpected"],"message":null}', "unknown", "provider_request_rejected"),
    (400, '{"name":"private@example.com"}', "unknown", "provider_request_rejected"),
])
def test_diagnostic(status, body, code, reason):
    assert email_auth.provider_diagnostic(status, body) == (code, reason)

@pytest.mark.parametrize("status", [200, 201, 202])
def test_native_fetch_success(monkeypatch, status):
    captured = {}
    class Result:
        async def text(self): return '{"id":"test-only"}'
    result = Result(); result.status = status
    async def fetch(url, **kwargs):
        captured.update(url=url, **kwargs); return result
    monkeypatch.setitem(sys.modules, 'workers', SimpleNamespace(fetch=fetch))
    headers = {"Authorization":"Bearer test-only"}
    asyncio.run(email_auth.provider_send({"to":["private@example.com"]}, headers))
    assert captured['headers']['User-Agent'] == 'Wazeros/30.0.0'
    assert 'User-Agent' not in headers
    assert json.loads(captured['body'])['to'] == ['private@example.com']

def test_failure_logs_no_secrets(monkeypatch, caplog):
    class Result:
        status = 401
        async def text(self):
            return '{"name":"validation_error","message":"API key is invalid private@example.com re_PRIVATE token_PRIVATE"}'
    async def fetch(*args, **kwargs): return Result()
    monkeypatch.setitem(sys.modules, 'workers', SimpleNamespace(fetch=fetch))
    with caplog.at_level(logging.ERROR), pytest.raises(email_auth.EmailProviderError):
        asyncio.run(email_auth.provider_send({}, {"Authorization":"Bearer re_PRIVATE"}))
    assert 'status=401 code=validation_error reason=api_key_invalid_or_inactive' in caplog.text
    for secret in ['private@example.com', 're_PRIVATE', 'token_PRIVATE']:
        assert secret not in caplog.text

def test_timeout_covers_response_body(monkeypatch):
    class Result:
        status = 200
        async def text(self): raise asyncio.TimeoutError()
    async def fetch(*args, **kwargs): return Result()
    monkeypatch.setitem(sys.modules, 'workers', SimpleNamespace(fetch=fetch))
    with pytest.raises(asyncio.TimeoutError):
        asyncio.run(email_auth.provider_send({}, {}))
