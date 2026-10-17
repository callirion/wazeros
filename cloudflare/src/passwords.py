import hashlib,hmac,secrets
ITERATIONS=600_000
def encode(password):
    salt=secrets.token_hex(16)
    key=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),ITERATIONS)
    return f'pbkdf2_sha256${ITERATIONS}${salt}${key.hex()}'
def verify(encoded,password):
    try:
        algorithm,n,salt,expected=encoded.split('$')
        if algorithm!='pbkdf2_sha256' or int(n)!=ITERATIONS:return False
        key=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),ITERATIONS)
        return hmac.compare_digest(key.hex(),expected)
    except (ValueError,TypeError):return False
