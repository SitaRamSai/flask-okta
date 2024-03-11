import asyncio
import json
from okta_jwt_verifier import AccessTokenVerifier, IDTokenVerifier

def is_access_token_valid(token, issuer):
    async def verify_access_token():
        jwt_verifier = AccessTokenVerifier(issuer=issuer, audience='api://SPA')
        try:
            await jwt_verifier.verify(token)
            return True
        except Exception:
            return False

    return asyncio.run(verify_access_token())

def is_id_token_valid(token, issuer, client_id, nonce):
    async def verify_id_token():
        jwt_verifier = IDTokenVerifier(issuer=issuer, client_id=client_id, audience='api://SPA')
        try:
            await jwt_verifier.verify(token, nonce=nonce)
            return True
        except Exception:
            return False

    return asyncio.run(verify_id_token())

def load_config(fname='./client_secrets.json'):
    with open(fname) as f:
        return json.load(f)

config = load_config()
