# auth.py
import os
import json
import requests
from functools import wraps
from flask import request, jsonify, abort, current_app
from jose import jwt
from jose.exceptions import JWTError, ExpiredSignatureError

AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "")
API_AUDIENCE = os.getenv("API_AUDIENCE", "")
ALGORITHMS = ["RS256"]

_jwks_cache = None

def get_jwks():
    global _jwks_cache
    if _jwks_cache is None:
        if not AUTH0_DOMAIN:
            current_app.logger.error("AUTH0_DOMAIN não configurado")
            return None
        jwks_url = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
        try:
            r = requests.get(jwks_url, timeout=5)
            r.raise_for_status()
            _jwks_cache = r.json()
        except Exception as e:
            current_app.logger.error("Erro ao buscar JWKS: %s", e)
            _jwks_cache = None
    return _jwks_cache

def _get_token_auth_header():
    auth = request.headers.get("Authorization", None)
    if not auth:
        abort(401, description="Authorization header is expected.")
    parts = auth.split()
    if parts[0].lower() != "bearer":
        abort(401, description="Authorization header must start with Bearer.")
    elif len(parts) == 1:
        abort(401, description="Token not found.")
    elif len(parts) > 2:
        abort(401, description="Authorization header must be Bearer token.")
    token = parts[1]
    return token

def requires_auth(required_scopes=None):
    """
    Decorator factory. Use @requires_auth() or @requires_auth(['scope1']).
    It decodes token, validates audience/issuer and stores payload em request.current_user.
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = _get_token_auth_header()
            jwks = get_jwks()
            if jwks is None:
                abort(500, description="JWKS indisponível")
            try:
                unverified_header = jwt.get_unverified_header(token)
            except JWTError:
                abort(401, description="Invalid header.")
            rsa_key = {}
            for key in jwks.get("keys", []):
                if key.get("kid") == unverified_header.get("kid"):
                    rsa_key = {
                        "kty": key.get("kty"),
                        "kid": key.get("kid"),
                        "use": key.get("use"),
                        "n": key.get("n"),
                        "e": key.get("e")
                    }
            if not rsa_key:
                abort(401, description="Unable to find appropriate key")
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_AUDIENCE,
                    issuer=f"https://{AUTH0_DOMAIN}/"
                )
            except ExpiredSignatureError:
                abort(401, description="token expired")
            except JWTError as e:
                abort(401, description=f"Invalid token: {e}")

            # optional scope check (if provided)
            if required_scopes:
                token_scopes = []
                sc = payload.get("scope")
                if isinstance(sc, str):
                    token_scopes = sc.split()
                # also check permissions claim if RBAC is enabled
                perms = payload.get("permissions", [])
                for scope in required_scopes:
                    if scope in token_scopes or scope in perms:
                        continue
                    abort(403, description="insufficient_scope")
            # attach payload to request
            request.current_user = payload
            return f(*args, **kwargs)
        return wrapper
    return decorator

def is_admin_from_payload(payload):
    """
    Detecta admin a partir do payload do token.
    Ajuste conforme seu Auth0 (roles em namespaced claim, permissions, etc).
    """
    if not payload:
        return False
    # 1) permissions RBAC
    perms = payload.get("permissions", []) or []
    if isinstance(perms, list) and ("delete:trip" in perms or "delete:investor" in perms):
        return True
    # 2) roles field
    roles = payload.get("roles") or payload.get("role")
    if isinstance(roles, str):
        roles = [roles]
    if isinstance(roles, list) and any(r.lower() == "admin" for r in roles):
        return True
    # 3) namespaced custom claim: .../roles
    for k, v in payload.items():
        if isinstance(k, str) and k.endswith("/roles"):
            if isinstance(v, list) and any(r.lower() == "admin" for r in v):
                return True
    return False

def requires_admin():
    """
    Decorator that enforces authentication and admin role.
    Use @requires_admin()
    """
    def decorator(f):
        @wraps(f)
        @requires_auth()
        def wrapper(*args, **kwargs):
            payload = getattr(request, "current_user", None)
            if not is_admin_from_payload(payload):
                abort(403, description="Admin role required")
            return f(*args, **kwargs)
        return wrapper
    return decorator

def register_auth_error_handlers(app):
    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({"error": "unauthorized", "message": getattr(e, "description", "")}), 401

    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({"error": "forbidden", "message": getattr(e, "description", "")}), 403

    @app.errorhandler(500)
    def internal(e):
        return jsonify({"error": "internal_server_error", "message": getattr(e, "description", "")}), 500