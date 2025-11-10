# app.py
import os
import time
import logging
from dotenv import load_dotenv
from flask import Flask, request, jsonify, make_response
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from bson.errors import InvalidId
from pymongo import ReturnDocument
from flask_cors import CORS
from datetime import datetime

from auth import requires_auth, requires_admin, register_auth_error_handlers

# ---------------------------------------------------------------------
# Configuração inicial
# ---------------------------------------------------------------------
load_dotenv()
app = Flask(__name__)

# logging
logging.basicConfig(level=logging.DEBUG)
app.logger.setLevel(logging.DEBUG)

# ---------------------------------------------------------------------
# Configuração do MongoDB
# ---------------------------------------------------------------------
app.config["MONGO_URI"] = os.getenv("MONGO_URI", "mongodb://localhost:27017/pfzambomdb")
mongo = PyMongo(app)

# ---------------------------------------------------------------------
# CORS (FRONTEND_ORIGINS ou CORS_ORIGINS)
# ---------------------------------------------------------------------
_raw_origins = os.getenv("FRONTEND_ORIGINS") or os.getenv("CORS_ORIGINS") or "http://localhost:5173"
_raw_origins = _raw_origins.strip()
if _raw_origins == "*" or _raw_origins.lower() == "any":
    cors_origins = "*"
else:
    cors_origins = [o.strip() for o in _raw_origins.split(",") if o.strip()]

CORS(
    app,
    resources={r"/*": {"origins": cors_origins}},
    supports_credentials=True,
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "Accept", "Idempotency-Key"],
)

# ---------------------------------------------------------------------
# Registro de handlers de erro do Auth0
# ---------------------------------------------------------------------
register_auth_error_handlers(app)

# ---------------------------------------------------------------------
# Preflight OPTIONS rápido
# ---------------------------------------------------------------------
@app.before_request
def handle_preflight():
    if request.method != "OPTIONS":
        return None

    origin = request.headers.get("Origin")
    allowed_origin = None

    if cors_origins == "*":
        allowed_origin = "*" if origin else "*"
    else:
        if origin and origin in cors_origins:
            allowed_origin = origin

    resp = make_response("", 204)
    if allowed_origin:
        resp.headers["Access-Control-Allow-Origin"] = allowed_origin
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Methods"] = "GET,POST,PUT,DELETE,OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Authorization,Content-Type,Accept,Idempotency-Key"
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Max-Age"] = "3600"
    return resp

# ---------------------------------------------------------------------
# Logging: não logar Authorization header
# ---------------------------------------------------------------------
@app.before_request
def log_request_info():
    if request.method == "OPTIONS":
        return
    hdrs = {k: v for k, v in request.headers.items() if k in ("Host", "Origin", "Content-Type")}
    body_preview = request.get_data(as_text=True)[:500] if request.data else ""
    app.logger.debug("Incoming request: %s %s headers=%s body_preview=%s", request.method, request.path, hdrs, body_preview)


# ---------------------------------------------------------------------
# Health / Ready
# ---------------------------------------------------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "pf-zambom-back"}), 200

@app.route("/ready", methods=["GET"])
def ready():
    try:
        mongo.db.command("ping")
        return jsonify({"ready": True}), 200
    except Exception:
        return jsonify({"ready": False}), 503

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------
def serialize_doc(doc):
    # converte ObjectId e datetimes para strings
    doc = dict(doc)
    if "_id" in doc:
        doc["_id"] = str(doc["_id"])
    for k, v in list(doc.items()):
        if isinstance(v, datetime):
            doc[k] = v.isoformat()
    return doc

# ---------------------------------------------------------------------
# Rotas: INVESTIDORES
# ---------------------------------------------------------------------
@app.route("/investors", methods=["GET"])
@requires_auth()
def list_investors():
    cursor = mongo.db.investors.find().sort("created_at", -1)
    items = [serialize_doc(i) for i in cursor]
    return jsonify(items), 200

@app.route("/investors", methods=["POST"])
@requires_auth()
def create_investor():
    data = request.get_json() or {}
    name = data.get("name") or data.get("nome")
    corretora = data.get("corretora")
    valor = data.get("valor_investido") or data.get("valor")
    perfil = data.get("perfil")
    if not (name and corretora and valor and perfil):
        return jsonify({"error": "Campos obrigatórios: name, corretora, valor_investido, perfil"}), 400
    try:
        valor_float = float(valor)
    except Exception:
        return jsonify({"error": "valor_investido deve ser numérico"}), 400

    doc = {
        "name": name,
        "corretora": corretora,
        "valor_investido": valor_float,
        "perfil": perfil,
        "created_at": datetime.utcnow()
    }
    inserted = mongo.db.investors.insert_one(doc)
    doc["_id"] = str(inserted.inserted_id)
    doc["created_at"] = doc["created_at"].isoformat()
    return jsonify(doc), 201

@app.route("/investors/<id>", methods=["DELETE"])
@requires_admin()
def delete_investor(id):
    try:
        _id = ObjectId(id)
    except Exception:
        return jsonify({"error": "ID inválido"}), 400
    res = mongo.db.investors.delete_one({"_id": _id})
    if res.deleted_count == 0:
        return jsonify({"error": "Investidor não encontrado"}), 404
    return jsonify({"message": "Investidor removido"}), 200

# ---------------------------------------------------------------------
# Rotas: VIAGENS (TRIPS)
# ---------------------------------------------------------------------
@app.route("/trips", methods=["GET"])
@requires_auth()
def list_trips():
    cursor = mongo.db.trips.find().sort("created_at", -1)
    items = [serialize_doc(i) for i in cursor]
    return jsonify(items), 200

@app.route("/trips", methods=["POST"])
@requires_auth()
def create_trip():
    data = request.get_json() or {}
    titulo = data.get("titulo") or data.get("title")
    destino = data.get("destino") or data.get("destination")
    data_inicio = data.get("data_inicio") or data.get("start_date")
    data_fim = data.get("data_fim") or data.get("end_date")
    preco = data.get("preco") or data.get("price")
    if not (titulo and destino and data_inicio and data_fim and preco):
        return jsonify({"error": "Campos obrigatórios: titulo, destino, data_inicio, data_fim, preco"}), 400
    try:
        dt_inicio = datetime.fromisoformat(data_inicio)
        dt_fim = datetime.fromisoformat(data_fim)
        preco_f = float(preco)
    except Exception:
        return jsonify({"error": "Formato de data inválido (YYYY-MM-DD) ou preço inválido"}), 400

    doc = {
        "titulo": titulo,
        "destino": destino,
        "data_inicio": dt_inicio,
        "data_fim": dt_fim,
        "preco": preco_f,
        "created_at": datetime.utcnow()
    }
    inserted = mongo.db.trips.insert_one(doc)
    doc["_id"] = str(inserted.inserted_id)
    # convert datetimes to iso
    doc["data_inicio"] = dt_inicio.isoformat()
    doc["data_fim"] = dt_fim.isoformat()
    doc["created_at"] = doc["created_at"].isoformat()
    return jsonify(doc), 201

@app.route("/trips/<id>", methods=["DELETE"])
@requires_admin()
def delete_trip(id):
    try:
        _id = ObjectId(id)
    except Exception:
        return jsonify({"error": "ID inválido"}), 400
    res = mongo.db.trips.delete_one({"_id": _id})
    if res.deleted_count == 0:
        return jsonify({"error": "Viagem não encontrada"}), 404
    return jsonify({"message": "Viagem removida"}), 200

# ---------------------------------------------------------------------
# Index / root
# ---------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    return jsonify({"message": "API PF-Zambom funcionando"}), 200

# ---------------------------------------------------------------------
# Inicialização: cria índices
# ---------------------------------------------------------------------
if __name__ == "__main__":
    try:
        mongo.db.investors.create_index([("created_at", -1)])
        mongo.db.trips.create_index([("created_at", -1)])
    except Exception as e:
        app.logger.warning("Falha ao criar índices iniciais: %s", e)

    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() in ("1", "true", "yes")
    app.run(host="0.0.0.0", port=port, debug=debug)
