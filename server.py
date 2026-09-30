"""Local prototype API for unsigned demo records; field-record signing is disabled."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import mimetypes
import os
import sqlite3
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get("FIELDTEST_DATA_DIR", ROOT / "data")).expanduser().resolve()
IMAGES = DATA / "images"
DB_PATH = DATA / "fieldtest.sqlite3"
KEY_PATH = DATA / "signing-key.pem"
MAX_IMAGE_BYTES = 15 * 1024 * 1024
PORT = int(os.environ.get("PORT", os.environ.get("FIELDTEST_PORT", "4173")))
HOST = os.environ.get("FIELDTEST_HOST", "127.0.0.1")
SECURE_COOKIES = os.environ.get("FIELDTEST_SECURE_COOKIES", "false").strip().lower() in {"1", "true", "yes"}
BOOTSTRAP_SUPERVISOR_ID = "QA-SUP"
BOOTSTRAP_SUPERVISOR_PASSWORD = "ABC@123456"
DEMO_OPERATOR_ID = "DEMO-001"
DEMO_OPERATOR_PASSWORD = "Fieldtest@2026"
DATA.mkdir(parents=True, exist_ok=True)
IMAGES.mkdir(parents=True, exist_ok=True)


def get_signing_key() -> Ed25519PrivateKey:
    if KEY_PATH.exists():
        return serialization.load_pem_private_key(KEY_PATH.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    KEY_PATH.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return key


SIGNING_KEY = get_signing_key()
PUBLIC_KEY = SIGNING_KEY.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
KEY_ID = hashlib.sha256(PUBLIC_KEY).hexdigest()[:16]


def canonical_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def connect() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH)
    db.execute("CREATE TABLE IF NOT EXISTS records (id TEXT PRIMARY KEY, data TEXT NOT NULL)")
    db.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, operator_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL, role TEXT NOT NULL, salt BLOB NOT NULL, password_hash BLOB NOT NULL, active INTEGER NOT NULL DEFAULT 1)")
    db.execute("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at TEXT NOT NULL)")
    session_columns = {row[1] for row in db.execute("PRAGMA table_info(sessions)")}
    if "user_id" not in session_columns:
        legacy_columns = {"token_hash", "operator_id", "expires_at"}
        if not legacy_columns.issubset(session_columns):
            db.close()
            raise sqlite3.DatabaseError("Unsupported sessions table schema")
        try:
            with db:
                db.execute("BEGIN IMMEDIATE")
                legacy_sessions = db.execute("SELECT token_hash,operator_id,expires_at FROM sessions").fetchall()
                db.execute("ALTER TABLE sessions RENAME TO sessions_legacy")
                db.execute("CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires_at TEXT NOT NULL)")
                for token_hash, operator_id, expires_at in legacy_sessions:
                    user = db.execute("SELECT id FROM users WHERE operator_id=?", (operator_id,)).fetchone()
                    if not user:
                        continue
                    try:
                        normalized_expiry = datetime.fromtimestamp(float(expires_at), timezone.utc).isoformat()
                    except (TypeError, ValueError, OverflowError, OSError):
                        continue
                    db.execute(
                        "INSERT OR IGNORE INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",
                        (token_hash, user[0], normalized_expiry),
                    )
                db.execute("DROP TABLE sessions_legacy")
        except Exception:
            db.close()
            raise
    return db


def password_digest(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)


def public_user(row: tuple) -> dict:
    return {"id": row[0], "operatorId": row[1], "name": row[2], "role": row[3]}


def bootstrap_supervisor() -> None:
    password = BOOTSTRAP_SUPERVISOR_PASSWORD
    if not 10 <= len(password) <= 256:
        raise SystemExit("Bootstrap supervisor password must be 10 to 256 characters")
    salt = os.urandom(16)
    db = connect()
    try:
        with db:
            if not db.execute("SELECT 1 FROM users WHERE operator_id=?", (BOOTSTRAP_SUPERVISOR_ID,)).fetchone():
                db.execute(
                    "INSERT INTO users(operator_id,name,role,salt,password_hash) VALUES(?,?,?,?,?)",
                    (BOOTSTRAP_SUPERVISOR_ID, "QA Supervisor", "supervisor", salt, password_digest(password, salt)),
                )
    finally:
        db.close()


def bootstrap_demo_operator() -> None:
    salt = os.urandom(16)
    db = connect()
    try:
        with db:
            db.execute(
                "INSERT INTO users(operator_id,name,role,salt,password_hash,active) VALUES(?,?,?,?,?,1) "
                "ON CONFLICT(operator_id) DO UPDATE SET name=excluded.name,role=excluded.role,salt=excluded.salt,password_hash=excluded.password_hash,active=1",
                (DEMO_OPERATOR_ID, "Demo Operator", "field-officer", salt, password_digest(DEMO_OPERATOR_PASSWORD, salt)),
            )
    finally:
        db.close()


class Handler(BaseHTTPRequestHandler):
    server_version = "FieldtestPrototype/1.0"

    def log_message(self, fmt: str, *args) -> None:
        print(f"{self.log_date_time_string()} {fmt % args}")

    def send_json(self, value: object, status: int = 200, headers: dict[str, str] | None = None) -> None:
        body = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, header_value in (headers or {}).items():
            self.send_header(name, header_value)
        self.end_headers()
        self.wfile.write(body)

    def request_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 16_384:
            raise ValueError("Invalid request size")
        value = json.loads(self.rfile.read(length))
        if not isinstance(value, dict):
            raise ValueError("Invalid request")
        return value

    def current_user(self) -> dict | None:
        try:
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            token = cookie["fieldtest_session"].value
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            with connect() as db:
                row = db.execute("SELECT users.id,users.operator_id,users.name,users.role FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>? AND users.active=1", (token_hash, datetime.now(timezone.utc).isoformat())).fetchone()
            return public_user(row) if row else None
        except (KeyError, ValueError):
            return None

    def require_user(self, roles: set[str] | None = None) -> dict | None:
        user = self.current_user()
        if not user:
            self.send_json({"error": "Sign in is required"}, 401)
            return None
        if roles and user["role"] not in roles:
            self.send_json({"error": "Your account role cannot perform this action"}, 403)
            return None
        return user

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            return self.send_json({"ok": True, "recordMode": "demo-only", "fieldSigningEnabled": False, "integrityCheck": "SHA-256"})
        if parsed.path == "/api/auth/status":
            with connect() as db:
                count = db.execute("SELECT COUNT(*) FROM users WHERE active=1").fetchone()[0]
            return self.send_json({"setupRequired": count == 0})
        if parsed.path == "/api/auth/me":
            user = self.current_user()
            if not user:
                return self.send_json({"error": "Sign in is required"}, 401)
            return self.send_json({"user": user})
        if parsed.path == "/api/public-key":
            return self.send_json({"algorithm": "Ed25519", "keyId": KEY_ID, "publicKey": base64.b64encode(PUBLIC_KEY).decode("ascii")})
        if parsed.path == "/api/records":
            user = self.require_user()
            if not user:
                return
            query = parse_qs(parsed.query).get("q", [""])[0].casefold()
            with connect() as db:
                rows = db.execute("SELECT data FROM records ORDER BY rowid DESC").fetchall()
            records = [json.loads(row[0]) for row in rows]
            if user["role"] == "field-officer":
                records = [r for r in records if r.get("operator") == user["operatorId"]]
            if query:
                records = [r for r in records if query in json.dumps(r, ensure_ascii=False).casefold()]
            return self.send_json({"records": records, "count": len(rows), "keyId": KEY_ID})
        if parsed.path == "/api/export":
            user = self.require_user()
            if not user:
                return
            with connect() as db:
                rows = db.execute("SELECT data FROM records ORDER BY rowid DESC").fetchall()
            records = [json.loads(row[0]) for row in rows]
            if user["role"] == "field-officer":
                records = [r for r in records if r.get("operator") == user["operatorId"]]
            return self.send_json(records)
        if parsed.path == "/api/operators":
            user = self.require_user({"supervisor"})
            if not user:
                return
            with connect() as db:
                rows = db.execute("SELECT id,operator_id,name,role,active FROM users ORDER BY operator_id").fetchall()
            return self.send_json({"operators": [{"id": r[0], "operatorId": r[1], "name": r[2], "role": r[3], "active": bool(r[4])} for r in rows]})
        if parsed.path.startswith("/api/records/") and not parsed.path.endswith("/verify"):
            user = self.require_user()
            if not user:
                return
            record_id = unquote(parsed.path[len("/api/records/"):].strip("/"))
            try:
                record_id = str(uuid.UUID(record_id))
            except ValueError:
                return self.send_json({"error": "Record not found"}, 404)
            with connect() as db:
                row = db.execute("SELECT data FROM records WHERE id=?", (record_id,)).fetchone()
            if not row:
                return self.send_json({"error": "Record not found"}, 404)
            record = json.loads(row[0])
            if user["role"] == "field-officer" and record.get("operator") != user["operatorId"]:
                return self.send_json({"error": "Record not found"}, 404)
            return self.send_json(record)
        if parsed.path.startswith("/api/records/") and parsed.path.endswith("/verify"):
            user = self.require_user()
            if not user:
                return
            record_id = unquote(parsed.path[len("/api/records/"):-len("/verify")].strip("/"))
            with connect() as db:
                row = db.execute("SELECT data FROM records WHERE id=?", (record_id,)).fetchone()
            if not row:
                return self.send_json({"error": "Record not found"}, 404)
            record = json.loads(row[0])
            if user["role"] == "field-officer" and record.get("operator") != user["operatorId"]:
                return self.send_json({"error": "Record not found"}, 404)
            demo_only = record.get("recordType") == "training-demo" and not record.get("signature")
            stored_record_hash = record.get("recordSha256")
            hash_payload = {k: v for k, v in record.items() if k != "recordSha256"}
            record_hash_ok = bool(stored_record_hash) and hashlib.sha256(canonical_bytes(hash_payload)).hexdigest() == stored_record_hash
            try:
                SIGNING_KEY.public_key().verify(base64.b64decode(record["signature"]), canonical_bytes(record["signedPayload"]))
                signature_ok = True
            except Exception:
                signature_ok = False
            try:
                image_path = IMAGES / f"{record_id}.bin"
                actual_hash = hashlib.sha256(image_path.read_bytes()).hexdigest()
                image_ok = actual_hash == record["imageSha256"]
            except Exception:
                image_ok = False
                actual_hash = None
            return self.send_json({"valid": signature_ok and image_ok, "demoOnly": demo_only, "signatureValid": signature_ok, "imageHashValid": image_ok, "recordHashValid": record_hash_ok, "recordSha256": stored_record_hash, "imageSha256": actual_hash, "keyId": record.get("keyId")})
        if parsed.path.startswith("/api/images/"):
            user = self.require_user()
            if not user:
                return
            record_id = unquote(parsed.path[len("/api/images/"):].strip("/"))
            try:
                record_id = str(uuid.UUID(record_id))
            except ValueError:
                return self.send_json({"error": "Record not found"}, 404)
            with connect() as db:
                row = db.execute("SELECT data FROM records WHERE id=?", (record_id,)).fetchone()
            image_path = IMAGES / f"{record_id}.bin"
            if not row or not image_path.exists():
                return self.send_json({"error": "Image not found"}, 404)
            record = json.loads(row[0])
            if user["role"] == "field-officer" and record.get("operator") != user["operatorId"]:
                return self.send_json({"error": "Image not found"}, 404)
            body = image_path.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", record.get("imageContentType", "application/octet-stream"))
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/" or parsed.path == "/fieldtest-companion.html":
            return self.send_file(ROOT / "fieldtest-companion.html")
        if parsed.path in ("/sw.js", "/manifest.webmanifest", "/icon.svg", "/demo-sample.png"):
            return self.send_file(ROOT / parsed.path.lstrip("/"))
        return self.send_json({"error": "Not found"}, 404)

    def send_file(self, path: Path) -> None:
        body = path.read_bytes()
        self.send_response(200)
        content_type = "application/manifest+json" if path.suffix == ".webmanifest" else mimetypes.guess_type(path.name)[0]
        self.send_header("Content-Type", content_type or "application/octet-stream")
        if path.name == "sw.js":
            self.send_header("Service-Worker-Allowed", "/")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path in {"/api/auth/setup", "/api/auth/login", "/api/auth/logout", "/api/operators"}:
            if path == "/api/auth/logout":
                cookie = SimpleCookie(self.headers.get("Cookie", ""))
                token = cookie["fieldtest_session"].value if "fieldtest_session" in cookie else ""
                if token:
                    with connect() as db:
                        db.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
                cookie = "fieldtest_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
                if SECURE_COOKIES:
                    cookie += "; Secure"
                return self.send_json({"ok": True}, headers={"Set-Cookie": cookie})
            try:
                body = self.request_json()
            except (ValueError, json.JSONDecodeError):
                return self.send_json({"error": "Invalid request"}, 400)
            if path == "/api/auth/setup":
                operator_id = str(body.get("operatorId", "")).strip()
                name = str(body.get("name", "")).strip()
                password = str(body.get("password", ""))
                if not operator_id or not name or len(password) < 10 or len(password) > 256:
                    return self.send_json({"error": "Enter a name, operator ID, and password of at least 10 characters"}, 400)
                salt = os.urandom(16)
                try:
                    with connect() as db:
                        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
                            return self.send_json({"error": "Initial setup is already complete"}, 409)
                        cursor = db.execute("INSERT INTO users(operator_id,name,role,salt,password_hash) VALUES(?,?,?,?,?)", (operator_id, name, "supervisor", salt, password_digest(password, salt)))
                        user_id = cursor.lastrowid
                except sqlite3.IntegrityError:
                    return self.send_json({"error": "That operator ID is already in use"}, 409)
                user = {"id": user_id, "operatorId": operator_id, "name": name, "role": "supervisor"}
            elif path == "/api/auth/login":
                operator_id = str(body.get("operatorId", "")).strip()
                password = str(body.get("password", ""))
                with connect() as db:
                    row = db.execute("SELECT id,operator_id,name,role,salt,password_hash FROM users WHERE operator_id=? AND active=1", (operator_id,)).fetchone()
                if not row or not hmac.compare_digest(password_digest(password, row[4]), row[5]):
                    return self.send_json({"error": "Operator ID or password is incorrect"}, 401)
                user = public_user(row)
            else:
                supervisor = self.require_user({"supervisor"})
                if not supervisor:
                    return
                operator_id = str(body.get("operatorId", "")).strip()
                name = str(body.get("name", "")).strip()
                password = str(body.get("password", ""))
                if not operator_id or not name or len(password) < 10 or len(password) > 256:
                    return self.send_json({"error": "Enter a name, operator ID, and password of at least 10 characters"}, 400)
                salt = os.urandom(16)
                try:
                    with connect() as db:
                        cursor = db.execute("INSERT INTO users(operator_id,name,role,salt,password_hash) VALUES(?,?,?,?,?)", (operator_id, name, "field-officer", salt, password_digest(password, salt)))
                        user_id = cursor.lastrowid
                except sqlite3.IntegrityError:
                    return self.send_json({"error": "That operator ID is already in use"}, 409)
                return self.send_json({"operator": {"id": user_id, "operatorId": operator_id, "name": name, "role": "field-officer"}}, 201)

            token = secrets.token_urlsafe(32)
            expires = datetime.now(timezone.utc) + timedelta(hours=8)
            with connect() as db:
                db.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), user["id"], expires.isoformat()))
            cookie = f"fieldtest_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800"
            if SECURE_COOKIES:
                cookie += "; Secure"
            return self.send_json({"user": user}, headers={"Set-Cookie": cookie})

        if path != "/api/records":
            return self.send_json({"error": "Not found"}, 404)
        user = self.require_user({"field-officer"})
        if not user:
            return
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_IMAGE_BYTES + 256_000:
            return self.send_json({"error": "Image is missing or exceeds the 15 MB limit"}, 413)
        content_type = self.headers.get("Content-Type", "")
        raw = self.rfile.read(length)
        message = BytesParser(policy=policy.default).parsebytes(
            f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + raw
        )
        fields = {}
        for part in message.iter_parts():
            name = part.get_param("name", header="content-disposition")
            if name == "metadata":
                fields[name] = part.get_content()
            elif name == "image":
                fields[name] = part.get_payload(decode=True)
                fields["image_type"] = part.get_content_type()
        if not fields.get("image") or not fields.get("metadata"):
            return self.send_json({"error": "Both image and metadata are required"}, 400)
        try:
            client = json.loads(fields["metadata"])
            record_id = str(uuid.UUID(client["id"]))
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            return self.send_json({"error": "Invalid record metadata"}, 400)

        try:
            captured_at = datetime.fromisoformat(str(client["capturedAt"]).replace("Z", "+00:00"))
            if captured_at.tzinfo is None or captured_at.utcoffset() is None:
                raise ValueError
            analyzed_at = datetime.fromisoformat(str(client.get("analyzedAt", client["capturedAt"])).replace("Z", "+00:00"))
            saved_at = datetime.fromisoformat(str(client.get("savedAt", datetime.now(timezone.utc).isoformat())).replace("Z", "+00:00"))
            if analyzed_at.tzinfo is None or analyzed_at.utcoffset() is None or saved_at.tzinfo is None or saved_at.utcoffset() is None:
                raise ValueError
            outcome = client["outcome"]
            rule_fit_score = int(client.get("ruleFitScore", client.get("confidence")))
            location = client.get("location")
            operator = str(client.get("operator", "")).strip()
            if operator != user["operatorId"]:
                return self.send_json({"error": "Record operator must match the signed-in field officer"}, 403)
            if not operator or len(operator) > 80 or outcome not in {"positive", "negative", "inconclusive"} or not 0 <= rule_fit_score <= 100:
                raise ValueError
            if not isinstance(client.get("assessment", {}), dict):
                raise ValueError
            assessment = client.get("assessment")
            record_type = client.get("recordType", "field-test")
            if record_type not in {"field-test", "training-demo"}:
                raise ValueError
            if record_type == "training-demo":
                if client.get("trainingMode") is not True or not isinstance(assessment, dict) or assessment.get("profileStatus") != "unvalidated-demo":
                    return self.send_json({"error": "Demo records must be explicitly marked unvalidated and training-only"}, 400)
                if not isinstance(client.get("demonstrationSample"), bool):
                    raise ValueError
                if location is not None:
                    if not isinstance(location, dict):
                        raise ValueError
                    latitude, longitude = float(location["latitude"]), float(location["longitude"])
                    accuracy = float(location["accuracyMeters"])
                    location_time = datetime.fromisoformat(str(location["capturedAt"]).replace("Z", "+00:00"))
                    if not (-90 <= latitude <= 90 and -180 <= longitude <= 180) or not math.isfinite(accuracy) or not 0 <= accuracy <= 100_000 or location_time.tzinfo is None or location_time.utcoffset() is None:
                        raise ValueError
            else:
                return self.send_json({"error": "Field-record signing is disabled until a qualified, kit-specific validation approval is installed and verified by this server"}, 403)
        except (ValueError, TypeError, KeyError, OverflowError):
            return self.send_json({"error": "Invalid timestamp, location, outcome, or rule-fit score"}, 400)

        image = fields["image"]
        image_type = fields.get("image_type", "")
        if image_type not in {"image/jpeg", "image/png", "image/webp"}:
            return self.send_json({"error": "Use a JPEG, PNG, or WebP image"}, 415)
        if len(image) > MAX_IMAGE_BYTES:
            return self.send_json({"error": "Image exceeds the 15 MB limit"}, 413)
        image_signatures = {"image/jpeg": image.startswith(b"\xff\xd8\xff"), "image/png": image.startswith(b"\x89PNG\r\n\x1a\n"), "image/webp": image.startswith(b"RIFF") and image[8:12] == b"WEBP"}
        if not image_signatures[image_type]:
            return self.send_json({"error": "Uploaded data does not match its image format"}, 415)
        image_hash = hashlib.sha256(image).hexdigest()
        if image_hash != client.get("imageSha256"):
            return self.send_json({"error": "Image hash did not match the captured image"}, 400)
        record_data = {
            "schema": "fieldtest-record/v1",
            "recordType": "training-demo",
            "trainingMode": True,
            "demonstrationSample": client.get("demonstrationSample", False),
            "recordStatus": "DEMO / TRAINING · NOT EVIDENCE",
            "signatureStatus": "NOT SIGNED · DEMO ONLY",
            "id": record_id,
            "capturedAt": captured_at.isoformat(),
            "serverReceivedAt": datetime.now(timezone.utc).isoformat(),
            "operator": operator,
            "kit": str(client.get("kit", "UNSPECIFIED"))[:120],
            "outcome": outcome,
            "ruleFitScore": rule_fit_score,
            "location": client.get("location"),
            "imageSha256": image_hash,
            "imageContentType": image_type,
            "assessment": client.get("assessment", {}),
            "auditTrail": [
                {"event": "created", "at": captured_at.isoformat()},
                {"event": "analyzed", "at": analyzed_at.isoformat()},
                {"event": "saved", "at": saved_at.isoformat()},
                {"event": "synced", "at": datetime.now(timezone.utc).isoformat()},
            ],
        }
        record_data["recordSha256"] = hashlib.sha256(canonical_bytes(record_data)).hexdigest()
        record = record_data
        image_path = IMAGES / f"{record_id}.bin"
        try:
            with image_path.open("xb") as image_file:
                image_file.write(image)
        except FileExistsError:
            return self.send_json({"error": "This record ID already exists"}, 409)
        try:
            with connect() as db:
                db.execute("INSERT INTO records(id,data) VALUES(?,?)", (record_id, json.dumps(record, ensure_ascii=False)))
        except sqlite3.IntegrityError:
            image_path.unlink(missing_ok=True)
            return self.send_json({"error": "This record ID already exists"}, 409)
        except Exception:
            image_path.unlink(missing_ok=True)
            raise
        return self.send_json({"record": record, "verification": f"/api/records/{record_id}/verify"}, 201)


if __name__ == "__main__":
    bootstrap_supervisor()
    bootstrap_demo_operator()
    print(f"Fieldtest prototype listening on {HOST}:{PORT}")
    print("Demo-only mode; field-evidence signing is disabled")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
