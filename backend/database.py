import json
import base64
import hashlib
import os
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path


DATABASE_PATH = Path(
    os.environ.get("FORENSICAI_DB_PATH", "forensicai.sqlite3")
)
class PostgresConnection:
    def __init__(self, connection):
        self.connection = connection
        import psycopg

        self.integrity_error = psycopg.IntegrityError

    def execute(self, query, parameters=()):
        query = query.replace(
            "email = ? COLLATE NOCASE",
            "LOWER(email) = LOWER(?)"
        )
        query = query.replace("datetime('now')", "CURRENT_TIMESTAMP::text")
        query = query.replace("?", "%s")
        try:
            return self.connection.execute(query, parameters)
        except self.integrity_error as error:
            raise sqlite3.IntegrityError(str(error)) from error

    def executemany(self, query, parameters):
        query = query.replace("?", "%s")
        try:
            return self.connection.cursor().executemany(query, parameters)
        except self.integrity_error as error:
            raise sqlite3.IntegrityError(str(error)) from error

    def commit(self):
        self.connection.commit()

    def rollback(self):
        self.connection.rollback()

    def close(self):
        self.connection.close()


@contextmanager
def connect(database_path=None):
    use_postgres = (
        database_path is None
        and os.environ.get("FORENSAI_DATABASE_BACKEND", "").lower()
        == "postgres"
    )
    if use_postgres:
        database_url = os.environ.get("DATABASE_URL", "").strip()
        if not database_url:
            raise RuntimeError(
                "FORENSAI_DATABASE_BACKEND=postgres requires DATABASE_URL."
            )
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as error:
            raise RuntimeError(
                "PostgreSQL support requires the psycopg package."
            ) from error
        raw_connection = psycopg.connect(
            database_url,
            row_factory=dict_row,
            connect_timeout=10
        )
        connection = PostgresConnection(raw_connection)
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return

    path = Path(database_path or DATABASE_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database(database_path=None):
    if (
        database_path is None
        and os.environ.get("FORENSAI_DATABASE_BACKEND", "").lower()
        == "postgres"
    ):
        _initialize_postgres_database()
        return

    with connect(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'investigator')),
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                token_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                expires_at INTEGER NOT NULL,
                revoked_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS documents (
                document_id TEXT PRIMARY KEY,
                source_filename TEXT NOT NULL,
                file_type TEXT NOT NULL,
                file_size_bytes INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                uploaded_at TEXT NOT NULL,
                processing_status TEXT NOT NULL DEFAULT 'uploaded',
                classification_override TEXT,
                owner_id TEXT REFERENCES users(user_id) ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS investigations (
                investigation_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                status TEXT NOT NULL,
                dossier_json TEXT NOT NULL,
                owner_id TEXT REFERENCES users(user_id) ON DELETE SET NULL
            );
            CREATE TABLE IF NOT EXISTS investigation_documents (
                investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id)
                    ON DELETE CASCADE,
                document_id TEXT NOT NULL REFERENCES documents(document_id),
                PRIMARY KEY (investigation_id, document_id)
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                investigation_id TEXT,
                document_ids_json TEXT NOT NULL,
                details_json TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS finding_reviews (
                review_id INTEGER PRIMARY KEY AUTOINCREMENT,
                investigation_id TEXT NOT NULL REFERENCES investigations(investigation_id)
                    ON DELETE CASCADE,
                finding_id TEXT NOT NULL,
                status TEXT NOT NULL,
                reviewer TEXT,
                note TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL,
                UNIQUE (investigation_id, finding_id)
            );
            CREATE INDEX IF NOT EXISTS idx_investigation_documents_document
                ON investigation_documents(document_id);
            CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp
                ON audit_events(timestamp);
            """
        )
        _ensure_column(
            connection,
            "documents",
            "owner_id",
            "TEXT REFERENCES users(user_id) ON DELETE SET NULL"
        )
        _ensure_column(
            connection,
            "investigations",
            "owner_id",
            "TEXT REFERENCES users(user_id) ON DELETE SET NULL"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id)"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_investigations_owner "
            "ON investigations(owner_id)"
        )
        _bootstrap_admin(connection)


def _first_column_value(row):
    return next(iter(row.values())) if isinstance(row, dict) else row[0]


def _initialize_postgres_database():
    schema_statements = (
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'investigator')),
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
        """,
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower
        ON users (LOWER(email))
        """,
        """
        CREATE TABLE IF NOT EXISTS revoked_tokens (
            token_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            expires_at BIGINT NOT NULL,
            revoked_at TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS documents (
            document_id TEXT PRIMARY KEY,
            source_filename TEXT NOT NULL,
            file_type TEXT NOT NULL,
            file_size_bytes BIGINT NOT NULL,
            sha256 TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            processing_status TEXT NOT NULL DEFAULT 'uploaded',
            classification_override TEXT,
            owner_id TEXT REFERENCES users(user_id) ON DELETE SET NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS investigations (
            investigation_id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            status TEXT NOT NULL,
            dossier_json TEXT NOT NULL,
            owner_id TEXT REFERENCES users(user_id) ON DELETE SET NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS investigation_documents (
            investigation_id TEXT NOT NULL
                REFERENCES investigations(investigation_id) ON DELETE CASCADE,
            document_id TEXT NOT NULL REFERENCES documents(document_id),
            PRIMARY KEY (investigation_id, document_id)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS audit_events (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            investigation_id TEXT,
            document_ids_json TEXT NOT NULL,
            details_json TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS finding_reviews (
            review_id BIGSERIAL PRIMARY KEY,
            investigation_id TEXT NOT NULL
                REFERENCES investigations(investigation_id) ON DELETE CASCADE,
            finding_id TEXT NOT NULL,
            status TEXT NOT NULL,
            reviewer TEXT,
            note TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL,
            UNIQUE (investigation_id, finding_id)
        )
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_investigation_documents_document
        ON investigation_documents(document_id)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp
        ON audit_events(timestamp)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id)
        """,
        """
        CREATE INDEX IF NOT EXISTS idx_investigations_owner
        ON investigations(owner_id)
        """
    )

    with connect() as connection:
        for statement in schema_statements:
            connection.execute(statement)
        _bootstrap_admin(connection)


def _ensure_column(connection, table, column, declaration):
    columns = {
        row["name"] for row in connection.execute(
            f"PRAGMA table_info({table})"
        ).fetchall()
    }
    if column not in columns:
        connection.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {declaration}"
        )


def _bootstrap_admin(connection):
    email = os.environ.get("FORENSAI_ADMIN_EMAIL", "").strip().lower()
    password = os.environ.get("FORENSAI_ADMIN_PASSWORD", "")
    if not email or not password:
        return
    if len(password) < 12 or len(password) > 128 or len(email) > 254:
        raise ValueError(
            "Set FORENSAI_ADMIN_EMAIL and a FORENSAI_ADMIN_PASSWORD of "
            "12-128 characters to bootstrap an administrator."
        )

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("FORENSAI_ADMIN_EMAIL must be a valid email address.")

    existing = connection.execute(
        "SELECT user_id, role FROM users WHERE email = ?",
        (email,)
    ).fetchone()
    if existing is None:
        from uuid import uuid4
        from datetime import datetime, timezone

        user_id = str(uuid4())
        connection.execute(
            """
            INSERT INTO users (user_id, email, password_hash, role, created_at)
            VALUES (?, ?, ?, 'admin', ?)
            """,
            (
                user_id,
                email,
                _hash_password(password),
                datetime.now(timezone.utc).isoformat(timespec="seconds")
            )
        )
    elif existing["role"] != "admin":
        connection.execute(
            """
            UPDATE users
            SET role = 'admin', password_hash = ?, is_active = 1
            WHERE user_id = ?
            """,
            (_hash_password(password), existing["user_id"])
        )

    admin_id = (
        existing["user_id"] if existing is not None
        else connection.execute(
            "SELECT user_id FROM users WHERE email = ?",
            (email,)
        ).fetchone()["user_id"]
    )
    connection.execute(
        "UPDATE documents SET owner_id = ? WHERE owner_id IS NULL",
        (admin_id,)
    )
    connection.execute(
        "UPDATE investigations SET owner_id = ? WHERE owner_id IS NULL",
        (admin_id,)
    )


def _hash_password(password):
    salt = os.urandom(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**14,
        r=8,
        p=1,
        dklen=64
    )
    return "scrypt${}${}".format(
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii")
    )


def save_document(metadata, owner_id=None, database_path=None):
    initialize_database(database_path)
    with connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO documents (
                document_id, source_filename, file_type, file_size_bytes,
                sha256, uploaded_at, processing_status, owner_id
            ) VALUES (?, ?, ?, ?, ?, ?, 'uploaded', ?)
            """,
            (
                metadata["document_id"],
                metadata["source_filename"],
                metadata["file_type"],
                metadata["file_size_bytes"],
                metadata["sha256"],
                metadata["uploaded_at"],
                owner_id
            )
        )


def get_document(document_id, database_path=None):
    initialize_database(database_path)
    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT * FROM documents WHERE document_id = ?",
            (document_id,)
        ).fetchone()
    return dict(row) if row else None


def get_document_owners(document_ids, database_path=None):
    if not document_ids:
        return {}
    initialize_database(database_path)
    placeholders = ",".join("?" for _ in document_ids)
    with connect(database_path) as connection:
        rows = connection.execute(
            f"SELECT document_id, owner_id FROM documents "
            f"WHERE document_id IN ({placeholders})",
            tuple(document_ids)
        ).fetchall()
    return {row["document_id"]: row["owner_id"] for row in rows}


def delete_document(document_id, database_path=None):
    initialize_database(database_path)
    with connect(database_path) as connection:
        connection.execute(
            "DELETE FROM documents WHERE document_id = ?",
            (document_id,)
        )


def update_document_classification(document_id, category, database_path=None):
    initialize_database(database_path)
    with connect(database_path) as connection:
        cursor = connection.execute(
            """
            UPDATE documents SET classification_override = ?
            WHERE document_id = ?
            """,
            (category, document_id)
        )
    return cursor.rowcount == 1


def update_document_status(document_id, status, database_path=None):
    initialize_database(database_path)
    with connect(database_path) as connection:
        connection.execute(
            "UPDATE documents SET processing_status = ? WHERE document_id = ?",
            (status, document_id)
        )


def save_investigation(dossier, document_ids, owner_id=None, database_path=None):
    initialize_database(database_path)
    serialized = json.dumps(dossier, ensure_ascii=False)
    with connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO investigations (
                investigation_id, created_at, updated_at, status, dossier_json,
                owner_id
            ) VALUES (?, ?, ?, 'completed', ?, ?)
            """,
            (
                dossier["investigation_id"],
                dossier["generated_at"],
                dossier["generated_at"],
                serialized,
                owner_id
            )
        )
        connection.executemany(
            """
            INSERT INTO investigation_documents (investigation_id, document_id)
            VALUES (?, ?)
            """,
            [
                (dossier["investigation_id"], document_id)
                for document_id in document_ids
            ]
        )


def get_investigation(investigation_id, database_path=None):
    initialize_database(database_path)
    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT dossier_json FROM investigations WHERE investigation_id = ?",
            (investigation_id,)
        ).fetchone()
    if not row:
        return None
    return json.loads(row["dossier_json"])


def get_investigation_owner(investigation_id, database_path=None):
    initialize_database(database_path)
    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT owner_id FROM investigations WHERE investigation_id = ?",
            (investigation_id,)
        ).fetchone()
    return row["owner_id"] if row else None


def assign_investigation_owner(investigation_id, owner_id, database_path=None):
    initialize_database(database_path)
    with connect(database_path) as connection:
        connection.execute(
            """
            UPDATE investigations SET owner_id = ?
            WHERE investigation_id = ? AND owner_id IS NULL
            """,
            (owner_id, investigation_id)
        )


def create_user(user_id, email, password_hash, role="investigator", database_path=None):
    initialize_database(database_path)
    with connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO users (user_id, email, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, datetime('now'))
            """,
            (user_id, email, password_hash, role)
        )
    return get_user_by_id(user_id, database_path)


def get_user_by_email(email, database_path=None):
    initialize_database(database_path)
    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE email = ? COLLATE NOCASE",
            (email,)
        ).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id, database_path=None):
    initialize_database(database_path)
    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT * FROM users WHERE user_id = ?",
            (user_id,)
        ).fetchone()
    return dict(row) if row else None


def list_users(database_path=None):
    initialize_database(database_path)
    with connect(database_path) as connection:
        rows = connection.execute(
            "SELECT user_id, email, role, is_active, created_at FROM users "
            "ORDER BY created_at, email"
        ).fetchall()
    return [dict(row) for row in rows]


def count_active_admins(database_path=None):
    initialize_database(database_path)
    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = 1"
        ).fetchone()
    return _first_column_value(row)


def update_user(user_id, role=None, is_active=None, database_path=None):
    if role is None and is_active is None:
        return False
    assignments = []
    values = []
    if role is not None:
        assignments.append("role = ?")
        values.append(role)
    if is_active is not None:
        assignments.append("is_active = ?")
        values.append(int(is_active))
    values.append(user_id)
    initialize_database(database_path)
    with connect(database_path) as connection:
        cursor = connection.execute(
            f"UPDATE users SET {', '.join(assignments)} WHERE user_id = ?",
            values
        )
    return cursor.rowcount == 1


def is_token_revoked(token_id, database_path=None):
    initialize_database(database_path)
    with connect(database_path) as connection:
        row = connection.execute(
            "SELECT 1 FROM revoked_tokens WHERE token_id = ?",
            (token_id,)
        ).fetchone()
    return row is not None


def revoke_token(token_id, user_id, expires_at, revoked_at, database_path=None):
    initialize_database(database_path)
    with connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO revoked_tokens (token_id, user_id, expires_at, revoked_at)
            VALUES (?, ?, ?, ?)
            """,
            (token_id, user_id, expires_at, revoked_at)
        )


def list_investigations(limit=100, user_id=None, is_admin=True, database_path=None):
    initialize_database(database_path)
    with connect(database_path) as connection:
        owner_filter = "" if is_admin else "WHERE owner_id = ?"
        parameters = () if is_admin else (user_id,)
        rows = connection.execute(
            f"""
            SELECT investigation_id, created_at, updated_at, status, dossier_json
            FROM investigations
            {owner_filter}
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (*parameters, limit)
        ).fetchall()
    results = []
    for row in rows:
        dossier = json.loads(row["dossier_json"])
        results.append({
            "investigation_id": row["investigation_id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "status": row["status"],
            "document_count": dossier["document_overview"]["document_count"],
            "finding_count": dossier["contextual_analysis"]["finding_count"],
            "documents": dossier["document_overview"]["documents"]
        })
    return results


def get_dashboard_summary(user_id=None, is_admin=True, database_path=None):
    initialize_database(database_path)
    with connect(database_path) as connection:
        owner_filter = "" if is_admin else "WHERE owner_id = ?"
        parameters = () if is_admin else (user_id,)
        investigation_rows = connection.execute(
            f"""
            SELECT investigation_id, status, dossier_json
            FROM investigations
            {owner_filter}
            """,
            parameters
        ).fetchall()
        reviewed_rows = connection.execute(
            f"""
            SELECT investigation_id, finding_id, status
            FROM finding_reviews
            WHERE investigation_id IN (
                SELECT investigation_id FROM investigations
                {owner_filter}
            )
            """,
            parameters
        ).fetchall()
        analyzed_count_row = connection.execute(
            f"""
            SELECT COUNT(DISTINCT document_id)
            FROM investigation_documents
            JOIN documents USING (document_id)
            WHERE documents.processing_status = 'completed'
            {"AND documents.owner_id = ?" if not is_admin else ""}
            """,
            (() if is_admin else (user_id,))
        ).fetchone()
        analyzed_document_count = _first_column_value(analyzed_count_row)

    review_statuses = {
        (row["investigation_id"], row["finding_id"]): row["status"]
        for row in reviewed_rows
    }
    documents_requiring_review = set()
    flagged_findings = 0

    for row in investigation_rows:
        dossier = json.loads(row["dossier_json"])
        findings = dossier.get("contextual_analysis", {}).get(
            "findings", []
        )
        for finding in findings:
            status = review_statuses.get(
                (row["investigation_id"], finding["finding_id"])
            )
            if status not in {
                "verified_by_investigator",
                "dismissed_by_investigator"
            }:
                documents_requiring_review.update(
                    evidence.get("document_id")
                    for evidence in finding.get("evidence", [])
                    if evidence.get("document_id")
                )
            if finding.get("status") in {
                "detected_inconsistency",
                "screening_indicator"
            }:
                flagged_findings += 1

    return {
        "total_investigations": len(investigation_rows),
        "total_documents_analyzed": analyzed_document_count,
        "documents_requiring_review": len(documents_requiring_review),
        "potential_anomalies": flagged_findings,
        "completed_investigations": sum(
            row["status"] == "completed" for row in investigation_rows
        )
    }


def save_finding_review(
    investigation_id,
    finding_id,
    status,
    reviewer,
    note,
    updated_at,
    database_path=None
):
    initialize_database(database_path)
    with connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO finding_reviews (
                investigation_id, finding_id, status, reviewer, note, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(investigation_id, finding_id) DO UPDATE SET
                status = excluded.status,
                reviewer = excluded.reviewer,
                note = excluded.note,
                updated_at = excluded.updated_at
            """,
            (
                investigation_id,
                finding_id,
                status,
                reviewer,
                note,
                updated_at
            )
        )


def get_finding_reviews(investigation_id, database_path=None):
    initialize_database(database_path)
    with connect(database_path) as connection:
        rows = connection.execute(
            """
            SELECT finding_id, status, reviewer, note, updated_at
            FROM finding_reviews
            WHERE investigation_id = ?
            ORDER BY updated_at DESC
            """,
            (investigation_id,)
        ).fetchall()
    return [dict(row) for row in rows]


def save_audit_event(event, database_path=None):
    initialize_database(database_path)
    with connect(database_path) as connection:
        connection.execute(
            """
            INSERT INTO audit_events (
                event_id, timestamp, event_type, investigation_id,
                document_ids_json, details_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event["event_id"],
                event["timestamp"],
                event["event_type"],
                event.get("investigation_id"),
                json.dumps(event["document_ids"]),
                json.dumps(event["details"], ensure_ascii=False)
            )
        )


def list_audit_events(limit=500, user_id=None, is_admin=True, database_path=None):
    initialize_database(database_path)
    with connect(database_path) as connection:
        rows = connection.execute(
            """
            SELECT event_id, timestamp, event_type, investigation_id,
                   document_ids_json, details_json
            FROM audit_events
            ORDER BY timestamp DESC, rowid DESC
            LIMIT ?
            """,
            (limit,)
        ).fetchall()
    events = [
        {
            "event_id": row["event_id"],
            "timestamp": row["timestamp"],
            "event_type": row["event_type"],
            "investigation_id": row["investigation_id"],
            "document_ids": json.loads(row["document_ids_json"]),
            "details": json.loads(row["details_json"])
        }
        for row in rows
    ]
    if is_admin:
        return events
    filtered = []
    for event in events:
        if event["investigation_id"]:
            if get_investigation_owner(
                event["investigation_id"], database_path
            ) == user_id:
                filtered.append(event)
            continue
        owners = get_document_owners(event["document_ids"], database_path)
        if any(owner == user_id for owner in owners.values()):
            filtered.append(event)
    return filtered
