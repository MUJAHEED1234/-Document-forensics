import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from contextlib import asynccontextmanager
from uuid import uuid4
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.testclient import TestClient
import pymupdf
from PIL import Image

os.environ.setdefault(
    "FORENSAI_JWT_SECRET",
    "test-only-jwt-secret-that-is-at-least-32-bytes-long"
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main

main.API_TOKEN = ""
os.environ.setdefault(
    "FORENSAI_JWT_SECRET",
    "test-only-jwt-secret-that-is-at-least-32-bytes-long"
)
os.environ["FORENSAI_ADMIN_EMAIL"] = "admin@example.test"
os.environ["FORENSAI_ADMIN_PASSWORD"] = "test-admin-password-123"


def login_admin(client):
    response = client.post(
        "/auth/login",
        json={
            "email": "admin@example.test",
            "password": "test-admin-password-123"
        }
    )
    if response.status_code != 200:
        raise AssertionError(f"Admin login failed: {response.text}")
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def admin_principal():
    return main.forensic_database.get_user_by_email("admin@example.test")

AUTH_HEADERS = {"Authorization": f"Bearer {main.API_TOKEN}"}


class InvestigationTests(unittest.TestCase):
    def legacy_shared_token_auth_test(self):
        with TestClient(main.app) as client:
            self.assertEqual(client.get("/health").status_code, 401)
            self.assertEqual(
                client.get(
                    "/health",
                    headers={"Authorization": "Bearer invalid-token"}
                ).status_code,
                401
            )
            response = client.get("/health", headers=AUTH_HEADERS)
            self.assertEqual(response.status_code, 200)
            with patch.object(main, "API_TOKEN", ""):
                unconfigured = client.get("/health", headers=AUTH_HEADERS)
            self.assertEqual(unconfigured.status_code, 503)
            with patch.dict(
                os.environ,
                {"FORENSAI_OCR_LANGUAGES": "en,xx"}
            ):
                unsupported_language = client.get(
                    "/health",
                    headers=AUTH_HEADERS
                )
            self.assertEqual(unsupported_language.status_code, 503)

    def test_jwt_auth_registration_admin_roles_and_logout(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(
                main.forensic_database,
                "DATABASE_PATH",
                Path(temp_dir) / "forensicai.sqlite3"
            ):
                with TestClient(main.app) as client:
                    self.assertEqual(client.get("/health").status_code, 401)
                    invalid = client.get(
                        "/health",
                        headers={"Authorization": "Bearer invalid"}
                    )
                    self.assertEqual(invalid.status_code, 401)
                    shared_token = client.get(
                        "/health",
                        headers={
                            "Authorization": (
                                "Bearer test-only-random-token-replace-this-before-use"
                            )
                        }
                    )
                    self.assertEqual(shared_token.status_code, 401)
                    admin_headers = login_admin(client)
                    self.assertEqual(
                        client.get("/health", headers=admin_headers).status_code,
                        200
                    )
                    registration = client.post(
                        "/auth/register",
                        json={
                            "email": "new@example.test",
                            "password": "test-investigator-password"
                        }
                    )
                    self.assertEqual(registration.status_code, 200)
                    self.assertEqual(
                        registration.json()["user"]["role"],
                        "investigator"
                    )
                    stored_user = main.forensic_database.get_user_by_email(
                        "new@example.test"
                    )
                    self.assertNotEqual(
                        stored_user["password_hash"],
                        "test-investigator-password"
                    )
                    investigator_headers = {
                        "Authorization": (
                            "Bearer " + registration.json()["access_token"]
                        )
                    }
                    self.assertEqual(
                        client.get(
                            "/auth/admin/users",
                            headers=investigator_headers
                        ).status_code,
                        403
                    )
                    self.assertEqual(
                        client.get(
                            "/auth/admin/users",
                            headers=admin_headers
                        ).status_code,
                        200
                    )
                    investigator_id = registration.json()["user"]["user_id"]
                    promoted = client.patch(
                        f"/auth/admin/users/{investigator_id}",
                        json={"role": "admin"},
                        headers=admin_headers
                    )
                    self.assertEqual(promoted.status_code, 200)
                    self.assertEqual(promoted.json()["user"]["role"], "admin")
                    admin_id = main.forensic_database.get_user_by_email(
                        "admin@example.test"
                    )["user_id"]
                    last_admin_demotion = client.patch(
                        f"/auth/admin/users/{admin_id}",
                        json={"role": "investigator"},
                        headers=admin_headers
                    )
                    self.assertEqual(last_admin_demotion.status_code, 400)
                    disabled = client.patch(
                        f"/auth/admin/users/{investigator_id}",
                        json={"is_active": False},
                        headers=admin_headers
                    )
                    self.assertEqual(disabled.status_code, 200)
                    self.assertEqual(
                        client.get(
                            "/health",
                            headers=investigator_headers
                        ).status_code,
                        401
                    )
                    logout = client.post("/auth/logout", headers=admin_headers)
                    self.assertEqual(logout.status_code, 200)
                    self.assertEqual(
                        client.get("/health", headers=admin_headers).status_code,
                        401
                    )

    def test_existing_database_records_are_assigned_to_bootstrap_admin(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "legacy.sqlite3"
            document_id = str(uuid4())
            investigation_id = str(uuid4())
            with sqlite3.connect(database_path) as connection:
                    connection.executescript(
                        """
                        CREATE TABLE documents (
                            document_id TEXT PRIMARY KEY,
                            source_filename TEXT NOT NULL,
                            file_type TEXT NOT NULL,
                            file_size_bytes INTEGER NOT NULL,
                            sha256 TEXT NOT NULL,
                            uploaded_at TEXT NOT NULL,
                            processing_status TEXT NOT NULL DEFAULT 'uploaded',
                            classification_override TEXT
                        );
                        CREATE TABLE investigations (
                            investigation_id TEXT PRIMARY KEY,
                            created_at TEXT NOT NULL,
                            updated_at TEXT NOT NULL,
                            status TEXT NOT NULL,
                            dossier_json TEXT NOT NULL
                        );
                        """
                    )
                    connection.execute(
                        "INSERT INTO documents VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            document_id,
                            "legacy.pdf",
                            "pdf",
                            10,
                            "a" * 64,
                            "2025-01-01T00:00:00Z",
                            "completed",
                            None
                        )
                    )
                    connection.execute(
                        "INSERT INTO investigations VALUES (?, ?, ?, ?, ?)",
                        (
                            investigation_id,
                            "2025-01-01T00:00:00Z",
                            "2025-01-01T00:00:00Z",
                            "completed",
                            json.dumps({})
                        )
                    )
            connection.close()

            main.forensic_database.initialize_database(database_path)
            admin = main.forensic_database.get_user_by_email(
                    "admin@example.test",
                    database_path
            )
            self.assertEqual(
                    main.forensic_database.get_document(
                        document_id,
                        database_path
                    )["owner_id"],
                    admin["user_id"]
            )
            self.assertEqual(
                    main.forensic_database.get_investigation_owner(
                        investigation_id,
                        database_path
                    ),
                    admin["user_id"]
            )

    def test_partial_bootstrap_config_does_not_block_registration(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with (
                    patch.object(
                        main.forensic_database,
                        "DATABASE_PATH",
                        Path(temp_dir) / "forensicai.sqlite3"
                    ),
                    patch.dict(
                        os.environ,
                        {
                            "FORENSAI_JWT_SECRET":
                                "test-only-jwt-secret-that-is-at-least-32-bytes-long",
                            "FORENSAI_ADMIN_EMAIL": "admin@example.test",
                            "FORENSAI_ADMIN_PASSWORD": ""
                        }
                    )
            ):
                    with TestClient(main.app) as client:
                        response = client.post(
                            "/auth/register",
                            json={
                                "email": "registered@example.test",
                                "password": "valid-registration-password"
                            }
                        )
            self.assertEqual(response.status_code, 200, response.text)

    def test_jwt_secret_requires_minimum_utf8_byte_length(self):
        with patch.dict(os.environ, {"FORENSAI_JWT_SECRET": ""}):
            with self.assertRaises(HTTPException) as missing:
                main._jwt_secret()
        self.assertIn("32 UTF-8 bytes", missing.exception.detail)

        with patch.dict(os.environ, {"FORENSAI_JWT_SECRET": "x" * 31}):
            with self.assertRaises(HTTPException):
                main._jwt_secret()

        with patch.dict(os.environ, {"FORENSAI_JWT_SECRET": "é" * 16}):
            self.assertEqual(len(main._jwt_secret()), 32)

    def test_startup_rejects_missing_jwt_secret_with_clear_message(self):
        with patch.dict(os.environ, {"FORENSAI_JWT_SECRET": ""}):
            with self.assertRaisesRegex(
                RuntimeError,
                "FORENSAI_JWT_SECRET.*32 UTF-8 bytes"
            ):
                with TestClient(main.app):
                    pass

    def test_local_dotenv_loader_reads_root_env_without_logging_secret(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            backend = root / "backend"
            backend.mkdir()
            generated_test_secret = "safe-test-value-" + "x" * 32
            (root / ".env").write_text(
                f"FORENSAI_JWT_SECRET={generated_test_secret}\n",
                encoding="utf-8"
            )
            (backend / ".env").write_text(
                "FORENSAI_JWT_SECRET=backend-fallback-secret\n",
                encoding="utf-8"
            )
            with patch.dict(os.environ, {}, clear=True):
                main.load_environment_files(root)
                self.assertEqual(
                    main._jwt_secret(),
                    generated_test_secret.encode("utf-8")
                )

    def test_bootstrap_promotes_matching_existing_account(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "forensicai.sqlite3"
            with patch.object(
                    main.forensic_database,
                    "DATABASE_PATH",
                    database_path
            ):
                    with patch.dict(
                        os.environ,
                        {
                            "FORENSAI_ADMIN_EMAIL": "",
                            "FORENSAI_ADMIN_PASSWORD": ""
                        }
                    ):
                        investigator = main.forensic_database.create_user(
                            str(uuid4()),
                            "admin@example.test",
                            main.hash_password("old-investigator-password"),
                            role="investigator"
                        )
                    self.assertEqual(investigator["role"], "investigator")
                    main.forensic_database.initialize_database()
                    bootstrapped = main.forensic_database.get_user_by_email(
                        "admin@example.test"
                    )
                    self.assertEqual(bootstrapped["role"], "admin")
                    self.assertTrue(main.verify_password(
                        "test-admin-password-123",
                        bootstrapped["password_hash"]
                    ))

    def test_investigation_and_document_ownership_is_enforced(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with patch.object(
                    main.forensic_database,
                    "DATABASE_PATH",
                    root / "forensicai.sqlite3"
            ):
                    with TestClient(main.app) as client:
                        admin_headers = login_admin(client)
                        registered = client.post(
                            "/auth/register",
                            json={
                                "email": "owner@example.test",
                                "password": "investigator-password-123"
                            }
                        )
                        self.assertEqual(registered.status_code, 200)
                        investigator_headers = {
                            "Authorization": (
                                "Bearer " + registered.json()["access_token"]
                            )
                        }

                        admin = main.forensic_database.get_user_by_email(
                            "admin@example.test"
                        )
                        document_id = str(uuid4())
                        main.forensic_database.save_document(
                            {
                                "document_id": document_id,
                                "source_filename": "admin-only.pdf",
                                "file_type": "pdf",
                                "file_size_bytes": 100,
                                "sha256": "a" * 64,
                                "uploaded_at": "2025-01-01T00:00:00Z"
                            },
                            owner_id=admin["user_id"]
                        )
                        investigation_id = str(uuid4())
                        dossier = {
                            "investigation_id": investigation_id,
                            "generated_at": "2025-01-01T00:00:00Z",
                            "document_overview": {
                                "document_count": 0,
                                "documents": []
                            },
                            "contextual_analysis": {
                                "finding_count": 0,
                                "findings": []
                            }
                        }
                        main.forensic_database.save_investigation(
                            dossier,
                            [],
                            owner_id=admin["user_id"]
                        )

                        self.assertEqual(
                            client.get(
                                f"/documents/{document_id}",
                                headers=investigator_headers
                            ).status_code,
                            404
                        )
                        self.assertEqual(
                            client.post(
                                "/investigations",
                                json={"document_ids": [document_id]},
                                headers=investigator_headers
                            ).status_code,
                            404
                        )
                        self.assertEqual(
                            client.get(
                                f"/investigations/{investigation_id}",
                                headers=investigator_headers
                            ).status_code,
                            404
                        )
                        history = client.get(
                            "/investigations",
                            headers=investigator_headers
                        )
                        self.assertEqual(history.json()["investigations"], [])
                        self.assertEqual(
                            client.get(
                                "/dashboard/summary",
                                headers=investigator_headers
                            ).json()["total_investigations"],
                            0
                        )
                        self.assertEqual(
                            len(client.get(
                                "/investigations",
                                headers=admin_headers
                            ).json()["investigations"]),
                            1
                        )

    def test_api_upload_ocr_classification_history_and_evidence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            uploads = root / "uploads"
            reports = root / "reports"
            uploads.mkdir()
            reports.mkdir()

            pdf_buffer = io.BytesIO()
            pdf = pymupdf.open()
            page = pdf.new_page()
            page.insert_text((72, 72), "Applicant Name: Alice Example", fontsize=12)
            page.insert_text((72, 110), "Date of Birth: 01/01/1990", fontsize=12)
            page.insert_text((72, 148), "Mobile Number: 9000000000", fontsize=12)
            pdf.save(pdf_buffer)
            pdf.close()

            image_buffer = io.BytesIO()
            Image.new("RGB", (240, 120), "white").save(image_buffer, format="PNG")

            scanned_pdf = pymupdf.open()
            scanned_page = scanned_pdf.new_page(width=240, height=120)
            scanned_page.insert_image(
                pymupdf.Rect(0, 0, 240, 120),
                stream=image_buffer.getvalue()
            )
            scanned_pdf_buffer = io.BytesIO()
            scanned_pdf.save(scanned_pdf_buffer)
            scanned_pdf.close()

            class FakeOCRReader:
                def readtext(self, _image, detail=1, paragraph=False):
                    return [
                        (
                            [[10, 10], [200, 10], [200, 35], [10, 35]],
                            "Applicant Name: Bob Example",
                            0.96
                        ),
                        (
                            [[10, 45], [200, 45], [200, 70], [10, 70]],
                            "Date of Birth: 02/02/1990",
                            0.90
                        )
                    ]

            with (
                patch.object(main, "UPLOAD_DIR", uploads),
                patch.object(main, "REPORT_DIR", reports),
                patch.object(main, "AUDIT_LOG", root / "audit.jsonl"),
                patch.object(
                    main.forensic_database,
                    "DATABASE_PATH",
                    root / "forensicai.sqlite3"
                ),
                patch.object(main, "get_ocr_reader", return_value=FakeOCRReader())
            ):
                with TestClient(main.app) as client:
                    client.headers.update(login_admin(client))
                    invalid = client.post(
                        "/upload",
                        files={"file": ("bad.pdf", b"not a pdf", "application/pdf")}
                    )
                    self.assertEqual(invalid.status_code, 400)
                    with patch.object(main, "MAX_FILE_SIZE", 4):
                        oversized = client.post(
                            "/upload",
                            files={
                                "file": (
                                    "large.pdf",
                                    b"%PDF-1.4 payload",
                                    "application/pdf"
                                )
                            }
                        )
                    self.assertEqual(oversized.status_code, 413)

                    pdf_upload = client.post(
                        "/upload",
                        files={
                            "file": (
                                "application.pdf",
                                pdf_buffer.getvalue(),
                                "application/pdf"
                            )
                        }
                    )
                    self.assertEqual(pdf_upload.status_code, 200)
                    pdf_id = pdf_upload.json()["document_id"]
                    self.assertEqual(
                        client.get(f"/extract/{pdf_id}").status_code,
                        200
                    )
                    structure = client.get(
                        f"/document-structure/{pdf_id}"
                    )
                    self.assertEqual(structure.status_code, 200)
                    self.assertTrue(structure.json()["pages"][0]["blocks"])
                    self.assertEqual(
                        client.get(f"/metadata/{pdf_id}").status_code,
                        200
                    )
                    fingerprint = client.get(f"/fingerprint/{pdf_id}")
                    self.assertEqual(len(fingerprint.json()["hash"]), 64)
                    report = client.get(f"/report/{pdf_id}")
                    self.assertEqual(report.status_code, 200)
                    report_pdf = pymupdf.open(
                        stream=report.content,
                        filetype="pdf"
                    )
                    report_pages = [
                        page.get_text()
                        for page in report_pdf
                    ]
                    self.assertTrue(
                        any("application.pdf" in text for text in report_pages)
                    )
                    self.assertTrue(
                        any(
                            "5. DIGITAL FORENSIC STATISTICS" in text
                            and "Unique Fonts" in text
                            for text in report_pages
                        )
                    )
                    classification = client.get(
                        f"/classification/{pdf_id}"
                    )
                    self.assertEqual(classification.status_code, 200)
                    correction = client.put(
                        f"/documents/{pdf_id}/classification",
                        json={"document_type": "application_form"}
                    )
                    self.assertEqual(correction.status_code, 200)
                    corrected_classification = client.get(
                        f"/classification/{pdf_id}"
                    )
                    self.assertEqual(
                        corrected_classification.json()["document_type"],
                        "application_form"
                    )
                    original_preview = client.get(
                        f"/documents/{pdf_id}/preview"
                    )
                    self.assertEqual(original_preview.status_code, 200)
                    self.assertEqual(
                        original_preview.headers["content-type"],
                        "application/pdf"
                    )

                    image_upload = client.post(
                        "/upload",
                        files={
                            "file": (
                                "supporting.png",
                                image_buffer.getvalue(),
                                "image/png"
                            )
                        }
                    )
                    self.assertEqual(image_upload.status_code, 200)
                    image_id = image_upload.json()["document_id"]
                    ocr = client.get(f"/ocr/{image_id}")
                    self.assertEqual(ocr.status_code, 200)
                    ocr_page = ocr.json()["pages"][0]
                    self.assertEqual(
                        ocr_page["regions"][0]["ocr_confidence"],
                        0.96
                    )
                    self.assertIsNotNone(ocr_page["regions"][0]["bbox"])
                    self.assertIsNotNone(ocr_page["ocr_confidence"])
                    scanned_upload = client.post(
                        "/upload",
                        files={
                            "file": (
                                "scanned.pdf",
                                scanned_pdf_buffer.getvalue(),
                                "application/pdf"
                            )
                        }
                    )
                    self.assertEqual(scanned_upload.status_code, 200)
                    scanned_id = scanned_upload.json()["document_id"]
                    scanned_ocr = client.get(f"/ocr/{scanned_id}")
                    self.assertEqual(scanned_ocr.status_code, 200)
                    self.assertEqual(
                        scanned_ocr.json()["pages"][0]["method"],
                        "easyocr"
                    )
                    self.assertTrue(
                        scanned_ocr.json()["pages"][0]["regions"]
                    )
                    preview = client.get(
                        f"/evidence-preview/{image_id}/1?bbox=10,10,200,35"
                    )
                    self.assertEqual(preview.status_code, 200)
                    self.assertTrue(preview.content.startswith(b"\x89PNG"))

                    dossier = client.post(
                        "/investigations",
                        json={"document_ids": [pdf_id, image_id]}
                    )
                    self.assertEqual(dossier.status_code, 200, dossier.text)
                    dossier_data = dossier.json()
                    self.assertTrue(dossier_data["document_structure"])
                    self.assertEqual(
                        dossier_data["visual_forensic_findings"][0][
                            "analysis"
                        ]["embedded_image_screening"]["total_images"],
                        0
                    )
                    self.assertEqual(
                        dossier_data["risk_assessment"]["category"],
                        "MEDIUM RISK"
                    )
                    self.assertEqual(
                        dossier_data["risk_assessment"]["score"],
                        45
                    )
                    self.assertTrue(
                        any(
                            finding["type"] == "cross_document_field_conflict"
                            and finding["field"] == "date_of_birth"
                            for finding in dossier_data[
                                "contextual_analysis"
                            ]["findings"]
                        )
                    )
                    self.assertTrue(
                        any(
                            row["field"] == "date_of_birth"
                            and row["value_status"] == "conflict"
                            for row in dossier_data["contextual_analysis"][
                                "cross_document_comparison"
                            ]
                        )
                    )
                    self.assertTrue(
                        any(
                            finding["type"] == "cross_document_field_not_extracted"
                            and finding["field"] == "mobile_number"
                            for finding in dossier_data[
                                "contextual_analysis"
                            ]["findings"]
                        )
                    )
                    summary = client.get("/dashboard/summary")
                    self.assertEqual(summary.status_code, 200)
                    self.assertEqual(
                        summary.json(),
                        {
                            "total_investigations": 1,
                            "total_documents_analyzed": 2,
                            "documents_requiring_review": 2,
                            "potential_anomalies": 2,
                            "completed_investigations": 1
                        }
                    )
                    self.assertTrue(
                        any(
                            finding["type"] == "cross_document_field_conflict"
                            for finding in dossier_data[
                                "contextual_analysis"
                            ]["findings"]
                        )
                    )
                    finding = next(
                        item
                        for item in dossier_data[
                            "contextual_analysis"
                        ]["findings"]
                        if item["type"] == "cross_document_field_conflict"
                    )
                    finding_detail = client.get(
                        f"/investigations/{dossier_data['investigation_id']}"
                        f"/findings/{finding['finding_id']}"
                    )
                    self.assertEqual(finding_detail.status_code, 200)
                    dossier_pdf = client.get(
                        f"/investigations/{dossier_data['investigation_id']}/report"
                    )
                    self.assertEqual(dossier_pdf.status_code, 200)
                    self.assertTrue(dossier_pdf.content.startswith(b"%PDF"))
                    report_document = pymupdf.open(
                        stream=dossier_pdf.content,
                        filetype="pdf"
                    )
                    report_text = "\n".join(
                        page.get_text() for page in report_document
                    )
                    self.assertIn("FORENSIC RISK ASSESSMENT", report_text)
                    self.assertIn("INVESTIGATOR REVIEW DECISIONS", report_text)
                    history = client.get("/investigations")
                    self.assertEqual(history.status_code, 200)
                    self.assertEqual(
                        history.json()["investigations"][0]["document_count"],
                        2
                    )
                    events = client.get("/audit-trail").json()["events"]
                    self.assertTrue(
                        any(event["event_type"] == "document_uploaded" for event in events)
                    )

    def test_duplicate_embedded_images_are_traced_in_dossier(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            uploads = root / "uploads"
            reports = root / "reports"
            uploads.mkdir()
            reports.mkdir()

            image_buffer = io.BytesIO()
            Image.new("RGB", (40, 40), "blue").save(
                image_buffer, format="PNG"
            )
            image_bytes = image_buffer.getvalue()
            pdf = pymupdf.open()
            for _ in range(2):
                page = pdf.new_page()
                page.insert_image(
                    pymupdf.Rect(20, 20, 100, 100),
                    stream=image_bytes
                )
            pdf_buffer = io.BytesIO()
            pdf.save(pdf_buffer)
            pdf.close()

            class EmptyOCRReader:
                def readtext(self, _image, detail=1, paragraph=False):
                    return []

            with (
                patch.object(main, "UPLOAD_DIR", uploads),
                patch.object(main, "REPORT_DIR", reports),
                patch.object(main, "AUDIT_LOG", root / "audit.jsonl"),
                patch.object(
                    main.forensic_database,
                    "DATABASE_PATH",
                    root / "forensicai.sqlite3"
                ),
                patch.object(
                    main, "get_ocr_reader", return_value=EmptyOCRReader()
                )
            ):
                with TestClient(main.app) as client:
                    client.headers.update(login_admin(client))
                    uploaded = client.post(
                        "/upload",
                        files={
                            "file": (
                                "duplicate-images.pdf",
                                pdf_buffer.getvalue(),
                                "application/pdf"
                            )
                        }
                    )
                    self.assertEqual(uploaded.status_code, 200)
                    document_id = uploaded.json()["document_id"]
                    result = client.get(
                        f"/image-forensics/{document_id}"
                    )
                    self.assertEqual(result.status_code, 200)
                    self.assertEqual(result.json()["total_findings"], 1)

                    dossier = client.post(
                        "/investigations",
                        json={"document_ids": [document_id]}
                    )
                    self.assertEqual(dossier.status_code, 200, dossier.text)
                    finding = next(
                        item
                        for item in dossier.json()["contextual_analysis"][
                            "findings"
                        ]
                        if item["type"] == "duplicate_embedded_image"
                    )
                    self.assertEqual(len(finding["evidence"]), 2)
                    self.assertEqual(
                        finding["evidence"][0]["sha256"],
                        finding["evidence"][1]["sha256"]
                    )

    def test_synthetic_identity_dossiers_include_fields_evidence_and_reports(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            uploads = root / "uploads"
            reports = root / "reports"
            uploads.mkdir()
            reports.mkdir()

            def synthetic_pdf(lines, prominent_disclaimer=False):
                document = pymupdf.open()
                page = document.new_page()
                y = 55
                if prominent_disclaimer:
                    page.insert_text(
                        (72, y),
                        "SYNTHETIC DOCUMENT - DEMO ONLY",
                        fontsize=32
                    )
                    y += 42
                for line in lines:
                    page.insert_text((72, y), line, fontsize=11)
                    y += 28
                content = document.tobytes()
                document.close()
                return content

            pan_content = synthetic_pdf(
                [
                    "Applicant Name: Asha Example",
                    "Date of Birth: 01/01/1990",
                    "Permanent Account Number: ABCDE1234F"
                ],
                prominent_disclaimer=True
            )
            aadhaar_content = synthetic_pdf([
                "Applicant Name: Asha Example",
                "Date of Birth: 01/01/1990",
                "Aadhaar Number: 999988887777"
            ])
            empty_content = synthetic_pdf(
                [
                    "Synthetic internal note only",
                    "No account record included",
                    "Demonstration summary",
                    "For investigation practice"
                ],
                prominent_disclaimer=True
            )

            with (
                patch.object(main, "UPLOAD_DIR", uploads),
                patch.object(main, "REPORT_DIR", reports),
                patch.object(main, "AUDIT_LOG", root / "audit.jsonl"),
                patch.object(
                    main.forensic_database,
                    "DATABASE_PATH",
                    root / "forensicai.sqlite3"
                )
            ):
                with TestClient(main.app) as client:
                    client.headers.update(login_admin(client))
                    uploaded = {}
                    for filename, content in (
                        ("fictional_pan_sample.pdf", pan_content),
                        ("fictional_aadhaar_sample.pdf", aadhaar_content),
                        ("fictional_no_fields.pdf", empty_content)
                    ):
                        response = client.post(
                            "/upload",
                            files={
                                "file": (
                                    filename,
                                    content,
                                    "application/pdf"
                                )
                            }
                        )
                        self.assertEqual(response.status_code, 200, response.text)
                        uploaded[filename] = response.json()["document_id"]

                    two_document_response = client.post(
                        "/investigations",
                        json={
                            "document_ids": [
                                uploaded["fictional_pan_sample.pdf"],
                                uploaded["fictional_aadhaar_sample.pdf"]
                            ]
                        }
                    )
                    self.assertEqual(
                        two_document_response.status_code,
                        200,
                        two_document_response.text
                    )
                    dossier = two_document_response.json()
                    self.assertTrue(
                        main.UUID(dossier["investigation_id"])
                    )
                    self.assertEqual(
                        dossier["contextual_analysis"][
                            "cross_document_comparison_status"
                        ],
                        "completed"
                    )

                    overview_by_id = {
                        item["document_id"]: item
                        for item in dossier["document_overview"]["documents"]
                    }
                    self.assertEqual(
                        overview_by_id[uploaded["fictional_pan_sample.pdf"]][
                            "source_filename"
                        ],
                        "fictional_pan_sample.pdf"
                    )
                    self.assertEqual(
                        overview_by_id[
                            uploaded["fictional_aadhaar_sample.pdf"]
                        ]["source_filename"],
                        "fictional_aadhaar_sample.pdf"
                    )
                    extracted_by_id = {
                        item["document_id"]: item
                        for item in dossier["extracted_information"]
                    }
                    pan_fields = extracted_by_id[
                        uploaded["fictional_pan_sample.pdf"]
                    ]["fields"]
                    aadhaar_fields = extracted_by_id[
                        uploaded["fictional_aadhaar_sample.pdf"]
                    ]["fields"]
                    for document_id in (
                        uploaded["fictional_pan_sample.pdf"],
                        uploaded["fictional_aadhaar_sample.pdf"]
                    ):
                        field_status = extracted_by_id[document_id][
                            "field_status"
                        ]
                        self.assertEqual(
                            field_status["applicant_name"]["status"],
                            "extracted"
                        )
                        self.assertEqual(
                            field_status["address"]["status"],
                            "not_extracted"
                        )
                        self.assertIn(
                            "does not establish",
                            field_status["address"]["message"]
                        )
                    self.assertEqual(
                        pan_fields["applicant_name"][0]["value"],
                        "Asha Example"
                    )
                    self.assertEqual(
                        pan_fields["date_of_birth"][0]["value"],
                        "01/01/1990"
                    )
                    self.assertEqual(
                        pan_fields["pan_number"][0]["value"],
                        "ABCDE1234F"
                    )
                    self.assertEqual(
                        aadhaar_fields["aadhaar_number"][0]["value"],
                        "999988887777"
                    )
                    for extracted in (pan_fields, aadhaar_fields):
                        for values in extracted.values():
                            for value in values:
                                self.assertIsNotNone(value["confidence"])
                                self.assertTrue(value["method"])
                                self.assertEqual(value["page"], 1)
                                self.assertIsNotNone(value["bbox"])
                                self.assertTrue(value["coordinate_system"])
                    for document_id in (
                        uploaded["fictional_pan_sample.pdf"],
                        uploaded["fictional_aadhaar_sample.pdf"]
                    ):
                        for values in extracted_by_id[document_id][
                            "fields"
                        ].values():
                            for value in values:
                                self.assertEqual(
                                    value["document_id"],
                                    document_id
                                )

                    comparisons = {
                        row["field"]: row
                        for row in dossier["contextual_analysis"][
                            "cross_document_comparison"
                        ]
                    }
                    self.assertEqual(
                        comparisons["applicant_name"]["value_status"],
                        "matching"
                    )
                    self.assertEqual(
                        comparisons["date_of_birth"]["value_status"],
                        "matching"
                    )
                    self.assertEqual(
                        {
                            value["document_id"]
                            for value in comparisons["applicant_name"]["values"]
                        },
                        set(uploaded.values()) - {
                            uploaded["fictional_no_fields.pdf"]
                        }
                    )
                    self.assertEqual(
                        comparisons["pan_number"]["status"],
                        "partially_observed"
                    )
                    self.assertEqual(
                        comparisons["pan_number"][
                            "not_extracted_from_document_ids"
                        ],
                        [uploaded["fictional_aadhaar_sample.pdf"]]
                    )
                    self.assertEqual(
                        comparisons["aadhaar_number"]["status"],
                        "partially_observed"
                    )
                    self.assertEqual(
                        comparisons["aadhaar_number"][
                            "not_extracted_from_document_ids"
                        ],
                        [uploaded["fictional_pan_sample.pdf"]]
                    )

                    traceability = {
                        item["document_id"]: item
                        for item in dossier["evidence_and_traceability"]
                    }
                    findings_by_id = {
                        item["finding_id"]: item
                        for item in dossier["contextual_analysis"]["findings"]
                    }
                    linked_reference_count = 0
                    for document_id, item in traceability.items():
                        self.assertEqual(
                            item["source_filename"],
                            overview_by_id[document_id]["source_filename"]
                        )
                        reference_keys = [
                            (
                                reference.get("page"),
                                tuple(reference.get("bbox") or []),
                                reference.get("field"),
                                reference.get("value"),
                                reference.get("text_excerpt")
                                or reference.get("evidence_text"),
                                reference.get("sha256"),
                                reference.get("image_xref")
                            )
                            for reference in item["references"]
                        ]
                        self.assertEqual(
                            len(reference_keys),
                            len(set(reference_keys))
                        )
                        for reference in item["references"]:
                            self.assertEqual(
                                reference["document_id"],
                                document_id
                            )
                            self.assertTrue(
                                reference.get("text_excerpt")
                                or reference.get("evidence_text")
                                or reference.get("sha256")
                            )
                        for reference in item["finding_references"]:
                            linked_reference_count += 1
                            self.assertIn(reference["finding_id"], findings_by_id)
                            self.assertEqual(
                                reference["document_id"],
                                document_id
                            )
                            self.assertEqual(
                                reference["source_filename"],
                                overview_by_id[document_id]["source_filename"]
                            )
                            self.assertTrue(
                                any(
                                    source.get("document_id") == document_id
                                    and source.get("page") == reference.get("page")
                                    and source.get("bbox") == reference.get("bbox")
                                    and (
                                        source.get("text_excerpt")
                                        or source.get("evidence_text")
                                    ) == reference.get("text_excerpt")
                                    for source in findings_by_id[
                                        reference["finding_id"]
                                    ]["evidence"]
                                )
                            )
                    self.assertGreater(linked_reference_count, 0)

                    disclaimer_finding = next(
                        finding
                        for finding in findings_by_id.values()
                        if finding["type"] == "visual_font_size_screening"
                        and finding["risk_assessment_excluded"]
                    )
                    self.assertIn(
                        "synthetic or demo disclaimer",
                        disclaimer_finding["explanation"]
                    )
                    self.assertTrue(disclaimer_finding["risk_exclusion_reason"])
                    contribution = next(
                        item for item in dossier["risk_assessment"][
                            "finding_contributions"
                        ]
                        if item["finding_id"] == disclaimer_finding["finding_id"]
                    )
                    self.assertEqual(contribution["points"], 0)
                    self.assertTrue(contribution["excluded_from_score"])

                    empty_response = client.post(
                        "/investigations",
                        json={
                            "document_ids": [
                                uploaded["fictional_no_fields.pdf"]
                            ]
                        }
                    )
                    self.assertEqual(empty_response.status_code, 200)
                    empty_dossier = empty_response.json()
                    empty_extraction = empty_dossier["extracted_information"][0]
                    self.assertEqual(empty_extraction["fields"], {})
                    self.assertEqual(
                        empty_extraction["message"],
                        "No structured fields detected"
                    )
                    self.assertTrue(all(
                        status["status"] == "not_extracted"
                        for status in empty_extraction["field_status"].values()
                    ))
                    empty_document_id = uploaded["fictional_no_fields.pdf"]
                    empty_traceability = next(
                        item
                        for item in empty_dossier["evidence_and_traceability"]
                        if item["document_id"] == empty_document_id
                    )
                    self.assertTrue(empty_traceability["references"])
                    self.assertTrue(empty_traceability["finding_references"])
                    self.assertTrue(all(
                        reference["finding_id"] in {
                            finding["finding_id"]
                            for finding in empty_dossier[
                                "contextual_analysis"
                            ]["findings"]
                        }
                        for reference in empty_traceability[
                            "finding_references"
                        ]
                    ))
                    self.assertTrue(any(
                        reference.get("finding_id")
                        for reference in empty_traceability["references"]
                    ))
                    self.assertEqual(
                        empty_dossier["contextual_analysis"][
                            "cross_document_comparison_message"
                        ],
                        "Cross-document comparison not applicable"
                    )
                    self.assertEqual(
                        empty_dossier["contextual_analysis"][
                            "cross_document_comparison"
                        ],
                        []
                    )

                    json_path = reports / (
                        f"Investigation_Dossier_{dossier['investigation_id']}.json"
                    )
                    self.assertEqual(
                        json.loads(json_path.read_text(encoding="utf-8")),
                        dossier
                    )
                    pdf_response = client.get(
                        f"/investigations/{dossier['investigation_id']}/report"
                    )
                    self.assertEqual(pdf_response.status_code, 200)
                    report_pdf = pymupdf.open(
                        stream=pdf_response.content,
                        filetype="pdf"
                    )
                    report_text = "\n".join(
                        page.get_text() for page in report_pdf
                    )
                    self.assertIn("fictional_pan_sample.pdf", report_text)
                    self.assertIn("ABCDE1234F", report_text)
                    self.assertIn(dossier["investigation_id"], report_text)
                    self.assertIn(
                        uploaded["fictional_pan_sample.pdf"],
                        report_text
                    )
                    self.assertIn(
                        uploaded["fictional_aadhaar_sample.pdf"],
                        report_text
                    )
                    self.assertIn("EVIDENCE AND TRACEABILITY", report_text)
                    self.assertIn("FINDING INTERPRETATION", report_text)
                    self.assertIn("LIMITATIONS", report_text)
                    self.assertIn(disclaimer_finding["finding_id"], report_text)

    def test_extracts_label_values_from_positioned_pdf_regions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            pdf_path = Path(temp_dir) / "positioned_identity.pdf"
            document = pymupdf.open()
            page = document.new_page()
            page.insert_text((72, 70), "Applicant Name", fontsize=11)
            page.insert_text((220, 70), "Asha Example", fontsize=11)
            page.insert_text((72, 100), "Date of Birth:", fontsize=11)
            page.insert_text((72, 115), "01/02/1990", fontsize=11)
            page.insert_text((72, 145), "Document Number", fontsize=11)
            page.insert_text((220, 145), "DOC-12345", fontsize=11)
            page.insert_text((72, 175), "Address", fontsize=11)
            page.insert_text((72, 190), "1 Example Street, Sample City", fontsize=11)
            page.insert_text((72, 220), "Gender:", fontsize=11)
            page.insert_text((220, 220), "Female", fontsize=11)
            page.insert_text((72, 250), "Issue Date", fontsize=11)
            page.insert_text((220, 250), "01/03/2020", fontsize=11)
            page.insert_text((72, 280), "Expiry Date:", fontsize=11)
            page.insert_text((220, 280), "01/03/2030", fontsize=11)
            document.save(pdf_path)
            document.close()

            page_texts = main.extract_document_pages(pdf_path)
            document_id = "synthetic-positioned-document"
            fields = main.extract_structured_fields(
                page_texts,
                document_id=document_id
            )

        expected = {
            "applicant_name": "Asha Example",
            "date_of_birth": "01/02/1990",
            "document_number": "DOC-12345",
            "address": "1 Example Street, Sample City",
            "gender": "Female",
            "issue_date": "01/03/2020",
            "expiry_date": "01/03/2030"
        }
        for field_name, expected_value in expected.items():
            with self.subTest(field=field_name):
                extracted = fields[field_name][0]
                self.assertEqual(extracted["value"], expected_value)
                self.assertEqual(extracted["document_id"], document_id)
                self.assertEqual(extracted["page"], 1)
                self.assertTrue(extracted["method"])
                self.assertIsNotNone(extracted["bbox"])
                self.assertEqual(
                    extracted["coordinate_system"],
                    "PDF points, origin at top left"
                )
                self.assertIn(
                    extracted["association_method"],
                    {
                        "same_line",
                        "adjacent_region_same_baseline",
                        "adjacent_region_below_label"
                    }
                )

    def test_dossier_explicitly_reports_no_structured_fields(self):
        page_texts = [{
            "page": 1,
            "text": "No recognized form labels here.",
            "method": "pdf_text",
            "regions": []
        }]
        fields = main.extract_structured_fields(page_texts)
        self.assertEqual(fields, {})
        self.assertTrue(all(
            status["status"] == "not_extracted"
            for status in main.build_field_extraction_status(fields).values()
        ))
        self.assertIn(
            "does not establish",
            main.build_field_extraction_status(fields)["applicant_name"][
                "message"
            ]
        )

    def test_builds_dossier_with_conflict_and_audit_event(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            uploads = root / "uploads"
            reports = root / "reports"
            uploads.mkdir()
            reports.mkdir()

            document_ids = [str(uuid4()), str(uuid4())]
            paths = {
                document_id: uploads / f"{document_id}.pdf"
                for document_id in document_ids
            }
            for path in paths.values():
                path.write_bytes(b"test PDF placeholder")

            pages_by_path = {
                paths[document_ids[0]]: [{
                    "page": 1,
                    "text": "Applicant Name: Alice Example",
                    "method": "pdf_text"
                }],
                paths[document_ids[1]]: [{
                    "page": 1,
                    "text": "Applicant Name: Alicia Example",
                    "method": "pdf_text"
                }]
            }
            fields_by_path = {
                paths[document_ids[0]]: "Alice Example",
                paths[document_ids[1]]: "Robert Example"
            }

            def extracted_fields(page_texts, document_id=None):
                path = next(
                    path for path, pages in pages_by_path.items()
                    if pages == page_texts
                )
                value = fields_by_path[path]
                return {
                    "applicant_name": [{
                        "value": value,
                        "confidence": 0.9,
                        "confidence_basis": "heuristic_extraction_score",
                        "page": 1,
                        "method": "pdf_text",
                        "evidence": f"Applicant Name: {value}",
                        "bbox": None,
                        "coordinate_system": None,
                        "human_verification_status": "requires_human_verification"
                    }]
                }

            with (
                patch.object(main, "UPLOAD_DIR", uploads),
                patch.object(main, "REPORT_DIR", reports),
                patch.object(main, "AUDIT_LOG", root / "audit_trail.jsonl"),
                patch.object(
                    main.forensic_database,
                    "DATABASE_PATH",
                    root / "forensicai.sqlite3"
                ),
                patch.object(
                    main,
                    "find_uploaded_document",
                    side_effect=lambda document_id: paths[document_id]
                ),
                patch.object(
                    main,
                    "extract_document_pages",
                    side_effect=lambda path: pages_by_path[path]
                ),
                patch.object(
                    main,
                    "extract_structured_fields",
                    side_effect=extracted_fields
                ),
                patch.object(
                    main,
                    "classify_document",
                    return_value={
                        "document_type": "identity",
                        "classification_scores": {"identity": 2},
                        "classification_confidence": 1.0,
                        "classification_method": "keyword_evidence",
                        "classification_note": "Test classifier"
                    }
                ),
                patch.object(main, "get_file_hash", return_value="a" * 64),
                patch.object(
                    main,
                    "get_original_filename",
                    side_effect=lambda path: path.name
                ),
                patch.object(
                    main,
                    "visual_document_forensics",
                    return_value={"findings": []}
                ),
                patch.object(
                    main,
                    "image_manipulation_forensics",
                    return_value={
                        "total_images": 0,
                        "image_statistics": [],
                        "disclaimer": "Synthetic test image screening.",
                        "findings": []
                    }
                )
            ):
                dossier = main.create_investigation(
                    main.InvestigationRequest(document_ids=document_ids),
                    user=admin_principal()
                )
                self.assertEqual(
                    dossier["risk_assessment"]["category"],
                    "NEEDS MANUAL REVIEW"
                )
                self.assertEqual(dossier["risk_assessment"]["score"], 20)
                conflict = next(
                    finding
                    for finding in dossier["contextual_analysis"]["findings"]
                    if finding["type"] == "cross_document_field_conflict"
                )

                self.assertEqual(conflict["field"], "applicant_name")
                self.assertEqual(len(conflict["evidence"]), 2)
                retrieved = main.get_investigation(
                    dossier["investigation_id"],
                    user=admin_principal()
                )
                self.assertEqual(
                    retrieved["document_overview"],
                    dossier["document_overview"]
                )
                self.assertEqual(retrieved["review_decisions"], [])
                report = main.generate_investigation_report(
                    dossier["investigation_id"],
                    user=admin_principal()
                )
                self.assertTrue(Path(report.path).is_file())
                events = main.get_audit_trail(
                    user=admin_principal()
                )["events"]
                self.assertEqual(len(events), 2)
                self.assertEqual(
                    {event["event_type"] for event in events},
                    {
                        "investigation_completed",
                        "investigation_report_generated"
                    }
                )
                completed = next(
                    event for event in events
                    if event["event_type"] == "investigation_completed"
                )
                self.assertEqual(
                    completed["details"]["finding_types"],
                    ["cross_document_field_conflict"]
                )
                saved_dossier = reports / (
                    f"Investigation_Dossier_{dossier['investigation_id']}.json"
                )
                self.assertEqual(
                    json.loads(saved_dossier.read_text(encoding="utf-8")),
                    dossier
                )

                fields_by_path[paths[document_ids[1]]] = "Alice Exampel"
                variation_dossier = main.create_investigation(
                    main.InvestigationRequest(document_ids=document_ids),
                    user=admin_principal()
                )
                variation_finding = next(
                    finding
                    for finding in variation_dossier[
                        "contextual_analysis"
                    ]["findings"]
                    if finding["type"] == "potential_name_variation"
                )
                variation_row = next(
                    row
                    for row in variation_dossier["contextual_analysis"][
                        "cross_document_comparison"
                    ]
                    if row["field"] == "applicant_name"
                )
                self.assertEqual(
                    variation_finding["status"],
                    "requires_human_verification"
                )
                self.assertEqual(
                    variation_row["value_status"],
                    "potential_spelling_variation"
                )
                self.assertEqual(
                    variation_dossier["risk_assessment"]["score"],
                    5
                )

    def test_rejects_duplicate_document_ids(self):
        document_id = str(uuid4())
        with (
            patch.object(main, "find_uploaded_document", return_value=Path("unused.pdf")),
            patch.object(main, "ensure_document_record")
        ):
            with self.assertRaises(HTTPException) as raised:
                main.create_investigation(main.InvestigationRequest(
                    document_ids=[document_id, document_id]
                ))
        self.assertEqual(raised.exception.status_code, 400)

    def test_name_normalization_and_potential_variation(self):
        left = {
            "document_id": "document-1",
            "value": "  Asha   Example "
        }
        right = {
            "document_id": "document-2",
            "value": "ASHA EXAMPLE"
        }
        variation = {
            "document_id": "document-3",
            "value": "Asha Exampel"
        }
        self.assertEqual(
            main.normalized_field_value("  Asha, Example "),
            main.normalized_field_value("ASHA EXAMPLE")
        )
        self.assertEqual(
            main.normalized_comparison_value(
                "date_of_birth", "01/01/1990"
            ),
            main.normalized_comparison_value(
                "date_of_birth", "1990-01-01"
            )
        )
        self.assertTrue(
            main.is_potential_name_variation(
                "applicant_name", [left, variation]
            )
        )
        self.assertFalse(
            main.is_potential_name_variation(
                "date_of_birth", [left, variation]
            )
        )
        self.assertFalse(
            main.is_potential_name_variation(
                "applicant_name", [left, right]
            )
        )

    def test_rejects_invalid_document_id(self):
        with self.assertRaises(HTTPException) as raised:
            main.validate_document_id("not-a-uuid")
        self.assertEqual(raised.exception.status_code, 400)

    def test_sqlite_history_and_manual_review(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            uploads = root / "uploads"
            reports = root / "reports"
            uploads.mkdir()
            reports.mkdir()
            document_id = str(uuid4())
            path = uploads / f"{document_id}.pdf"
            path.write_bytes(b"placeholder")
            page_texts = [{
                "page": 1,
                "text": "Applicant Name: Alice Example",
                "method": "pdf_text",
                "regions": []
            }]
            fields = {
                "applicant_name": [{
                    "value": "Alice Example",
                    "confidence": 0.9,
                    "confidence_basis": "heuristic_extraction_score",
                    "page": 1,
                    "method": "pdf_text",
                    "evidence": "Applicant Name: Alice Example",
                    "review_required": True,
                    "human_verification_status": "requires_human_verification",
                    "bbox": None,
                    "coordinate_system": None
                }, {
                    "value": "Alicia Example",
                    "confidence": 0.8,
                    "confidence_basis": "heuristic_extraction_score",
                    "page": 1,
                    "method": "pdf_text",
                    "evidence": "Applicant Name: Alicia Example",
                    "review_required": True,
                    "human_verification_status": "requires_human_verification",
                    "bbox": None,
                    "coordinate_system": None
                }]
            }
            with (
                patch.object(main, "UPLOAD_DIR", uploads),
                patch.object(main, "REPORT_DIR", reports),
                patch.object(main, "AUDIT_LOG", root / "audit.jsonl"),
                patch.object(
                    main.forensic_database,
                    "DATABASE_PATH",
                    root / "forensicai.sqlite3"
                ),
                patch.object(
                    main,
                    "extract_document_pages",
                    return_value=page_texts
                ),
                patch.object(
                    main,
                    "extract_structured_fields",
                    return_value=fields
                ),
                patch.object(
                    main,
                    "classify_document",
                    return_value={
                        "document_type": "identity",
                        "classification_scores": {"identity": 2},
                        "classification_confidence": 1.0,
                        "classification_method": "keyword_evidence",
                        "classification_note": "Test classifier"
                    }
                ),
                patch.object(main, "get_file_hash", return_value="b" * 64),
                patch.object(
                    main,
                    "visual_document_forensics",
                    return_value={"findings": []}
                ),
                patch.object(
                    main,
                    "image_manipulation_forensics",
                    return_value={
                        "total_images": 0,
                        "image_statistics": [],
                        "disclaimer": "Synthetic test image screening.",
                        "findings": []
                    }
                )
            ):
                dossier = main.create_investigation(
                    main.InvestigationRequest(document_ids=[document_id]),
                    user=admin_principal()
                )
                finding_id = dossier["contextual_analysis"]["findings"][0][
                    "finding_id"
                ]

                history = main.list_investigation_history(
                    user=admin_principal()
                )
                self.assertEqual(
                    history["investigations"][0]["investigation_id"],
                    dossier["investigation_id"]
                )
                review = main.review_investigation_finding(
                    dossier["investigation_id"],
                    finding_id,
                    main.FindingReviewRequest(
                        status="verified_by_investigator",
                        reviewer="Demo reviewer",
                        note="Checked against synthetic source."
                    ),
                    user=admin_principal()
                )
                self.assertEqual(review["status"], "verified_by_investigator")
                summary = main.forensic_database.get_dashboard_summary()
                self.assertEqual(summary["total_investigations"], 1)
                self.assertEqual(summary["total_documents_analyzed"], 1)
                self.assertEqual(summary["documents_requiring_review"], 0)
                self.assertEqual(summary["potential_anomalies"], 1)
                self.assertEqual(summary["completed_investigations"], 1)
                retrieved = main.get_investigation(
                    dossier["investigation_id"],
                    user=admin_principal()
                )
                self.assertEqual(
                    retrieved["review_decisions"][0]["status"],
                    "verified_by_investigator"
                )


if __name__ == "__main__":
    unittest.main()
