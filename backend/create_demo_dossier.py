import os
import secrets
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient


BACKEND_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BACKEND_DIR.parent
DEMO_DIR = PROJECT_DIR / "demo_dataset"
os.environ.setdefault("FORENSAI_JWT_SECRET", secrets.token_urlsafe(32))
sys.path.insert(0, str(BACKEND_DIR))
import main


def main_entry():
    filenames = [
        "application_record.pdf",
        "supporting_record.pdf",
        "altered_supporting_record.pdf"
    ]
    with tempfile.TemporaryDirectory(prefix="forensicai-demo-") as temp_dir:
        temporary_root = Path(temp_dir)
        uploads = temporary_root / "uploads"
        reports = temporary_root / "reports"
        uploads.mkdir()
        reports.mkdir()

        with (
            patch.object(main, "UPLOAD_DIR", uploads),
            patch.object(main, "REPORT_DIR", reports),
            patch.object(main, "AUDIT_LOG", temporary_root / "audit.jsonl"),
            patch.object(
                main.forensic_database,
                "DATABASE_PATH",
                temporary_root / "forensicai.sqlite3"
            )
        ):
            with TestClient(main.app) as client:
                registration = client.post(
                    "/auth/register",
                    json={
                        "email": "demo-investigator@example.test",
                        "password": "demo-investigator-password"
                    }
                )
                registration.raise_for_status()
                client.headers["Authorization"] = (
                    "Bearer " + registration.json()["access_token"]
                )
                document_ids = []
                for filename in filenames:
                    with (DEMO_DIR / filename).open("rb") as document_file:
                        response = client.post(
                            "/upload",
                            files={
                                "file": (
                                    filename,
                                    document_file,
                                    "application/pdf"
                                )
                            }
                        )
                    response.raise_for_status()
                    document_ids.append(response.json()["document_id"])

                dossier_response = client.post(
                    "/investigations",
                    json={"document_ids": document_ids}
                )
                dossier_response.raise_for_status()
                dossier = dossier_response.json()

                report_response = client.get(
                    f"/investigations/{dossier['investigation_id']}/report"
                )
                report_response.raise_for_status()

        dossier_path = DEMO_DIR / "sample_investigation_dossier.json"
        report_path = DEMO_DIR / "sample_investigation_dossier.pdf"
        dossier_path.write_text(
            dossier_response.text,
            encoding="utf-8"
        )
        report_path.write_bytes(report_response.content)

    print(f"Generated {dossier_path}")
    print(f"Generated {report_path}")
    print(f"Investigation ID: {dossier['investigation_id']}")
    print(
        "Findings: "
        f"{dossier['contextual_analysis']['finding_count']}"
    )


if __name__ == "__main__":
    main_entry()
