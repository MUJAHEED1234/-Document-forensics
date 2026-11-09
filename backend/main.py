from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi import Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from typing import Literal

from pathlib import Path
from uuid import uuid4, UUID
from io import BytesIO
from datetime import datetime, timezone, timedelta
from xml.sax.saxutils import escape
from contextlib import asynccontextmanager
from dotenv import load_dotenv

import hashlib
import hmac
import json
import logging
import os
import statistics
import re
import sqlite3
import unicodedata
import base64
from difflib import SequenceMatcher

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_environment_files(project_root=PROJECT_ROOT):
    load_dotenv(project_root / ".env", override=False)
    load_dotenv(project_root / "backend" / ".env", override=False)


load_environment_files()

import pymupdf
import easyocr
import numpy as np
from PIL import Image, ImageDraw

import database as forensic_database

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    KeepTogether, SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
)

logger = logging.getLogger(__name__)


JWT_ISSUER = "forensai"
JWT_LIFETIME = timedelta(minutes=30)
bearer_token_scheme = HTTPBearer(auto_error=False)


def _jwt_secret():
    secret = os.environ.get("FORENSAI_JWT_SECRET", "")
    secret_bytes = secret.encode("utf-8")
    if not secret.strip() or len(secret_bytes) < 32:
        raise HTTPException(
            status_code=503,
            detail=(
                "JWT configuration is invalid. FORENSAI_JWT_SECRET must be "
                "set to a random value of at least 32 UTF-8 bytes in the "
                "project .env file or process environment."
            )
        )
    return secret_bytes


def _encode_segment(value):
    return base64.urlsafe_b64encode(
        json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).rstrip(b"=").decode("ascii")


def create_access_token(user):
    now = datetime.now(timezone.utc)
    expires_at = now + JWT_LIFETIME
    header = _encode_segment({"alg": "HS256", "typ": "JWT"})
    payload = _encode_segment({
        "iss": JWT_ISSUER,
        "sub": user["user_id"],
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": str(uuid4())
    })
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = hmac.new(
        _jwt_secret(),
        signing_input,
        hashlib.sha256
    ).digest()
    token = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    return f"{header}.{payload}.{token}", expires_at


def _decode_access_token(token):
    try:
        header_segment, payload_segment, signature_segment = token.split(".")
        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        signature = base64.urlsafe_b64decode(
            signature_segment + "=" * (-len(signature_segment) % 4)
        )
        expected = hmac.new(
            _jwt_secret(),
            signing_input,
            hashlib.sha256
        ).digest()
        if not hmac.compare_digest(signature, expected):
            raise ValueError("Invalid token signature.")

        header = json.loads(base64.urlsafe_b64decode(
            header_segment + "=" * (-len(header_segment) % 4)
        ))
        claims = json.loads(base64.urlsafe_b64decode(
            payload_segment + "=" * (-len(payload_segment) % 4)
        ))
        if header.get("alg") != "HS256" or claims.get("iss") != JWT_ISSUER:
            raise ValueError("Invalid token claims.")
        if int(claims["exp"]) <= int(datetime.now(timezone.utc).timestamp()):
            raise ValueError("Token has expired.")
        if not claims.get("sub") or not claims.get("jti"):
            raise ValueError("Required token claims are missing.")
        return claims
    except HTTPException:
        raise
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise HTTPException(
            status_code=401,
            detail="Bearer token is invalid or expired.",
            headers={"WWW-Authenticate": "Bearer"}
        ) from error


def require_authenticated_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_token_scheme
    )
):
    if request.url.path in {"/auth/register", "/auth/login"}:
        return None
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="A valid JWT bearer token is required.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    claims = _decode_access_token(credentials.credentials)
    user = forensic_database.get_user_by_id(claims["sub"])
    if (
        user is None
        or not user["is_active"]
        or forensic_database.is_token_revoked(claims["jti"])
    ):
        raise HTTPException(
            status_code=401,
            detail="Bearer token is invalid or revoked.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    is_admin = user["role"] == "admin"
    investigation_id = request.path_params.get("investigation_id")
    if investigation_id:
        owner_id = forensic_database.get_investigation_owner(investigation_id)
        if owner_id is None:
            if not is_admin:
                raise HTTPException(status_code=404, detail="Investigation not found.")
        elif owner_id != user["user_id"] and not is_admin:
            raise HTTPException(status_code=404, detail="Investigation not found.")

    document_id = request.path_params.get("document_id")
    if document_id:
        document = forensic_database.get_document(document_id)
        if document is None:
            if not is_admin:
                raise HTTPException(status_code=404, detail="Document not found.")
        elif document["owner_id"] != user["user_id"] and not is_admin:
            raise HTTPException(status_code=404, detail="Document not found.")
    request.state.user = user
    return user


def require_admin(user=Depends(require_authenticated_user)):
    if user is None or user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator role required.")
    return user


def hash_password(password):
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


def verify_password(password, encoded_hash):
    try:
        scheme, salt_text, digest_text = encoded_hash.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.urlsafe_b64decode(
            salt_text + "=" * (-len(salt_text) % 4)
        )
        expected = base64.urlsafe_b64decode(
            digest_text + "=" * (-len(digest_text) % 4)
        )
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=2**14,
            r=8,
            p=1,
            dklen=len(expected)
        )
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def validate_email(email):
    normalized = email.strip().lower()
    if len(normalized) > 254 or not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        normalized
    ):
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    return normalized


def public_user(user):
    return {
        "user_id": user["user_id"],
        "email": user["email"],
        "role": user["role"],
        "is_active": bool(user["is_active"]),
        "created_at": user["created_at"]
    }


def issue_auth_response(user):
    token, expires_at = create_access_token(user)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_at": expires_at.isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "user": public_user(user)
    }


# =========================================================
# 1. INITIALIZE FASTAPI
# =========================================================

@asynccontextmanager
async def lifespan(_app):
    try:
        _jwt_secret()
    except HTTPException as error:
        raise RuntimeError(error.detail) from error
    yield


app = FastAPI(
    title="FORENSAI - Document Intelligence System",
    description="AI-powered document forensics and contextual intelligence platform",
    version="3.2",
    lifespan=lifespan,
    dependencies=[Depends(require_authenticated_user)]
)

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_methods=["*"],
    allow_headers=["*"],
)

# =========================================================
# 2. DIRECTORIES AND FILE CONFIGURATION
# =========================================================

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

ALLOWED_TYPES = {
    ".pdf": "application/pdf",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
}

MAX_FILE_SIZE = 15 * 1024 * 1024
MAX_OCR_PAGES = 50
MAX_INVESTIGATION_DOCUMENTS = 10
AUDIT_LOG = Path("audit_trail.jsonl")
MAX_IMAGE_PIXELS = 40_000_000
SUPPORTED_OCR_LANGUAGES = {"en", "hi", "kn"}
DOCUMENT_TYPES = {
    "identity",
    "educational",
    "financial",
    "legal",
    "employment",
    "application_form",
    "government",
    "other",
    "unclassified",
    "mixed"
}
SYNTHETIC_DISCLAIMER_PATTERN = re.compile(
    r"\b(?:SAMPLE|FICTIONAL|NOT\s+VALID|DEMO|SYNTHETIC|"
    r"NOT\s+AN\s+IDENTITY\s+DOCUMENT|NOT\s+FOR\s+VERIFICATION)\b",
    re.IGNORECASE
)


class InvestigationRequest(BaseModel):
    document_ids: list[str] = Field(min_length=1, max_length=MAX_INVESTIGATION_DOCUMENTS)


class ClassificationRequest(BaseModel):
    document_type: str


class FindingReviewRequest(BaseModel):
    status: Literal[
        "requires_human_verification",
        "verified_by_investigator",
        "dismissed_by_investigator"
    ]
    reviewer: str = Field(default="", max_length=100)
    note: str = Field(default="", max_length=2000)


class CredentialsRequest(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=12, max_length=128)


class AdminUserRequest(CredentialsRequest):
    role: Literal["admin", "investigator"] = "investigator"


class UserUpdateRequest(BaseModel):
    role: Literal["admin", "investigator"] | None = None
    is_active: bool | None = None


# =========================================================
# 3. OCR ENGINE
# =========================================================

ocr_reader = None


def configured_ocr_languages():
    configured_languages = os.environ.get(
        "FORENSAI_OCR_LANGUAGES", "en"
    )
    languages = [
        language.strip().lower()
        for language in configured_languages.split(",")
        if language.strip()
    ]
    unsupported_languages = sorted(set(languages) - SUPPORTED_OCR_LANGUAGES)
    if not languages or unsupported_languages:
        raise HTTPException(
            status_code=503,
            detail=(
                "FORENSAI_OCR_LANGUAGES must contain one or more of: "
                "en, hi, kn."
            )
        )
    return languages


def get_ocr_reader():
    global ocr_reader

    if ocr_reader is None:
        ocr_reader = easyocr.Reader(configured_ocr_languages(), gpu=False)

    return ocr_reader


# =========================================================
# 4. COMMON VALIDATION AND FILE HELPERS
# =========================================================

def validate_document_id(document_id):
    try:
        UUID(document_id)
    except (ValueError, TypeError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid document ID.")


def find_uploaded_document(document_id):
    validate_document_id(document_id)

    for extension in ALLOWED_TYPES:
        candidate = UPLOAD_DIR / f"{document_id}{extension}"
        if candidate.is_file():
            return candidate

    raise HTTPException(status_code=404, detail="Uploaded document not found.")


def open_pdf(file_path):
    if file_path.suffix.lower() != ".pdf":
        raise HTTPException(
            status_code=400,
            detail="This operation supports PDF files only."
        )

    try:
        return pymupdf.open(str(file_path))
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Unable to open PDF. File may be corrupted."
        )


def get_file_hash(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def get_metadata_value(value):
    if value is None or str(value).strip() == "":
        return "Not available"
    return str(value)


def get_original_filename(file_path):
    document = forensic_database.get_document(file_path.stem)
    if document:
        return document["source_filename"]

    metadata_path = UPLOAD_DIR / f"{file_path.stem}.json"
    if not metadata_path.is_file():
        return file_path.name

    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to read uploaded document source metadata."
        ) from error

    return metadata.get("filename") or file_path.name


def ensure_document_record(document_id, file_path):
    existing = forensic_database.get_document(document_id)
    if existing:
        return existing
    metadata = {
        "document_id": document_id,
        "source_filename": get_original_filename(file_path),
        "file_type": file_path.suffix.lower().lstrip("."),
        "file_size_bytes": file_path.stat().st_size,
        "sha256": get_file_hash(file_path),
        "uploaded_at": datetime.fromtimestamp(
            file_path.stat().st_mtime,
            timezone.utc
        ).isoformat(timespec="seconds")
    }
    forensic_database.save_document(metadata)
    return forensic_database.get_document(document_id)


def record_audit_event(
    event_type,
    document_ids,
    details=None,
    investigation_id=None
):
    event = {
        "event_id": str(uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "event_type": event_type,
        "investigation_id": investigation_id,
        "document_ids": document_ids,
        "details": details or {}
    }

    try:
        forensic_database.save_audit_event(event)
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to write the investigation audit trail."
        ) from error


def record_processing_event(document_id, activity):
    record_audit_event(
        "document_processing_completed",
        [document_id],
        {"activity": activity}
    )


def extract_pdf_text_regions(page):
    regions = []
    text_data = page.get_text("dict")
    for block in text_data.get("blocks", []):
        if block.get("type") != 0:
            continue
        for line in block.get("lines", []):
            spans = line.get("spans", [])
            text = "".join(span.get("text", "") for span in spans).strip()
            if not text:
                continue
            boxes = [span["bbox"] for span in spans if span.get("bbox")]
            bbox = None
            if boxes:
                bbox = [
                    min(box[0] for box in boxes),
                    min(box[1] for box in boxes),
                    max(box[2] for box in boxes),
                    max(box[3] for box in boxes)
                ]
            regions.append({
                "text": text,
                "bbox": [round(float(value), 2) for value in bbox] if bbox else None,
                "coordinate_system": "PDF points, origin at top left",
                "source": "pdf_text",
                "ocr_confidence": None,
                "font_size": (
                    round(max(float(span.get("size", 0)) for span in spans), 2)
                    if spans else None
                ),
                "bold": any(
                    int(span.get("flags", 0)) & 16 for span in spans
                ),
                "column_count": len(spans)
            })
    return regions


def recognize_image_regions(
    reader,
    image_array,
    point_scale_x=1,
    point_scale_y=1,
    coordinate_system="image pixels, origin at top left"
):
    recognized = reader.readtext(image_array, detail=1, paragraph=False)
    regions = []
    for bounding_box, text, confidence in recognized:
        points = [
            (
                round(float(point[0]) * point_scale_x, 2),
                round(float(point[1]) * point_scale_y, 2)
            )
            for point in bounding_box
        ]
        xs = [point[0] for point in points]
        ys = [point[1] for point in points]
        regions.append({
            "text": str(text).strip(),
            "bbox": [
                round(min(xs), 2),
                round(min(ys), 2),
                round(max(xs), 2),
                round(max(ys), 2)
            ],
            "coordinate_system": coordinate_system,
            "source": "easyocr",
            "ocr_confidence": round(float(confidence), 4)
        })
    return regions


# =========================================================
# 5. COMMON DOCUMENT TEXT EXTRACTION
# =========================================================

def extract_document_pages(file_path):
    """
    Extracts text page by page.
    Digital PDF text is preferred. EasyOCR is used when a PDF page
    has no selectable text, or when the uploaded file is an image.
    """

    page_texts = []

    if file_path.suffix.lower() == ".pdf":
        with open_pdf(file_path) as pdf:
            if len(pdf) > MAX_OCR_PAGES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Document exceeds the {MAX_OCR_PAGES}-page processing limit."
                )

            for page_number, page in enumerate(pdf, start=1):
                text = page.get_text("text").strip()
                method = "pdf_text"
                regions = extract_pdf_text_regions(page)

                page_images = page.get_images(full=True)
                needs_ocr = not text or (page_images and len(text) < 120)
                if needs_ocr:
                    has_selectable_text = bool(text)
                    if page.rect.width * page.rect.height * 4 > MAX_IMAGE_PIXELS:
                        raise HTTPException(
                            status_code=400,
                            detail=(
                                f"Page {page_number} is too large to safely "
                                "render for OCR."
                            )
                        )
                    reader = get_ocr_reader()
                    pix = page.get_pixmap(
                        matrix=pymupdf.Matrix(2, 2),
                        alpha=False
                    )
                    image_array = np.frombuffer(
                        pix.samples, dtype=np.uint8
                    ).reshape(pix.height, pix.width, pix.n)

                    ocr_regions = recognize_image_regions(
                        reader,
                        image_array,
                        page.rect.width / pix.width,
                        page.rect.height / pix.height,
                        "PDF points, origin at top left"
                    )
                    if ocr_regions:
                        existing_text = text.casefold()
                        ocr_regions = [
                            region for region in ocr_regions
                            if region["text"]
                            and region["text"].casefold() not in existing_text
                        ]
                        regions.extend(ocr_regions)
                        ocr_text = "\n".join(
                            region["text"] for region in ocr_regions
                        )
                        text = "\n".join(part for part in (text, ocr_text) if part)
                    if not has_selectable_text:
                        method = "easyocr"
                    elif ocr_regions:
                        method = "pdf_text+easyocr"

                page_texts.append({
                    "page": page_number,
                    "text": text,
                    "method": method,
                    "regions": regions,
                    "ocr_confidence": (
                        round(
                            statistics.mean(
                                region["ocr_confidence"]
                                for region in regions
                                if region["ocr_confidence"] is not None
                            ),
                            4
                        )
                        if any(
                            region["ocr_confidence"] is not None
                            for region in regions
                        )
                        else None
                    )
                })

    else:
        try:
            with Image.open(file_path) as source_image:
                if source_image.width * source_image.height > MAX_IMAGE_PIXELS:
                    raise HTTPException(
                        status_code=400,
                        detail="Image is too large to safely process."
                    )
                image = source_image.convert("RGB")
                image_array = np.array(image)
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="Unable to read uploaded image."
            )

        if image_array.shape[0] * image_array.shape[1] > MAX_IMAGE_PIXELS:
            raise HTTPException(
                status_code=400,
                detail="Image is too large to safely process."
            )

        reader = get_ocr_reader()
        regions = recognize_image_regions(reader, image_array)

        page_texts.append({
            "page": 1,
            "text": "\n".join(region["text"] for region in regions),
            "method": "easyocr",
            "regions": regions,
            "ocr_confidence": (
                round(
                    statistics.mean(
                        region["ocr_confidence"] for region in regions
                    ),
                    4
                )
                if regions else None
            )
        })

    return page_texts


# =========================================================
# 6. DOCUMENT CLASSIFICATION
# =========================================================

DOCUMENT_KEYWORDS = {
    "educational": [
        "marks card", "marksheet", "mark sheet", "university",
        "student", "semester", "registration number",
        "hall ticket", "grade", "school", "college",
        "transcript", "certificate"
    ],
    "identity": [
        "aadhaar", "aadhar", "passport", "identity card",
        "date of birth", "pan card", "permanent account number",
        "voter id", "driving licence", "driving license"
    ],
    "financial": [
        "invoice", "receipt", "total amount", "transaction",
        "bank statement", "payment", "account number",
        "balance", "gst", "tax"
    ],
    "legal": [
        "agreement", "court", "affidavit", "legal notice",
        "petitioner", "respondent", "deed", "notary",
        "terms and conditions"
    ],
    "employment": [
        "appointment letter", "employment", "employee",
        "salary", "designation", "experience letter",
        "offer letter", "joining date"
    ],
    "application_form": [
        "application form", "applicant name", "application number",
        "application id", "personal details", "applicant signature"
    ],
    "government": [
        "government of", "department of", "republic of",
        "municipal corporation", "government certificate"
    ],
}


def classify_document(text):
    text_lower = text.lower()
    scores = {}

    for category, keywords in DOCUMENT_KEYWORDS.items():
        score = sum(
            1 for keyword in keywords
            if keyword in text_lower
        )
        if score:
            scores[category] = score

    if not scores:
        return {
            "document_type": "unclassified",
            "classification_scores": {},
            "classification_confidence": 0.0,
            "classification_method": "keyword_evidence",
            "classification_note": "No known document-category keywords were detected."
        }

    ranked = sorted(scores.items(), key=lambda item: item[1], reverse=True)
    top_category, top_score = ranked[0]

    # Call a document mixed when multiple categories have meaningful evidence.
    meaningful_categories = [
        category for category, score in ranked if score >= 2
    ]

    if len(meaningful_categories) >= 2:
        document_type = "mixed"
    elif len(ranked) > 1 and ranked[1][1] == top_score:
        document_type = "mixed"
    else:
        document_type = top_category

    return {
        "document_type": document_type,
        "classification_scores": scores,
        "classification_confidence": round(
            top_score / sum(scores.values()), 2
        ),
        "classification_method": "keyword_evidence",
        "classification_note": (
            "Heuristic keyword score, not a calibrated probability. "
            "Human review is required."
        )
    }


# =========================================================
# 7. STRUCTURED FIELD DEFINITIONS AND EXTRACTION
# =========================================================

FIELD_LABELS = {
    "applicant_name": [
        "applicant name", "full name", "student name",
        "customer name", "name of applicant", "name"
    ],
    "date_of_birth": [
        "date of birth", "birth date", "dob"
    ],
    "gender": ["gender", "sex"],
    "address": [
        "residential address", "permanent address",
        "communication address", "address"
    ],
    "mobile_number": [
        "mobile number", "phone number", "contact number",
        "mobile", "phone", "telephone"
    ],
    "email": ["email address", "e-mail address", "email", "e-mail"],
    "application_date": [
        "application date", "date of application", "submitted date"
    ],
    "application_number": [
        "application number", "application no", "application id"
    ],
    "document_number": [
        "document number", "certificate number", "id number",
        "reference number", "passport number"
    ],
    "pan_number": [
        "permanent account number", "pan number", "pan"
    ],
    "aadhaar_number": [
        "aadhaar number", "aadhar number", "aadhaar no", "aadhar no",
        "aadhaar", "aadhar", "unique identification number", "uid"
    ],
    "issue_date": ["issue date", "date of issue", "issued on"],
    "expiry_date": ["expiry date", "expiration date", "valid until", "valid through"],
    "registration_number": [
        "registration number", "registration no", "reg no"
    ],
    "roll_number": ["roll number", "roll no", "seat number"],
    "institution": [
        "institution", "university", "school name", "college name"
    ],
    "organization": [
        "organization", "organisation", "company name", "employer"
    ],
    "amount": [
        "total amount", "application amount", "loan amount", "amount"
    ],
}

# Longest labels are checked first so "student name" is not confused with "name".
LABEL_LOOKUP = sorted(
    [
        (label, field_name)
        for field_name, labels in FIELD_LABELS.items()
        for label in labels
    ],
    key=lambda item: len(item[0]),
    reverse=True
)


def find_evidence_region(page, value, evidence):
    normalized_value = re.sub(r"\s+", " ", str(value)).casefold()
    normalized_evidence = re.sub(r"\s+", " ", str(evidence)).casefold()
    for region in page.get("regions", []):
        region_text = re.sub(
            r"\s+", " ", region.get("text", "")
        ).casefold()
        if (
            normalized_value
            and normalized_value in region_text
        ) or (
            region_text
            and region_text in normalized_evidence
        ):
            return region
    return None


def add_extracted_field(fields, field_name, value, page, method,
                        evidence, confidence, evidence_region=None):
    value = str(value).strip().strip(" \t:=-,;.")
    if not value:
        return

    actual_ocr_confidence = (
        evidence_region.get("ocr_confidence")
        if evidence_region else None
    )
    item = {
        "value": value,
        "confidence": (
            actual_ocr_confidence
            if actual_ocr_confidence is not None
            else round(float(confidence), 2)
        ),
        "confidence_basis": (
            "easyocr_recognition"
            if actual_ocr_confidence is not None
            else "heuristic_extraction_score"
        ),
        "page": page["page"] if isinstance(page, dict) else page,
        "method": method,
        "evidence": evidence.strip(),
        "review_required": True,
        "human_verification_status": "requires_human_verification",
        "bbox": evidence_region.get("bbox") if evidence_region else None,
        "coordinate_system": (
            evidence_region.get("coordinate_system")
            if evidence_region else None
        )
    }

    fields.setdefault(field_name, [])

    # Avoid repeating the exact same value on the same page.
    duplicate = any(
        existing["value"].casefold() == value.casefold()
        and existing["page"] == page
        for existing in fields[field_name]
    )

    if not duplicate:
        fields[field_name].append(item)


def extract_structured_fields(page_texts):
    """
    Extracts multiple occurrences of labelled fields, plus common patterns.
    It does not guess a person's name from arbitrary unlabelled text.
    """

    extracted_fields = {}

    patterns = {
        "email": (
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            0.90
        ),
        "mobile_number": (
            r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)",
            0.85
        ),
        "date": (
            r"\b(?:\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}[/-]\d{1,2}[/-]\d{1,2})\b",
            0.80
        ),
        "website": (
            r"\b(?:https?://|www\.)[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?:/[^\s]*)?",
            0.85
        ),
    }

    for page in page_texts:
        page_number = page["page"]
        page_text = page["text"]
        method = page["method"]
        base_confidence = 0.90 if method == "pdf_text" else 0.72
        lines = [line.strip() for line in page_text.splitlines()]

        for index, line in enumerate(lines):
            if not line:
                continue

            # 1) Label and value on the same line:
            #    "Student Name: Ravi Kumar"
            #    "Student Name - Ravi Kumar"
            matched_label = False

            for label, field_name in LABEL_LOOKUP:
                label_pattern = (
                    r"^\s*" + re.escape(label) +
                    r"\s*(?:[:=\-]\s*|\s{2,})(.*)$"
                )

                match = re.match(
                    label_pattern, line, flags=re.IGNORECASE
                )

                if match:
                    value = match.group(1).strip()

                    # 2) Some forms put the value on the next line.
                    if not value and index + 1 < len(lines):
                        next_line = lines[index + 1].strip()
                        if next_line and not self_is_another_label(next_line):
                            value = next_line
                            evidence = line + " | " + next_line
                        else:
                            evidence = line
                    else:
                        evidence = line

                    add_extracted_field(
                        extracted_fields,
                        field_name,
                        value,
                        page,
                        method,
                        evidence,
                        base_confidence,
                        find_evidence_region(page, value, evidence)
                    )
                    matched_label = True
                    break

            # No generic guessing is done for unmatched lines.
            if matched_label:
                continue

        # Pattern-based extraction across the complete page text.
        for field_name, (pattern, confidence) in patterns.items():
            for match in re.finditer(pattern, page_text, re.IGNORECASE):
                value = match.group(0).strip()
                add_extracted_field(
                    extracted_fields,
                    field_name,
                    value,
                    page,
                    method,
                    value,
                    confidence if method == "pdf_text" else confidence - 0.15,
                    find_evidence_region(page, value, value)
                )

    return extracted_fields


def self_is_another_label(line):
    """Return True if a line appears to be another known field label."""
    candidate = line.strip().lower().rstrip(":=- ")
    return any(
        candidate == label
        or candidate.startswith(label + ":")
        or candidate.startswith(label + " -")
        for label, _field_name in LABEL_LOOKUP
    )


# =========================================================
# 8. HOME AND HEALTH APIs
# =========================================================

@app.get("/")
def home():
    return {
        "message": "FORENSAI is running!",
        "version": "3.2",
        "available_features": [
            "Document Upload",
            "PDF Text Extraction",
            "OCR Recognition",
            "Document Classification",
            "Structured Information Extraction",
            "SHA-256 Fingerprinting",
            "PDF Metadata Analysis",
            "Digital Forensic Analysis",
            "Visual Document Forensics",
            "Image Forensics",
            "PDF Report Generation",
            "Multi-document Investigation Dossiers",
            "Evidence Mapping",
            "Audit Trail"
        ]
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "authentication": "individual_accounts_with_revocable_expiring_jwts",
        "ocr_languages": configured_ocr_languages(),
        "ocr_engine": "EasyOCR",
        "pdf_engine": "PyMuPDF",
        "report_generator": "ReportLab",
        "structured_extraction": "enabled",
        "document_classification": "enabled",
        "multi_document_investigation": "enabled",
        "audit_trail": "enabled"
    }


@app.post("/auth/register")
def register_user(payload: CredentialsRequest):
    _jwt_secret()
    email = validate_email(payload.email)
    if forensic_database.get_user_by_email(email):
        raise HTTPException(status_code=409, detail="An account with that email already exists.")
    user_id = str(uuid4())
    try:
        user = forensic_database.create_user(
            user_id,
            email,
            hash_password(payload.password),
            role="investigator"
        )
    except sqlite3.IntegrityError as error:
        raise HTTPException(
            status_code=409,
            detail="An account with that email already exists."
        ) from error
    return issue_auth_response(user)


@app.post("/auth/login")
def login_user(payload: CredentialsRequest):
    _jwt_secret()
    email = validate_email(payload.email)
    user = forensic_database.get_user_by_email(email)
    if (
        user is None
        or not user["is_active"]
        or not verify_password(payload.password, user["password_hash"])
    ):
        raise HTTPException(
            status_code=401,
            detail="Email or password is incorrect.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return issue_auth_response(user)


@app.get("/auth/me")
def get_current_user(user=Depends(require_authenticated_user)):
    return {"user": public_user(user)}


@app.post("/auth/logout")
def logout_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_token_scheme),
    user=Depends(require_authenticated_user)
):
    claims = _decode_access_token(credentials.credentials)
    forensic_database.revoke_token(
        claims["jti"],
        user["user_id"],
        claims["exp"],
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        )
    )
    return {"message": "Signed out successfully."}


@app.get("/auth/admin/users", dependencies=[Depends(require_admin)])
def list_users():
    return {"users": forensic_database.list_users()}


@app.post("/auth/admin/users", dependencies=[Depends(require_admin)])
def create_managed_user(payload: AdminUserRequest):
    email = validate_email(payload.email)
    if forensic_database.get_user_by_email(email):
        raise HTTPException(status_code=409, detail="An account with that email already exists.")
    try:
        user = forensic_database.create_user(
            str(uuid4()),
            email,
            hash_password(payload.password),
            role=payload.role
        )
    except sqlite3.IntegrityError as error:
        raise HTTPException(
            status_code=409,
            detail="An account with that email already exists."
        ) from error
    return {"user": public_user(user)}


@app.patch("/auth/admin/users/{user_id}")
def update_managed_user(
    user_id: str,
    payload: UserUpdateRequest,
    admin=Depends(require_admin)
):
    target = forensic_database.get_user_by_id(user_id)
    if target is None:
        raise HTTPException(status_code=404, detail="User not found.")
    if payload.role is None and payload.is_active is None:
        raise HTTPException(
            status_code=400,
            detail="Provide a role or active-state update."
        )
    demotes_or_disables_admin = (
        target["role"] == "admin"
        and target["is_active"]
        and (
            payload.role == "investigator"
            or payload.is_active is False
        )
    )
    if demotes_or_disables_admin:
        if target["user_id"] == admin["user_id"]:
            raise HTTPException(
                status_code=400,
                detail="Administrators cannot demote or disable their own account."
            )
        if forensic_database.count_active_admins() <= 1:
            raise HTTPException(
                status_code=400,
                detail="At least one active administrator must remain."
            )
    forensic_database.update_user(
        user_id,
        role=payload.role,
        is_active=payload.is_active
    )
    return {"user": public_user(forensic_database.get_user_by_id(user_id))}


# =========================================================
# 9. DOCUMENT UPLOAD API
# =========================================================

@app.post("/upload")
async def upload_document(
    file: UploadFile = File(...),
    user=Depends(require_authenticated_user)
):
    extension = Path(file.filename or "").suffix.lower()

    if extension not in ALLOWED_TYPES:
        raise HTTPException(
            status_code=400,
            detail="Only PDF, JPG, JPEG and PNG files are allowed."
        )

    content = await file.read(MAX_FILE_SIZE + 1)

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=413,
            detail="File is too large. Maximum size is 15 MB."
        )

    if not content:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    signatures = {
        ".pdf": content.startswith(b"%PDF"),
        ".jpg": content.startswith(b"\xff\xd8\xff"),
        ".jpeg": content.startswith(b"\xff\xd8\xff"),
        ".png": content.startswith(b"\x89PNG\r\n\x1a\n")
    }

    if not signatures[extension]:
        raise HTTPException(
            status_code=400,
            detail="File content does not match its extension."
        )

    if extension == ".pdf":
        try:
            with pymupdf.open(stream=content, filetype="pdf") as pdf:
                if len(pdf) == 0:
                    raise ValueError("Empty PDF")
                if len(pdf) > MAX_OCR_PAGES:
                    raise HTTPException(
                        status_code=400,
                        detail=f"PDF exceeds the {MAX_OCR_PAGES}-page limit."
                    )
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="Invalid or corrupted PDF."
            )
    else:
        try:
            with Image.open(BytesIO(content)) as image:
                if image.width * image.height > MAX_IMAGE_PIXELS:
                    raise HTTPException(
                        status_code=400,
                        detail="Image dimensions exceed the processing limit."
                    )
                image.verify()
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(
                status_code=400,
                detail="Invalid or corrupted image."
            )

    document_id = str(uuid4())
    safe_filename = f"{document_id}{extension}"
    file_path = UPLOAD_DIR / safe_filename
    metadata_path = UPLOAD_DIR / f"{document_id}.json"
    file_path.write_bytes(content)
    try:
        source_filename = Path(file.filename or safe_filename).name
        uploaded_at = datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ).replace("+00:00", "Z")
        metadata_path.write_text(
            json.dumps(
                {
                    "filename": source_filename,
                    "file_type": extension
                },
                ensure_ascii=False
            ),
            encoding="utf-8"
        )
        forensic_database.save_document({
            "document_id": document_id,
            "source_filename": source_filename,
            "file_type": extension.lstrip("."),
            "file_size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "uploaded_at": uploaded_at
        }, owner_id=user["user_id"])
        record_audit_event(
            "document_uploaded",
            [document_id],
            {
                "file_type": extension,
                "file_size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest()
            }
        )
    except HTTPException:
        forensic_database.delete_document(document_id)
        file_path.unlink()
        if metadata_path.exists():
            metadata_path.unlink()
        raise
    except Exception as error:
        forensic_database.delete_document(document_id)
        file_path.unlink()
        if metadata_path.exists():
            metadata_path.unlink()
        raise HTTPException(
            status_code=500,
            detail="Unable to save uploaded document and its audit metadata."
        ) from error

    return {
        "message": "Document uploaded successfully!",
        "document_id": document_id,
        "filename": file.filename,
        "saved_as": safe_filename,
        "file_type": extension,
        "file_size": len(content)
    }


@app.get("/documents/{document_id}")
def get_document_details(document_id: str):
    file_path = find_uploaded_document(document_id)
    document = ensure_document_record(document_id, file_path)
    return {
        "document_id": document_id,
        "source_filename": document["source_filename"],
        "file_type": document["file_type"],
        "file_size_bytes": document["file_size_bytes"],
        "sha256": document["sha256"],
        "uploaded_at": document["uploaded_at"],
        "processing_status": document["processing_status"],
        "classification_override": document["classification_override"]
    }


@app.get("/documents/{document_id}/preview")
def preview_original_document(document_id: str):
    file_path = find_uploaded_document(document_id)
    source_filename = re.sub(
        r'[\r\n"]',
        "_",
        get_original_filename(file_path)
    )
    return Response(
        content=file_path.read_bytes(),
        media_type=ALLOWED_TYPES[file_path.suffix.lower()],
        headers={
            "Content-Disposition": f'inline; filename="{source_filename}"',
            "Cache-Control": "no-store"
        }
    )


@app.get("/classification/{document_id}")
def get_document_classification(document_id: str):
    file_path = find_uploaded_document(document_id)
    pages = extract_document_pages(file_path)
    predicted = classify_document(
        "\n\n".join(page["text"] for page in pages)
    )
    document = ensure_document_record(document_id, file_path)
    record_processing_event(document_id, "document_classification")
    override = document["classification_override"]
    return {
        "document_id": document_id,
        "predicted_document_type": predicted["document_type"],
        "document_type": override or predicted["document_type"],
        "classification_confidence": predicted["classification_confidence"],
        "classification_scores": predicted["classification_scores"],
        "classification_method": predicted["classification_method"],
        "classification_status": (
            "manually_corrected" if override else "automatically_predicted"
        ),
        "manual_override": override,
        "confidence_note": predicted["classification_note"]
    }


@app.put("/documents/{document_id}/classification")
def update_document_classification(
    document_id: str,
    payload: ClassificationRequest
):
    file_path = find_uploaded_document(document_id)
    ensure_document_record(document_id, file_path)
    category = payload.document_type.strip().lower()
    if category not in DOCUMENT_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Document type must be one of: {', '.join(sorted(DOCUMENT_TYPES))}."
        )
    forensic_database.update_document_classification(document_id, category)
    record_audit_event(
        "document_classification_corrected",
        [document_id],
        {"document_type": category}
    )
    return {
        "document_id": document_id,
        "document_type": category,
        "classification_status": "manually_corrected"
    }


# =========================================================
# 10. PDF TEXT EXTRACTION API
# =========================================================

@app.get("/extract/{document_id}")
def extract_document_text(document_id: str):
    file_path = find_uploaded_document(document_id)

    if file_path.suffix.lower() != ".pdf":
        raise HTTPException(
            status_code=400,
            detail="Text extraction currently supports PDF files only."
        )

    try:
        with open_pdf(file_path) as pdf:
            if len(pdf) > MAX_OCR_PAGES:
                raise HTTPException(
                    status_code=400,
                    detail=f"Document exceeds the {MAX_OCR_PAGES}-page limit."
                )

            extracted_pages = [
                {
                    "page": page_number,
                    "text": page.get_text("text").strip()
                }
                for page_number, page in enumerate(pdf, start=1)
            ]

        full_text = "\n\n".join(
            page["text"] for page in extracted_pages
        )

        record_processing_event(document_id, "pdf_text_extraction")
        return {
            "message": "Text extraction completed!",
            "document_id": document_id,
            "total_pages": len(extracted_pages),
            "extracted_text": full_text,
            "pages": extracted_pages,
            "ocr_required": not bool(full_text.strip())
        }

    except HTTPException:
        raise
    except Exception as error:
        logger.exception("Text extraction failed for document %s", document_id)
        raise HTTPException(
            status_code=500,
            detail="Text extraction failed."
        ) from error


# =========================================================
# 11. OCR RECOGNITION API
# =========================================================

@app.get("/ocr/{document_id}")
def perform_ocr(document_id: str):
    file_path = find_uploaded_document(document_id)

    try:
        pages = extract_document_pages(file_path)
        full_text = "\n\n".join(page["text"] for page in pages)

        record_processing_event(document_id, "ocr")
        return {
            "message": "OCR completed successfully!",
            "document_id": document_id,
            "total_pages": len(pages),
            "extracted_text": full_text,
            "pages": pages,
            "text_found": bool(full_text.strip())
        }

    except HTTPException:
        raise
    except Exception as error:
        logger.exception("OCR processing failed for document %s", document_id)
        raise HTTPException(
            status_code=500,
            detail="OCR processing failed."
        ) from error


# =========================================================
# 12. STRUCTURED INFORMATION EXTRACTION API
# =========================================================

@app.get("/structured-extraction/{document_id}")
def structured_information_extraction(document_id: str):
    file_path = find_uploaded_document(document_id)

    try:
        page_texts = extract_document_pages(file_path)
        full_text = "\n\n".join(page["text"] for page in page_texts)

        extracted_fields = extract_structured_fields(page_texts)
        predicted_classification = classify_document(full_text)
        document_record = ensure_document_record(document_id, file_path)
        classification_override = document_record["classification_override"]
        classification = dict(predicted_classification)
        if classification_override:
            classification["document_type"] = classification_override

        total_characters = len(full_text)
        total_field_values = sum(
            len(values) for values in extracted_fields.values()
        )

        record_processing_event(document_id, "structured_extraction")
        return {
            "message": "Structured information extraction completed!",
            "document_id": document_id,
            "total_pages": len(page_texts),
            "document_type": classification["document_type"],
            "predicted_document_type": predicted_classification["document_type"],
            "classification_confidence": predicted_classification[
                "classification_confidence"
            ],
            "classification_status": (
                "manually_corrected"
                if classification_override else "automatically_predicted"
            ),
            "classification_scores": classification["classification_scores"],
            "classification_note": classification["classification_note"],
            "extraction_status": (
                "fields_detected" if total_field_values
                else "no_fields_detected"
            ),
            "total_fields_extracted": total_field_values,
            "total_field_types": len(extracted_fields),
            "total_characters_processed": total_characters,
            "fields": extracted_fields,
            "document_structure": build_document_structure(
                page_texts, extracted_fields
            ),
            "page_references": [
                {
                    "page": page["page"],
                    "method": page["method"],
                    "characters": len(page["text"]),
                    "ocr_confidence": page.get("ocr_confidence"),
                    "regions_with_coordinates": sum(
                        region.get("bbox") is not None
                        for region in page.get("regions", [])
                    )
                }
                for page in page_texts
            ],
            "confidence_note": (
                "Confidence values are preliminary heuristic extraction "
                "scores, not calibrated probabilities and not proof that "
                "the extracted information is true. Human verification is required."
            )
        }

    except HTTPException:
        raise
    except Exception as error:
        logger.exception(
            "Structured extraction failed for document %s", document_id
        )
        raise HTTPException(
            status_code=500,
            detail="Structured extraction failed."
        ) from error


@app.get("/document-structure/{document_id}")
def analyze_document_structure(document_id: str):
    file_path = find_uploaded_document(document_id)
    pages = extract_document_pages(file_path)
    fields = extract_structured_fields(pages)
    structure = build_document_structure(pages, fields)
    record_processing_event(document_id, "document_structure_analysis")
    return {
        "document_id": document_id,
        "document_type": classify_document(
            "\n".join(page["text"] for page in pages)
        )["document_type"],
        **structure
    }


def build_document_structure(page_texts, fields):
    page_results = []

    for page in page_texts:
        regions = page.get("regions", [])
        font_sizes = [
            region["font_size"]
            for region in regions
            if region.get("font_size")
        ]
        median_font_size = (
            statistics.median(font_sizes) if font_sizes else 0
        )
        blocks = []
        missing_fields = []
        lines = [line.strip() for line in page["text"].splitlines() if line.strip()]

        for region in regions:
            text = region.get("text", "").strip()
            if not text:
                continue
            normalized = text.casefold()
            matched_label = next(
                (
                    (label, field_name)
                    for label, field_name in LABEL_LOOKUP
                    if normalized.startswith(label)
                ),
                None
            )
            if matched_label:
                block_type = "form_field"
            elif (
                region.get("bold")
                or (
                    median_font_size
                    and region.get("font_size")
                    and region["font_size"] >= median_font_size * 1.35
                )
            ):
                block_type = "heading"
            elif region.get("column_count", 1) > 1:
                block_type = "possible_table_row"
            else:
                block_type = "paragraph"

            blocks.append({
                "type": block_type,
                "text": text,
                "page": page["page"],
                "bbox": region.get("bbox"),
                "coordinate_system": region.get("coordinate_system"),
                "source": region.get("source"),
                "field": matched_label[1] if matched_label else None
            })

        for line_index, line in enumerate(lines):
            normalized_line = line.casefold()
            for label, field_name in LABEL_LOOKUP:
                if normalized_line == label or re.fullmatch(
                    re.escape(label) + r"\s*[:=\-]",
                    normalized_line
                ):
                    next_line_index = line_index + 1
                    has_following_value = (
                        next_line_index < len(lines)
                        and not self_is_another_label(lines[next_line_index])
                    )
                    extracted_on_page = any(
                        value["page"] == page["page"]
                        for value in fields.get(field_name, [])
                    )
                    if not has_following_value and not extracted_on_page:
                        missing_fields.append({
                            "field": field_name,
                            "label": label,
                            "page": page["page"],
                            "status": "label_without_extracted_value"
                        })
                    break

        duplicate_fields = []
        for field_name, values in fields.items():
            page_values = [
                value["value"] for value in values
                if value["page"] == page["page"]
            ]
            if len(page_values) > 1:
                duplicate_fields.append({
                    "field": field_name,
                    "values": page_values,
                    "page": page["page"],
                    "status": "multiple_extracted_values"
                })

        page_results.append({
            "page": page["page"],
            "extraction_method": page["method"],
            "ocr_confidence": page.get("ocr_confidence"),
            "blocks": blocks,
            "missing_fields": missing_fields,
            "duplicate_fields": duplicate_fields,
            "layout_note": (
                "Possible table rows are inferred from text-span layout; "
                "they are not verified table structures."
            )
        })

    return {
        "total_pages": len(page_texts),
        "pages": page_results,
        "unsupported_regions": [
            "Signature and stamp detection is not implemented."
        ],
        "limitations": (
            "Headings and possible table rows use text/font layout heuristics. "
            "A region absent from extraction is not necessarily absent from the source."
        )
    }


# =========================================================
# 13. SHA-256 FINGERPRINT API
# =========================================================

@app.get("/fingerprint/{document_id}")
def document_fingerprint(document_id: str):
    file_path = find_uploaded_document(document_id)

    try:
        fingerprint = get_file_hash(file_path)
        record_processing_event(document_id, "sha256_fingerprint")
        return {
            "message": "Document fingerprint generated successfully!",
            "document_id": document_id,
            "algorithm": "SHA-256",
            "hash": fingerprint,
            "file_size": file_path.stat().st_size
        }
    except Exception as error:
        logger.exception("Fingerprint generation failed for document %s", document_id)
        raise HTTPException(
            status_code=500,
            detail="Fingerprint generation failed."
        ) from error


# =========================================================
# 14. PDF METADATA ANALYSIS API
# =========================================================

@app.get("/metadata/{document_id}")
def analyze_document_metadata(document_id: str):
    file_path = find_uploaded_document(document_id)

    if file_path.suffix.lower() != ".pdf":
        raise HTTPException(
            status_code=400,
            detail="Metadata analysis supports PDF files only."
        )

    try:
        with open_pdf(file_path) as pdf:
            metadata = pdf.metadata or {}
            page_information = []
            total_embedded_images = 0

            for page_number, page in enumerate(pdf, start=1):
                images = page.get_images(full=True)
                total_embedded_images += len(images)

                page_information.append({
                    "page": page_number,
                    "width": round(page.rect.width, 2),
                    "height": round(page.rect.height, 2),
                    "rotation": page.rotation,
                    "text_characters": len(page.get_text("text")),
                    "embedded_images": len(images)
                })

            metadata_result = {
                "format": get_metadata_value(metadata.get("format")),
                "title": get_metadata_value(metadata.get("title")),
                "author": get_metadata_value(metadata.get("author")),
                "subject": get_metadata_value(metadata.get("subject")),
                "keywords": get_metadata_value(metadata.get("keywords")),
                "creator": get_metadata_value(metadata.get("creator")),
                "producer": get_metadata_value(metadata.get("producer")),
                "creationDate": get_metadata_value(metadata.get("creationDate")),
                "modDate": get_metadata_value(metadata.get("modDate")),
                "trapped": get_metadata_value(metadata.get("trapped")),
                "encryption": pdf.is_encrypted
            }

            record_processing_event(document_id, "pdf_metadata_analysis")
            return {
                "message": "PDF metadata analysis completed!",
                "document_id": document_id,
                "file_type": "PDF",
                "file_size_bytes": file_path.stat().st_size,
                "metadata": metadata_result,
                "total_pages": len(pdf),
                "total_embedded_images": total_embedded_images,
                "page_information": page_information
            }

    except HTTPException:
        raise
    except Exception as error:
        logger.exception("Metadata analysis failed for document %s", document_id)
        raise HTTPException(
            status_code=500,
            detail="Metadata analysis failed."
        ) from error


# =========================================================
# 15. DIGITAL FORENSIC ANALYSIS API
# =========================================================

@app.get("/forensics/{document_id}")
def digital_forensic_analysis(document_id: str):
    file_path = find_uploaded_document(document_id)

    if file_path.suffix.lower() != ".pdf":
        raise HTTPException(
            status_code=400,
            detail="Digital PDF forensic analysis supports PDF files only."
        )

    try:
        file_hash = get_file_hash(file_path)
        file_size = file_path.stat().st_size

        with open_pdf(file_path) as pdf:
            metadata = pdf.metadata or {}
            unique_fonts = set()
            total_images = 0
            total_annotations = 0
            total_text_blocks = 0

            for page in pdf:
                total_images += len(page.get_images(full=True))
                total_annotations += len(list(page.annots() or []))
                text_data = page.get_text("dict")

                for block in text_data.get("blocks", []):
                    if block.get("type") != 0:
                        continue

                    total_text_blocks += 1

                    for line in block.get("lines", []):
                        for span in line.get("spans", []):
                            if span.get("font"):
                                unique_fonts.add(span["font"])

            record_processing_event(document_id, "digital_forensic_analysis")
            return {
                "message": "Digital forensic analysis completed!",
                "document_id": document_id,
                "document_fingerprint": {
                    "algorithm": "SHA-256",
                    "hash": file_hash
                },
                "document_information": {
                    "file_type": file_path.suffix.upper().replace(".", ""),
                    "file_size_bytes": file_size,
                    "total_pages": len(pdf),
                    "producer": get_metadata_value(metadata.get("producer")),
                    "repaired_by_parser": pdf.is_repaired,
                    "encrypted": pdf.is_encrypted
                },
                "document_statistics": {
                    "unique_fonts": sorted(unique_fonts),
                    "total_fonts": len(unique_fonts),
                    "total_images": total_images,
                    "total_annotations": total_annotations,
                    "total_text_blocks": total_text_blocks
                },
                "metadata": metadata
            }

    except HTTPException:
        raise
    except Exception as error:
        logger.exception("Forensic analysis failed for document %s", document_id)
        raise HTTPException(
            status_code=500,
            detail="Forensic analysis failed."
        ) from error


# =========================================================
# 16. VISUAL DOCUMENT FORENSICS API
# =========================================================

@app.get("/visual-forensics/{document_id}")
def visual_document_forensics(document_id: str):
    file_path = find_uploaded_document(document_id)

    if file_path.suffix.lower() != ".pdf":
        raise HTTPException(
            status_code=400,
            detail="Visual document forensics supports PDF files only."
        )

    try:
        findings = []
        document_fonts = set()
        font_sizes = []
        page_results = []

        with open_pdf(file_path) as pdf:
            for page_number, page in enumerate(pdf, start=1):
                page_fonts = set()
                page_sizes = []
                page_spans = []
                text_data = page.get_text("dict")

                for block in text_data.get("blocks", []):
                    if block.get("type") != 0:
                        continue

                    for line in block.get("lines", []):
                        for span in line.get("spans", []):
                            font = span.get("font", "")
                            size = float(span.get("size", 0))

                            if font:
                                page_fonts.add(font)
                                document_fonts.add(font)

                            if size > 0:
                                font_sizes.append(size)
                                page_sizes.append(size)
                                page_spans.append({
                                    "size": size,
                                    "font": font,
                                    "text": span.get("text", ""),
                                    "bbox": span.get("bbox")
                                })

                median_size = (
                    statistics.median(page_sizes) if page_sizes else 0
                )

                unusual_sizes = []
                unusual_regions = []
                unusual_scores = []
                unusual_disclaimer_flags = []

                if median_size > 0:
                    for span in page_spans:
                        size = span["size"]
                        if size > median_size * 2.5 or size < median_size * 0.4:
                            unusual_sizes.append(round(size, 2))
                            unusual_scores.append(
                                max(size / median_size, median_size / size)
                            )
                            disclaimer_match = SYNTHETIC_DISCLAIMER_PATTERN.search(
                                span["text"]
                            )
                            unusual_disclaimer_flags.append(
                                disclaimer_match is not None
                            )
                            if span["bbox"]:
                                unusual_regions.append({
                                    "page": page_number,
                                    "bbox": [round(value, 2) for value in span["bbox"]],
                                    "coordinate_system": "PDF points, origin at top left",
                                    "text_excerpt": span["text"][:160],
                                    "font": span["font"],
                                    "observed_font_size": round(size, 2),
                                    "context": (
                                        "prominent_synthetic_disclaimer"
                                        if disclaimer_match else None
                                    ),
                                    "disclaimer_marker": (
                                        disclaimer_match.group(0)
                                        if disclaimer_match else None
                                    )
                                })

                    if unusual_sizes:
                        finding_id = str(uuid4())
                        disclaimer_only = (
                            bool(unusual_disclaimer_flags)
                            and all(unusual_disclaimer_flags)
                        )
                        findings.append({
                            "finding_id": finding_id,
                            "source_document_id": document_id,
                            "page": page_number,
                            "type": "Unusual font size",
                            "severity": "LOW",
                            "observed_size": unusual_sizes[0],
                            "typical_size": round(median_size, 2),
                            "heuristic_score": round(
                                max(unusual_scores), 2
                            ),
                            "analysis_method": (
                                "relative_pdf_font_size_screening"
                            ),
                            "description": (
                                "Text font size differs significantly "
                                "from the page median."
                                + (
                                    " The cited outlier is prominent synthetic "
                                    "or demo disclaimer text, so this observation "
                                    "is retained but excluded from the heuristic "
                                    "risk score."
                                    if disclaimer_only else ""
                                )
                            ),
                            "recommended_action": (
                                (
                                    "Confirm the disclaimer is intentional; "
                                    "do not interpret its typography as a "
                                    "manipulation indicator."
                                    if disclaimer_only else
                                    "Inspect each cited region in context and "
                                    "compare it with the original document."
                                )
                            ),
                            "regions": unusual_regions,
                            "evidence": unusual_regions,
                            "observation_status": (
                                "contextualized_observation"
                                if disclaimer_only else "screening_indicator"
                            ),
                            "risk_assessment_excluded": disclaimer_only,
                            "risk_exclusion_reason": (
                                "All cited outlier regions contain prominent "
                                "synthetic/demo disclaimer text."
                                if disclaimer_only else None
                            )
                        })

                page_results.append({
                    "page": page_number,
                    "font_count": len(page_fonts),
                    "fonts": sorted(page_fonts),
                    "median_font_size": round(median_size, 2),
                    "unusual_font_sizes": unusual_sizes,
                    "text_characters": len(page.get_text("text"))
                })

            total_findings = len(findings)

            record_processing_event(document_id, "visual_forensic_analysis")
            return {
                "message": "Visual document analysis completed!",
                "document_id": document_id,
                "analysis_type": "PDF Visual Forensics",
                "total_pages": len(pdf),
                "document_fonts": sorted(document_fonts),
                "total_unique_fonts": len(document_fonts),
                "findings_summary": {
                    "total_findings": total_findings,
                    "high": 0,
                    "medium": 0,
                    "low": total_findings
                },
                "findings": findings,
                "page_analysis": page_results,
                "font_statistics": {
                    "total_font_size_samples": len(font_sizes),
                    "average_font_size": (
                        round(statistics.mean(font_sizes), 2)
                        if font_sizes else 0
                    ),
                    "median_font_size": (
                        round(statistics.median(font_sizes), 2)
                        if font_sizes else 0
                    )
                },
                "disclaimer": (
                    "Visual anomalies are screening indicators only. "
                    "Different fonts and font sizes may be legitimate. "
                    "These results do not prove document forgery."
                )
            }

    except HTTPException:
        raise
    except Exception as error:
        logger.exception(
            "Visual forensic analysis failed for document %s", document_id
        )
        raise HTTPException(
            status_code=500,
            detail="Visual forensic analysis failed."
        ) from error


@app.get("/evidence-preview/{document_id}/{page_number}")
def evidence_preview(
    document_id: str,
    page_number: int,
    bbox: str | None = None
):
    file_path = find_uploaded_document(document_id)

    try:
        target_bbox = None
        if bbox is not None:
            try:
                coordinates = [float(value) for value in bbox.split(",")]
            except ValueError as error:
                raise HTTPException(
                    status_code=400,
                    detail="Evidence bounding box must contain four numbers."
                ) from error
            if (
                len(coordinates) != 4
                or coordinates[2] <= coordinates[0]
                or coordinates[3] <= coordinates[1]
            ):
                raise HTTPException(
                    status_code=400,
                    detail="Evidence bounding box is invalid."
                )
            target_bbox = coordinates

        if file_path.suffix.lower() != ".pdf":
            if page_number != 1:
                raise HTTPException(
                    status_code=404,
                    detail="Image documents contain only page 1."
                )
            with Image.open(file_path) as source_image:
                if source_image.width * source_image.height > MAX_IMAGE_PIXELS:
                    raise HTTPException(
                        status_code=400,
                        detail="Image is too large to safely preview."
                    )
                preview = source_image.convert("RGB")
            draw = ImageDraw.Draw(preview)
            if target_bbox:
                draw.rectangle(
                    tuple(round(value) for value in target_bbox),
                    outline=(220, 38, 38),
                    width=4
                )
            image_buffer = BytesIO()
            preview.save(image_buffer, format="PNG")
            record_audit_event(
                "evidence_preview_viewed",
                [document_id],
                {"page": page_number, "highlighted_region": bool(target_bbox)}
            )
            return Response(
                content=image_buffer.getvalue(),
                media_type="image/png",
                headers={"Cache-Control": "no-store"}
            )

        with open_pdf(file_path) as pdf:
            if page_number < 1 or page_number > len(pdf):
                raise HTTPException(
                    status_code=404,
                    detail="Requested page is outside the document."
                )

            page = pdf[page_number - 1]
            scale = 1.5
            if (
                page.rect.width * page.rect.height * scale * scale
                > MAX_IMAGE_PIXELS
            ):
                raise HTTPException(
                    status_code=400,
                    detail="Page is too large to safely render an evidence preview."
                )
            spans = []
            text_data = page.get_text("dict")

            for block in text_data.get("blocks", []):
                if block.get("type") != 0:
                    continue
                for line in block.get("lines", []):
                    spans.extend(line.get("spans", []))

            font_sizes = [
                float(span.get("size", 0))
                for span in spans
                if float(span.get("size", 0)) > 0
            ]
            median_size = statistics.median(font_sizes) if font_sizes else 0
            pixmap = page.get_pixmap(
                matrix=pymupdf.Matrix(scale, scale),
                alpha=False
            )
            preview = Image.frombytes(
                "RGB",
                (pixmap.width, pixmap.height),
                pixmap.samples
            )
            draw = ImageDraw.Draw(preview)
            if target_bbox:
                rectangle = tuple(
                    round(value * scale) for value in target_bbox
                )
                draw.rectangle(rectangle, outline=(220, 38, 38), width=4)
            for span in spans:
                size = float(span.get("size", 0))
                bbox = span.get("bbox")
                if (
                    median_size > 0
                    and bbox
                    and (size > median_size * 2.5 or size < median_size * 0.4)
                ):
                    rectangle = tuple(
                        round(float(value) * scale) for value in bbox
                    )
                    draw.rectangle(rectangle, outline=(220, 38, 38), width=4)

            image_buffer = BytesIO()
            preview.save(image_buffer, format="PNG")
            record_audit_event(
                "evidence_preview_viewed",
                [document_id],
                {"page": page_number, "highlighted_region": bool(target_bbox)}
            )
            return Response(
                content=image_buffer.getvalue(),
                media_type="image/png",
                headers={"Cache-Control": "no-store"}
            )

    except HTTPException:
        raise
    except Exception as error:
        logger.exception(
            "Evidence preview generation failed for document %s", document_id
        )
        raise HTTPException(
            status_code=500,
            detail="Evidence preview generation failed."
        ) from error


# =========================================================
# 17. IMAGE MANIPULATION FORENSICS API
# =========================================================

@app.get("/image-forensics/{document_id}")
def image_manipulation_forensics(document_id: str):
    file_path = find_uploaded_document(document_id)

    if file_path.suffix.lower() != ".pdf":
        raise HTTPException(
            status_code=400,
            detail="Image forensics currently supports embedded PDF images only."
        )

    try:
        findings = []
        image_hashes = {}
        image_statistics = []
        total_images = 0

        with open_pdf(file_path) as pdf:
            for page_number, page in enumerate(pdf, start=1):
                for image_info in page.get_images(full=True):
                    xref = image_info[0]
                    extracted_image = pdf.extract_image(xref)
                    image_bytes = extracted_image["image"]

                    image_hash = hashlib.sha256(image_bytes).hexdigest()
                    width = extracted_image["width"]
                    height = extracted_image["height"]
                    image_extension = extracted_image["ext"]

                    total_images += 1

                    image_statistics.append({
                        "page": page_number,
                        "image_xref": xref,
                        "width": width,
                        "height": height,
                        "format": image_extension,
                        "file_size_bytes": len(image_bytes),
                        "sha256": image_hash
                    })

                    if image_hash in image_hashes:
                        findings.append({
                            "finding_id": str(uuid4()),
                            "source_document_id": document_id,
                            "page": page_number,
                            "image_xref": xref,
                            "sha256": image_hash,
                            "type": "Duplicate embedded image",
                            "severity": "LOW",
                            "heuristic_score": 1.0,
                            "analysis_method": (
                                "exact_sha256_duplicate_embedded_image"
                            ),
                            "description": (
                                "An image with identical binary content "
                                "was found elsewhere in the PDF."
                            ),
                            "recommended_action": (
                                "Compare both cited images in the original "
                                "PDF; repeated logos and design elements may "
                                "be legitimate."
                            ),
                            "matching_image": image_hashes[image_hash]
                        })
                    else:
                        image_hashes[image_hash] = {
                            "page": page_number,
                            "image_xref": xref,
                            "sha256": image_hash
                        }

        duplicate_count = len(findings)

        record_processing_event(document_id, "image_forensic_analysis")
        return {
            "message": "Image forensic analysis completed!",
            "document_id": document_id,
            "analysis_type": "PDF Image Manipulation Screening",
            "total_images": total_images,
            "image_statistics": image_statistics,
            "findings": findings,
            "total_findings": duplicate_count,
            "duplicate_images": duplicate_count,
            "assessment": (
                "No exact duplicate embedded images were detected."
                if duplicate_count == 0
                else "Exact duplicate embedded images were detected. "
                     "Further examination is recommended."
            ),
            "disclaimer": (
                "This endpoint checks exact duplicate image content. "
                "It does not perform pixel-level similarity analysis, ELA, "
                "object manipulation detection or prove forgery. Repeated "
                "logos, photographs and design elements may be legitimate."
            )
        }

    except HTTPException:
        raise
    except Exception as error:
        logger.exception(
            "Image forensic analysis failed for document %s", document_id
        )
        raise HTTPException(
            status_code=500,
            detail="Image forensic analysis failed."
        ) from error


# =========================================================
# 18. PDF FORENSIC REPORT GENERATOR
# =========================================================

@app.get("/report/{document_id}")
def generate_forensic_report(document_id: str):
    file_path = find_uploaded_document(document_id)

    if file_path.suffix.lower() != ".pdf":
        raise HTTPException(
            status_code=400,
            detail="PDF report generation supports PDF files only."
        )

    try:
        pdf_bytes = file_path.read_bytes()
        file_hash = hashlib.sha256(pdf_bytes).hexdigest()

        page_details = []
        metadata = {}
        font_names = set()
        total_images = 0
        total_annotations = 0

        with open_pdf(file_path) as pdf:
            total_pages = len(pdf)
            metadata = pdf.metadata or {}

            for page_number, page in enumerate(pdf, start=1):
                text = page.get_text("text")
                images = page.get_images(full=True)
                total_images += len(images)

                annotations = list(page.annots() or [])
                total_annotations += len(annotations)

                text_data = page.get_text("dict")
                for block in text_data.get("blocks", []):
                    if block.get("type") != 0:
                        continue
                    for line in block.get("lines", []):
                        for span in line.get("spans", []):
                            if span.get("font"):
                                font_names.add(span["font"])

                page_details.append([
                    str(page_number),
                    str(len(text)),
                    str(len(images))
                ])

        report_path = REPORT_DIR / f"Forensic_Report_{document_id}.pdf"

        doc = SimpleDocTemplate(
            str(report_path),
            pagesize=A4,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "ReportTitle",
            parent=styles["Title"],
            alignment=1,
            textColor=colors.darkblue,
            fontSize=17
        )
        small_style = ParagraphStyle(
            "SmallText",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
            wordWrap="CJK"
        )

        story = [
            Paragraph("FORENSAI DOCUMENT INTELLIGENCE", title_style),
            Spacer(1, 10),
            Paragraph("DIGITAL FORENSIC INVESTIGATION REPORT", styles["Heading2"]),
            Spacer(1, 20),
            Paragraph("1. DOCUMENT INFORMATION", styles["Heading2"])
        ]

        report_info = [
            ["Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Document ID", document_id],
            ["File Name", get_original_filename(file_path)],
            ["File Type", "PDF"],
            ["File Size", f"{len(pdf_bytes)} bytes"],
            ["Total Pages", str(total_pages)]
        ]

        info_table = Table(report_info, colWidths=[150, 340])
        info_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.lightgrey),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP")
        ]))
        story.extend([info_table, Spacer(1, 20)])

        story.append(Paragraph("2. DOCUMENT FINGERPRINT", styles["Heading2"]))
        story.append(Paragraph("<b>Algorithm:</b> SHA-256", styles["Normal"]))
        story.append(Spacer(1, 5))
        story.append(Paragraph("<b>Hash:</b> " + escape(file_hash), small_style))
        story.append(Spacer(1, 20))

        story.append(Paragraph("3. PDF METADATA ANALYSIS", styles["Heading2"]))
        metadata_rows = [[
            Paragraph("<b>Metadata Field</b>", small_style),
            Paragraph("<b>Value</b>", small_style)
        ]]

        for key, value in metadata.items():
            metadata_rows.append([
                Paragraph(escape(str(key)), small_style),
                Paragraph(escape(get_metadata_value(value)), small_style)
            ])

        metadata_table = Table(
            metadata_rows, colWidths=[150, 340], repeatRows=1
        )
        metadata_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP")
        ]))
        story.extend([metadata_table, Spacer(1, 20)])

        story.append(Paragraph("4. PAGE-BY-PAGE ANALYSIS", styles["Heading2"]))
        page_table = [["Page", "Text Characters", "Embedded Images"]]
        page_table.extend(page_details)

        page_analysis = Table(
            page_table, colWidths=[100, 170, 170], repeatRows=1
        )
        page_analysis.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 8),
            ("ALIGN", (0, 0), (-1, -1), "CENTER")
        ]))
        story.extend([page_analysis, Spacer(1, 20)])

        forensic_rows = [
            ["Analysis", "Result"],
            ["Unique Fonts", str(len(font_names))],
            ["Font Names", ", ".join(sorted(font_names)) or "None"],
            ["Total Embedded Images", str(total_images)],
            ["Total Annotations", str(total_annotations)],
            ["PDF Encrypted", str(metadata.get("encryption", "Unknown"))]
        ]

        forensic_table = Table(
            forensic_rows, colWidths=[150, 340], repeatRows=1
        )
        forensic_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("PADDING", (0, 0), (-1, -1), 7),
            ("VALIGN", (0, 0), (-1, -1), "TOP")
        ]))
        story.append(KeepTogether([
            Paragraph("5. DIGITAL FORENSIC STATISTICS", styles["Heading2"]),
            forensic_table,
            Spacer(1, 20)
        ]))

        story.append(Paragraph("6. INVESTIGATION SUMMARY", styles["Heading2"]))
        summary = (
            "The document SHA-256 fingerprint, PDF metadata, page-level "
            "statistics, font information, embedded image counts and "
            "annotation counts have been collected for this investigation report."
        )
        story.append(Paragraph(summary, styles["Normal"]))
        story.append(Spacer(1, 15))

        disclaimer = (
            "<b>DISCLAIMER:</b> This report provides technical document "
            "information. It does not independently establish whether a "
            "document is genuine, forged or manipulated. Additional forensic "
            "verification may be required."
        )
        story.append(Paragraph(disclaimer, styles["Normal"]))

        doc.build(story)

        if not report_path.is_file():
            raise RuntimeError("Report file was not created.")

        record_audit_event(
            "document_report_generated",
            [document_id],
            {"format": "pdf"}
        )
        return FileResponse(
            path=str(report_path),
            media_type="application/pdf",
            filename=f"Forensic_Report_{document_id}.pdf"
        )

    except HTTPException:
        raise
    except Exception as error:
        logger.exception("Report generation failed for document %s", document_id)
        raise HTTPException(
            status_code=500,
            detail="Report generation failed."
        ) from error


def normalized_field_value(value):
    normalized = unicodedata.normalize("NFKC", str(value)).casefold()
    return " ".join(re.findall(r"\w+", normalized, flags=re.UNICODE))


def is_potential_name_variation(field_name, occurrences):
    if field_name not in {"applicant_name", "full_name", "name"}:
        return False

    values_by_document = {}
    for occurrence in occurrences:
        values_by_document.setdefault(
            occurrence["document_id"], set()
        ).add(normalized_field_value(occurrence["value"]))

    if len(values_by_document) < 2:
        return False

    document_values = [
        next(iter(values))
        for values in values_by_document.values()
        if len(values) == 1
    ]
    if (
        len(document_values) != len(values_by_document)
        or len(set(document_values)) < 2
    ):
        return False

    return all(
        SequenceMatcher(None, left, right).ratio() >= 0.88
        for index, left in enumerate(document_values)
        for right in document_values[index + 1:]
    )


def build_risk_assessment(findings):
    severity_points = {"HIGH": 35, "MEDIUM": 20, "LOW": 5}
    contributions = [
        {
            "finding_id": finding["finding_id"],
            "type": finding["type"],
            "severity": finding.get("severity", "LOW"),
            "points": severity_points.get(
                finding.get("severity", "LOW").upper(), 0
            ) if not finding.get("risk_assessment_excluded") else 0,
            "evidence": finding.get("evidence", []),
            "excluded_from_score": bool(
                finding.get("risk_assessment_excluded")
            ),
            "exclusion_reason": finding.get("risk_exclusion_reason")
        }
        for finding in findings
    ]
    score = min(100, sum(item["points"] for item in contributions))
    has_risk_contributing_findings = any(
        item["points"] > 0 for item in contributions
    )
    if score >= 60:
        category = "HIGH RISK"
    elif score >= 25:
        category = "MEDIUM RISK"
    elif has_risk_contributing_findings:
        category = "NEEDS MANUAL REVIEW"
    else:
        category = "LOW RISK"

    return {
        "score": score,
        "category": category,
        "method": "severity_weighted_heuristic",
        "finding_contributions": contributions,
        "limitations": [
            "This score ranks detected review indicators; it is not a probability.",
            "A higher score is not proof of forgery, fraud, or identity mismatch.",
            "OCR errors, document type differences, and false positives can affect the score.",
            "Prominent synthetic/demo disclaimer typography is retained as an observation and excluded from the score when all cited outlier regions match disclaimer markers.",
            "Investigators must review original documents and supporting evidence."
        ],
        "recommended_next_steps": (
            ["Review cited evidence and confirm document relationships."]
            if findings else
            ["No automated indicators were found; this does not establish authenticity."]
        )
    }


def parse_document_date(value):
    for date_format in (
        "%d/%m/%Y",
        "%d-%m-%Y",
        "%d/%m/%y",
        "%Y-%m-%d",
        "%Y/%m/%d"
    ):
        try:
            return datetime.strptime(value.strip(), date_format).date()
        except ValueError:
            continue
    return None


def normalized_comparison_value(field_name, value):
    if field_name in {
        "date_of_birth",
        "issue_date",
        "expiry_date",
        "application_date"
    }:
        parsed_date = parse_document_date(str(value))
        if parsed_date:
            return parsed_date.isoformat()
    return normalized_field_value(value)


def load_investigation_dossier(investigation_id, owner_id=None):
    try:
        UUID(investigation_id)
    except (ValueError, TypeError, AttributeError) as error:
        raise HTTPException(
            status_code=400,
            detail="Invalid investigation ID."
        ) from error

    dossier = forensic_database.get_investigation(investigation_id)
    if dossier:
        if owner_id:
            forensic_database.assign_investigation_owner(
                investigation_id,
                owner_id
            )
        return dossier

    dossier_path = REPORT_DIR / f"Investigation_Dossier_{investigation_id}.json"
    if not dossier_path.is_file():
        raise HTTPException(status_code=404, detail="Investigation not found.")

    try:
        dossier = json.loads(dossier_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to read the saved investigation dossier."
        ) from error
    try:
        document_ids = []
        for document in dossier["document_overview"]["documents"]:
            document_id = document["document_id"]
            file_path = find_uploaded_document(document_id)
            ensure_document_record(document_id, file_path)
            document_ids.append(document_id)
        forensic_database.save_investigation(
            dossier,
            document_ids,
            owner_id=owner_id
        )
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to migrate the saved investigation into SQLite."
        ) from error
    return dossier


@app.post("/investigations")
def create_investigation(
    payload: InvestigationRequest,
    user=Depends(require_authenticated_user)
):
    document_ids = payload.document_ids
    file_paths = {}
    for document_id in document_ids:
        validate_document_id(document_id)
        if document_id in file_paths:
            raise HTTPException(
                status_code=400,
                detail="Document IDs in an investigation must be unique."
            )
        file_paths[document_id] = None

    for document_id in document_ids:
        document_record = forensic_database.get_document(document_id)
        if (
            document_record is None
            or (
                document_record["owner_id"] != user["user_id"]
                and user["role"] != "admin"
            )
        ):
            if user["role"] == "admin" and document_record is None:
                file_path = find_uploaded_document(document_id)
                document_record = ensure_document_record(document_id, file_path)
            else:
                raise HTTPException(
                    status_code=404,
                    detail="One or more uploaded documents were not found."
                )
        file_paths[document_id] = find_uploaded_document(document_id)
        document_record = ensure_document_record(
            document_id,
            file_paths[document_id]
        )
        if (
            document_record["owner_id"] != user["user_id"]
            and user["role"] != "admin"
        ):
            raise HTTPException(
                status_code=404,
                detail="One or more uploaded documents were not found."
            )

    document_results = []
    findings = []
    field_occurrences = {}

    for document_id, file_path in file_paths.items():
        page_texts = extract_document_pages(file_path)
        full_text = "\n\n".join(page["text"] for page in page_texts)
        fields = extract_structured_fields(page_texts)
        predicted_classification = classify_document(full_text)
        document_record = forensic_database.get_document(document_id)
        classification_override = (
            document_record["classification_override"]
            if document_record else None
        )
        classification = dict(predicted_classification)
        if classification_override:
            classification["document_type"] = classification_override
        document_hash = get_file_hash(file_path)

        overview = {
            "document_id": document_id,
            "source_filename": get_original_filename(file_path),
            "file_type": file_path.suffix.lower().lstrip("."),
            "file_size_bytes": file_path.stat().st_size,
            "sha256": document_hash,
            "total_pages": len(page_texts),
            "document_type": classification["document_type"],
            "predicted_document_type": predicted_classification["document_type"],
            "classification_confidence": predicted_classification[
                "classification_confidence"
            ],
            "classification_status": (
                "manually_corrected"
                if classification_override else "automatically_predicted"
            ),
            "classification_scores": classification["classification_scores"],
            "processing_status": "completed"
        }
        structure = build_document_structure(page_texts, fields)

        evidence = []
        for field_name, values in fields.items():
            for value in values:
                reference = {
                    "document_id": document_id,
                    "source_filename": overview["source_filename"],
                    "field": field_name,
                    "value": value["value"],
                    "confidence": value["confidence"],
                    "confidence_basis": value["confidence_basis"],
                    "page": value["page"],
                    "method": value["method"],
                    "evidence_text": value["evidence"],
                    "bbox": value["bbox"],
                    "coordinate_system": value["coordinate_system"],
                    "human_verification_status": value[
                        "human_verification_status"
                    ]
                }
                evidence.append(reference)
                field_occurrences.setdefault(field_name, []).append(reference)

            distinct_values = {
                normalized_comparison_value(field_name, value["value"])
                for value in values
            }
            if len(distinct_values) > 1:
                findings.append({
                    "finding_id": str(uuid4()),
                    "type": "within_document_field_conflict",
                    "status": "detected_inconsistency",
                    "severity": "MEDIUM",
                    "analysis_method": "within_document_field_value_comparison",
                    "field": field_name,
                    "explanation": (
                        f"Different values for {field_name.replace('_', ' ')} "
                        "were extracted from this document."
                    ),
                    "suggested_verification": (
                        "Review each cited page and confirm the correct value "
                        "with an authorized source."
                    ),
                    "confidence": round(
                        min(value["confidence"] for value in values), 2
                    ),
                    "evidence": [
                        item for item in evidence
                        if item["field"] == field_name
                    ]
                })

        if file_path.suffix.lower() == ".pdf":
            visual_analysis = visual_document_forensics(document_id)
            for visual_finding in visual_analysis["findings"]:
                regions = visual_finding.get("regions", [])
                findings.append({
                    "finding_id": visual_finding["finding_id"],
                    "type": "visual_font_size_screening",
                    "status": visual_finding.get(
                        "observation_status",
                        "screening_indicator"
                    ),
                    "severity": visual_finding["severity"],
                    "source_document_id": document_id,
                    "analysis_method": visual_finding["analysis_method"],
                    "explanation": visual_finding["description"],
                    "suggested_verification": visual_finding[
                        "recommended_action"
                    ],
                    "confidence": None,
                    "heuristic_score": visual_finding["heuristic_score"],
                    "risk_assessment_excluded": visual_finding.get(
                        "risk_assessment_excluded",
                        False
                    ),
                    "risk_exclusion_reason": visual_finding.get(
                        "risk_exclusion_reason"
                    ),
                    "evidence": [
                        {
                            "document_id": document_id,
                            "source_filename": overview["source_filename"],
                            "page": region["page"],
                            "bbox": region["bbox"],
                            "coordinate_system": region["coordinate_system"],
                            "text_excerpt": region["text_excerpt"],
                            "analysis_method": "relative_pdf_font_size_screening"
                        }
                        for region in regions
                    ]
                })
            embedded_image_analysis = image_manipulation_forensics(
                document_id
            )
            visual_analysis["embedded_image_screening"] = {
                "status": "completed",
                "total_images": embedded_image_analysis["total_images"],
                "image_statistics": embedded_image_analysis[
                    "image_statistics"
                ],
                "disclaimer": embedded_image_analysis["disclaimer"]
            }
            for image_finding in embedded_image_analysis["findings"]:
                matching_image = image_finding["matching_image"]
                findings.append({
                    "finding_id": image_finding["finding_id"],
                    "type": "duplicate_embedded_image",
                    "status": "screening_indicator",
                    "severity": image_finding["severity"],
                    "source_document_id": document_id,
                    "analysis_method": "exact_sha256_duplicate_embedded_image",
                    "explanation": image_finding["description"],
                    "suggested_verification": image_finding[
                        "recommended_action"
                    ],
                    "confidence": None,
                    "heuristic_score": image_finding["heuristic_score"],
                    "evidence": [
                        {
                            "document_id": document_id,
                            "source_filename": overview["source_filename"],
                            "page": image_finding["page"],
                            "image_xref": image_finding.get("image_xref"),
                            "sha256": image_finding.get("sha256"),
                            "analysis_method": (
                                "exact_sha256_duplicate_embedded_image"
                            )
                        },
                        {
                            "document_id": document_id,
                            "source_filename": overview["source_filename"],
                            "page": matching_image["page"],
                            "image_xref": matching_image["image_xref"],
                            "sha256": image_finding.get("sha256"),
                            "analysis_method": (
                                "exact_sha256_duplicate_embedded_image"
                            )
                        }
                    ]
                })
        else:
            visual_analysis = {
                "status": "not_supported_for_this_format",
                "note": (
                    "Automated visual region screening is currently "
                    "implemented for PDF text only."
                )
            }

        if not fields:
            extracted_information_message = "No structured fields detected"
        else:
            extracted_information_message = None

        forensic_database.update_document_status(document_id, "completed")
        document_results.append({
            "overview": overview,
            "extracted_information": {
                "fields": fields,
                "status": (
                    "fields_detected" if fields
                    else "no_structured_fields_detected"
                ),
                "message": extracted_information_message,
                "page_references": [
                    {
                        "page": page["page"],
                        "method": page["method"],
                        "characters": len(page["text"]),
                        "ocr_confidence": page.get("ocr_confidence"),
                        "region_count": len(page.get("regions", []))
                    }
                    for page in page_texts
                ],
                "confidence_note": (
                    "Heuristic confidence scores are not calibrated "
                    "probabilities and do not verify truth."
                )
            },
            "document_structure": structure,
            "evidence": evidence,
            "visual_forensic_findings": visual_analysis
        })

    for field_name, occurrences in field_occurrences.items():
        if field_name == "date":
            continue
        documents_with_field = {
            occurrence["document_id"] for occurrence in occurrences
        }
        distinct_values = {
            normalized_comparison_value(field_name, occurrence["value"])
            for occurrence in occurrences
        }
        if (
            len(documents_with_field) > 1
            and len(distinct_values) > 1
            and is_potential_name_variation(field_name, occurrences)
        ):
            similarity = min(
                SequenceMatcher(
                    None,
                    normalized_field_value(left["value"]),
                    normalized_field_value(right["value"])
                ).ratio()
                for index, left in enumerate(occurrences)
                for right in occurrences[index + 1:]
                if left["document_id"] != right["document_id"]
            )
            findings.append({
                "finding_id": str(uuid4()),
                "type": "potential_name_variation",
                "status": "requires_human_verification",
                "severity": "LOW",
                "analysis_method": "normalized_name_similarity_screening",
                "field": field_name,
                "explanation": (
                    "The extracted names are similar but not identical. "
                    "This may reflect spelling, OCR, or source differences "
                    "and is not evidence of impersonation."
                ),
                "suggested_verification": (
                    "Compare the cited original regions and confirm the "
                    "appropriate name with an authorized source."
                ),
                "confidence": round(similarity, 2),
                "evidence": occurrences
            })
        elif len(documents_with_field) > 1 and len(distinct_values) > 1:
            findings.append({
                "finding_id": str(uuid4()),
                "type": "cross_document_field_conflict",
                "status": "detected_inconsistency",
                "severity": "MEDIUM",
                "analysis_method": "normalized_exact_cross_document_field_comparison",
                "field": field_name,
                "explanation": (
                    f"Submitted documents contain differing values for "
                    f"{field_name.replace('_', ' ')}. Confirm that these "
                    "documents belong to the same application or transaction."
                ),
                "suggested_verification": (
                    "Confirm the records belong to the same case, then verify "
                    "each value against its original document."
                ),
                "confidence": round(
                    min(item["confidence"] for item in occurrences), 2
                ),
                "evidence": occurrences
            })

    comparison_rows = []
    submitted_ids = set(document_ids)
    fields_to_compare = (
        set(field_occurrences) | {"applicant_name", "date_of_birth"}
    )
    for field_name in sorted(fields_to_compare):
        if field_name == "date":
            continue
        occurrences = field_occurrences.get(field_name, [])
        by_document = {}
        for occurrence in occurrences:
            by_document.setdefault(occurrence["document_id"], []).append(
                occurrence
            )
        value_count = len({
            normalized_comparison_value(field_name, item["value"])
            for item in occurrences
        })
        missing_document_ids = sorted(submitted_ids - set(by_document))
        exact_value_count = len({
            re.sub(r"\s+", " ", str(item["value"])).strip().casefold()
            for item in occurrences
        })
        if not occurrences:
            value_status = "not_extracted"
        elif value_count > 1 and is_potential_name_variation(
            field_name, occurrences
        ):
            value_status = "potential_spelling_variation"
        elif value_count > 1:
            value_status = "conflict"
        elif exact_value_count > 1:
            value_status = "normalized_match"
        else:
            value_status = "matching"
        if len(document_ids) > 1:
            comparison_rows.append({
                "field": field_name,
                "status": (
                    "partially_observed"
                    if occurrences and missing_document_ids
                    else value_status
                ),
                "value_status": value_status,
                "values": occurrences,
                "not_extracted_from_document_ids": missing_document_ids,
                "note": (
                    "A field not extracted by OCR is not proof that it is "
                    "absent from the original document."
                )
            })
        if occurrences and missing_document_ids:
            findings.append({
                "finding_id": str(uuid4()),
                "type": "cross_document_field_not_extracted",
                "status": "information_not_extracted",
                "severity": "LOW",
                "analysis_method": "field_presence_comparison",
                "field": field_name,
                "explanation": (
                    f"{field_name.replace('_', ' ')} was extracted from some "
                    "documents but not from every document in this case."
                ),
                "suggested_verification": (
                    "Check the cited pages and confirm whether this field is "
                    "expected in the other document types."
                ),
                "confidence": None,
                "evidence": occurrences,
                "not_extracted_from_document_ids": missing_document_ids
            })

    for document_result in document_results:
        fields = document_result["extracted_information"]["fields"]
        issue_values = fields.get("issue_date", [])
        expiry_values = fields.get("expiry_date", [])
        for issue in issue_values:
            issue_date = parse_document_date(issue["value"])
            for expiry in expiry_values:
                expiry_date = parse_document_date(expiry["value"])
                if issue_date and expiry_date and expiry_date < issue_date:
                    issue_evidence = next(
                        item for item in document_result["evidence"]
                        if item["field"] == "issue_date"
                        and item["value"] == issue["value"]
                    )
                    expiry_evidence = next(
                        item for item in document_result["evidence"]
                        if item["field"] == "expiry_date"
                        and item["value"] == expiry["value"]
                    )
                    findings.append({
                        "finding_id": str(uuid4()),
                        "type": "invalid_document_date_sequence",
                        "status": "detected_inconsistency",
                        "severity": "MEDIUM",
                        "analysis_method": "parsed_issue_and_expiry_date_order",
                        "field": "issue_date/expiry_date",
                        "explanation": (
                            "The extracted expiry date precedes the extracted "
                            "issue date."
                        ),
                        "suggested_verification": (
                            "Verify both dates and their formats against "
                            "the source page."
                        ),
                        "confidence": min(
                            issue["confidence"], expiry["confidence"]
                        ),
                        "evidence": [issue_evidence, expiry_evidence]
                    })

    if len(document_ids) == 1:
        cross_document_comparison_status = "not_applicable"
        cross_document_comparison_message = (
            "Cross-document comparison not applicable"
        )
        comparison_rows = []
    else:
        cross_document_comparison_status = "completed"
        cross_document_comparison_message = (
            "Fields are compared only when extraction produced source values."
        )

    risk_assessment = build_risk_assessment(findings)
    investigation_id = str(uuid4())
    generated_at = datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")
    dossier = {
        "investigation_id": investigation_id,
        "generated_at": generated_at,
        "document_overview": {
            "document_count": len(document_results),
            "documents": [result["overview"] for result in document_results]
        },
        "extracted_information": [
            {
                "document_id": result["overview"]["document_id"],
                "fields": result["extracted_information"]["fields"],
                "status": result["extracted_information"]["status"],
                "message": result["extracted_information"]["message"],
                "page_references": result["extracted_information"]["page_references"],
                "confidence_note": result["extracted_information"]["confidence_note"]
            }
            for result in document_results
        ],
        "contextual_analysis": {
            "findings": findings,
            "finding_count": len(findings),
            "cross_document_comparison": comparison_rows,
            "cross_document_comparison_status": cross_document_comparison_status,
            "cross_document_comparison_message": cross_document_comparison_message,
            "disclaimer": (
                "Differences and visual indicators require human review; "
                "they do not establish fraud or document manipulation."
            )
        },
        "finding_interpretation": {
            "technical_observations": (
                "Measurements and extracted values returned by analysis "
                "modules; they describe the submitted files."
            ),
            "potential_anomalies": (
                "Automated screening and comparison findings are review "
                "leads, not determinations of fraud or manipulation."
            ),
            "investigator_decisions": (
                "Only entries in review_decisions are investigator-recorded "
                "decisions. Automated finding statuses are not confirmations."
            )
        },
        "risk_assessment": risk_assessment,
        "visual_forensic_findings": [
            {
                "document_id": result["overview"]["document_id"],
                "source_filename": result["overview"]["source_filename"],
                "analysis": result["visual_forensic_findings"]
            }
            for result in document_results
        ],
        "document_structure": [
            {
                "document_id": result["overview"]["document_id"],
                "structure": result["document_structure"]
            }
            for result in document_results
        ],
        "evidence_and_traceability": [
            {
                "document_id": result["overview"]["document_id"],
                "source_filename": result["overview"]["source_filename"],
                "references": result["evidence"],
                "finding_references": []
            }
            for result in document_results
        ],
        "investigation_summary": {
            "anomalies_requiring_review": findings,
            "areas_for_verification": [
                "Confirm extracted field values against the original documents.",
                "Verify that all submitted documents relate to the same case.",
                "Review highlighted PDF regions in context; font-size outliers can be legitimate."
            ],
            "limitations": [
                "OCR and field extraction are heuristic and may omit or misread content.",
                "Handwriting recognition is not implemented; EasyOCR recognition confidence is returned for recognized regions but is not calibrated.",
                "Visual screening detects unusual PDF text font sizes, not image tampering or forgery.",
                "Headings and possible table rows use text layout heuristics, not a document-layout model.",
                "Field correlations use exact normalized text values and do not perform semantic entity resolution.",
                "Prominent synthetic/demo disclaimer text can create a font-size observation; such observations are retained and explicitly excluded from the risk score when all cited regions match disclaimer markers.",
                "No automated result is a determination of authenticity or fraud."
            ]
        }
    }

    evidence_sections = {
        item["document_id"]: item
        for item in dossier["evidence_and_traceability"]
    }
    source_filenames = {
        item["document_id"]: item["source_filename"]
        for item in dossier["document_overview"]["documents"]
    }
    if (
        dossier["investigation_id"] != investigation_id
        or set(source_filenames) != submitted_ids
    ):
        raise HTTPException(
            status_code=500,
            detail="Investigation dossier document identity validation failed."
        )

    for finding in findings:
        finding_references = finding.get("evidence", [])
        if not finding_references:
            continue
        for reference in finding_references:
            referenced_document_id = reference.get("document_id")
            if referenced_document_id not in evidence_sections:
                raise HTTPException(
                    status_code=500,
                    detail=(
                        "Investigation evidence references a document outside "
                        "the submitted investigation."
                    )
                )
            source_filename = source_filenames[referenced_document_id]
            finding_reference = {
                **reference,
                "document_id": referenced_document_id,
                "source_filename": source_filename,
                "finding_id": finding["finding_id"],
                "finding_type": finding["type"],
                "finding_status": finding["status"],
                "severity": finding.get("severity"),
                "analysis_method": (
                    reference.get("analysis_method")
                    or reference.get("method")
                    or finding.get("analysis_method")
                ),
                "text_excerpt": (
                    reference.get("text_excerpt")
                    or reference.get("evidence_text")
                )
            }
            evidence_sections[
                referenced_document_id
            ]["finding_references"].append(finding_reference)

    dossier_path = REPORT_DIR / f"Investigation_Dossier_{investigation_id}.json"
    try:
        dossier_path.write_text(
            json.dumps(dossier, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
    except OSError as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to save the investigation dossier."
        ) from error

    try:
        forensic_database.save_investigation(
            dossier,
            document_ids,
            owner_id=user["user_id"]
        )
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to save the investigation to SQLite history."
        ) from error

    record_audit_event(
        "investigation_completed",
        document_ids,
        {
            "finding_count": len(findings),
            "finding_types": sorted({
                finding["type"] for finding in findings
            })
        },
        investigation_id=investigation_id
    )
    return dossier


@app.get("/investigations/{investigation_id}")
def get_investigation(
    investigation_id: str,
    user=Depends(require_authenticated_user)
):
    dossier = load_investigation_dossier(investigation_id, user["user_id"])
    dossier["review_decisions"] = forensic_database.get_finding_reviews(
        investigation_id
    )
    return dossier


@app.get("/investigations")
def list_investigation_history(
    limit: int = 100,
    user=Depends(require_authenticated_user)
):
    if limit < 1 or limit > 500:
        raise HTTPException(
            status_code=400,
            detail="History limit must be between 1 and 500."
        )
    return {
        "investigations": forensic_database.list_investigations(
            limit,
            user_id=user["user_id"],
            is_admin=user["role"] == "admin"
        )
    }


@app.get("/dashboard/summary")
def get_dashboard_summary(user=Depends(require_authenticated_user)):
    return forensic_database.get_dashboard_summary(
        user_id=user["user_id"],
        is_admin=user["role"] == "admin"
    )


@app.get("/investigations/{investigation_id}/findings/{finding_id}")
def get_investigation_finding(
    investigation_id: str,
    finding_id: str,
    user=Depends(require_authenticated_user)
):
    dossier = load_investigation_dossier(investigation_id, user["user_id"])
    finding = next(
        (
            item for item in dossier["contextual_analysis"]["findings"]
            if item["finding_id"] == finding_id
        ),
        None
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return {
        "investigation_id": investigation_id,
        "finding": finding,
        "related_findings": [
            item for item in dossier["contextual_analysis"]["findings"]
            if item["finding_id"] != finding_id
            and {
                source.get("document_id")
                for source in item.get("evidence", [])
            }.intersection({
                source.get("document_id")
                for source in finding.get("evidence", [])
            })
        ]
    }


@app.post("/investigations/{investigation_id}/findings/{finding_id}/review")
def review_investigation_finding(
    investigation_id: str,
    finding_id: str,
    payload: FindingReviewRequest,
    user=Depends(require_authenticated_user)
):
    dossier = load_investigation_dossier(investigation_id, user["user_id"])
    finding = next(
        (
            item for item in dossier["contextual_analysis"]["findings"]
            if item["finding_id"] == finding_id
        ),
        None
    )
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")

    updated_at = datetime.now(timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")
    forensic_database.save_finding_review(
        investigation_id,
        finding_id,
        payload.status,
        payload.reviewer.strip(),
        payload.note.strip(),
        updated_at
    )
    record_audit_event(
        "finding_review_updated",
        [
            document["document_id"]
            for document in dossier["document_overview"]["documents"]
        ],
        {
            "finding_id": finding_id,
            "review_status": payload.status
        },
        investigation_id=investigation_id
    )
    return {
        "investigation_id": investigation_id,
        "finding_id": finding_id,
        "status": payload.status,
        "reviewer": payload.reviewer.strip(),
        "note": payload.note.strip(),
        "updated_at": updated_at
    }


@app.get("/investigations/{investigation_id}/report")
def generate_investigation_report(
    investigation_id: str,
    user=Depends(require_authenticated_user)
):
    dossier = load_investigation_dossier(investigation_id, user["user_id"])
    report_path = REPORT_DIR / f"Investigation_Dossier_{investigation_id}.pdf"
    finding_interpretation = dossier.get(
        "finding_interpretation",
        {
            "technical_observations": (
                "Measurements and extracted values returned by analysis "
                "modules describe the submitted files."
            ),
            "potential_anomalies": (
                "Automated screening findings are review leads, not "
                "determinations of fraud or manipulation."
            ),
            "investigator_decisions": (
                "Only entries in review_decisions are investigator-recorded "
                "decisions; automated statuses are not confirmations."
            )
        }
    )

    try:
        def draw_page_number(report_canvas, report_document):
            report_canvas.saveState()
            report_canvas.setFont("Helvetica", 8)
            report_canvas.setFillColor(colors.HexColor("#637083"))
            report_canvas.drawString(
                40,
                22,
                f"FORENSAI | {investigation_id}"
            )
            report_canvas.drawRightString(
                A4[0] - 40,
                22,
                f"Page {report_document.page}"
            )
            report_canvas.restoreState()

        styles = getSampleStyleSheet()
        story = [
            Paragraph("FORENSAI INVESTIGATION DOSSIER", styles["Title"]),
            Spacer(1, 10),
            Paragraph(
                f"Investigation ID: {escape(investigation_id)}",
                styles["Normal"]
            ),
            Paragraph(
                f"Generated: {escape(dossier['generated_at'])}",
                styles["Normal"]
            ),
            Paragraph(
                "Heuristic risk assessment: "
                f"{escape(dossier['risk_assessment']['category'])} "
                f"({dossier['risk_assessment']['score']}/100). "
                "This is not proof of fraud or manipulation.",
                styles["Normal"]
            ),
            Paragraph(
                "Automated technical observations and potential anomalies "
                "are not proof of fraud or manipulation. Investigator "
                "decisions are recorded separately in the review-decision section.",
                styles["Normal"]
            ),
            Spacer(1, 14)
        ]

        sections = [
            ("1. DOCUMENT OVERVIEW", dossier["document_overview"]),
            ("2. EXTRACTED INFORMATION", dossier["extracted_information"]),
            ("3. CONTEXTUAL ANALYSIS", dossier["contextual_analysis"]),
            ("4. VISUAL FORENSIC FINDINGS", dossier["visual_forensic_findings"]),
            ("5. EVIDENCE AND TRACEABILITY", dossier["evidence_and_traceability"]),
            ("6. FORENSIC RISK ASSESSMENT", dossier["risk_assessment"]),
            (
                "7. INVESTIGATOR REVIEW DECISIONS",
                forensic_database.get_finding_reviews(investigation_id)
            ),
            ("8. INVESTIGATION SUMMARY", dossier["investigation_summary"]),
            ("9. FINDING INTERPRETATION", finding_interpretation),
            ("10. LIMITATIONS", dossier["investigation_summary"]["limitations"])
        ]
        for title, content in sections:
            story.append(Paragraph(title, styles["Heading2"]))
            story.append(Paragraph(
                escape(json.dumps(content, ensure_ascii=False, indent=2)).replace(
                    "\n", "<br/>"
                ),
                styles["Code"]
            ))
            story.append(Spacer(1, 12))

        document = SimpleDocTemplate(
            str(report_path),
            pagesize=A4,
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40
        )
        document.build(
            story,
            onFirstPage=draw_page_number,
            onLaterPages=draw_page_number
        )
    except Exception as error:
        logger.exception(
            "Investigation dossier PDF generation failed for %s",
            investigation_id
        )
        raise HTTPException(
            status_code=500,
            detail="Investigation dossier PDF generation failed."
        ) from error

    if not report_path.is_file():
        raise HTTPException(
            status_code=500,
            detail="Investigation dossier PDF was not created."
        )
    record_audit_event(
        "investigation_report_generated",
        [
            document["document_id"]
            for document in dossier["document_overview"]["documents"]
        ],
        {
            "format": "pdf"
        },
        investigation_id=investigation_id
    )
    return FileResponse(
        path=str(report_path),
        media_type="application/pdf",
        filename=f"Investigation_Dossier_{investigation_id}.pdf"
    )


@app.get("/audit-trail")
def get_audit_trail(user=Depends(require_authenticated_user)):
    try:
        is_admin = user["role"] == "admin"
        events = forensic_database.list_audit_events(
            user_id=user["user_id"],
            is_admin=is_admin
        )
        if AUDIT_LOG.is_file():
            lines = AUDIT_LOG.read_text(encoding="utf-8").splitlines()
            legacy_events = [
                json.loads(line) for line in lines[-500:] if line.strip()
            ]
            for event in legacy_events:
                if is_admin:
                    events.append(event)
                    continue
                investigation_id = event.get("investigation_id")
                if (
                    investigation_id
                    and forensic_database.get_investigation_owner(
                        investigation_id
                    ) == user["user_id"]
                ):
                    events.append(event)
                    continue
                if investigation_id:
                    continue
                owners = forensic_database.get_document_owners(
                    event.get("document_ids", [])
                )
                if any(owner == user["user_id"] for owner in owners.values()):
                    events.append(event)
        events.sort(key=lambda event: event["timestamp"], reverse=True)
    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail="Unable to read the investigation audit trail."
        ) from error
    return {"events": events[:500]}


# =========================================================
# 19. RUN SERVER
# =========================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        reload=True
    )
