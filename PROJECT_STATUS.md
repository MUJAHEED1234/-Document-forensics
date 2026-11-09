# FORENSAI Project Status

**Audit date:** 2026-11-09
**Scope:** Read-only source/configuration review plus existing backend tests and frontend production build. No application behavior was changed during this audit.

## Architecture

```text
React + Vite + Lucide
  ├─ Account login/registration and investigator/admin UI
  ├─ Upload, analysis-module controls, dossier review, evidence preview
  └─ Same-origin /api calls through the Vite development proxy
       ↓
FastAPI
  ├─ JWT authentication, account roles, route authorization
  ├─ PDF/image validation, analysis endpoints, investigation orchestration
  ├─ PyMuPDF + EasyOCR + NumPy/Pillow
  └─ ReportLab PDF and JSON dossier generation
       ↓
Local filesystem: uploads and reports
SQLite: users, documents, investigations, reviews, revoked tokens, audit events
```

The backend is concentrated in `backend/main.py`; persistence is in `backend/database.py`. The frontend is a Vite React application with most application state and views in `ai-document-forensics-react/src/App.jsx`. OCR, extraction, classification, comparison, and report behavior are primarily deterministic heuristics. The software does not provide authoritative authenticity or identity decisions.

## Verified validation

| Check | Result | Scope and caveats |
|---|---|---|
| `python -m unittest discover -s .\backend\tests -v` | **15 tests passed** | Includes auth/role/ownership checks, upload validation, mocked OCR responses, dossier/history/review/evidence behavior, and synthetic comparison cases. |
| `npm run build` in the React app | **Passed** | Confirms production compilation only; it is not an end-to-end UI test. |
| Runtime API and visual inspection | **Not performed in this audit** | No live backend/API workflow or real EasyOCR model run was executed. |

No test failure was observed in the checks above. This does not establish OCR accuracy or forensic detection accuracy.

## Implemented and verified in source

- **Document ingestion:** `/upload` accepts PDF/JPG/JPEG/PNG extensions, checks file signatures and decodability, enforces a 15 MiB application-level file limit, a 50-page PDF limit, and image-pixel limits. Stored filenames are UUID-based. A test covers invalid PDF content and an oversized upload.
- **Document analysis endpoints:** PDF text extraction, OCR, structured extraction, classification, manual classification correction, document structure, fingerprinting, metadata, PDF forensics, visual forensics, image forensics, and evidence preview routes are present.
- **OCR data model:** OCR responses retain page, recognized text, confidence, bounding boxes, and coordinate-system metadata when supplied by EasyOCR. English, Hindi, and Kannada are the configured supported language codes.
- **Classification:** Keyword-based document classes return scores and an explicitly heuristic confidence; investigators can save a manual correction.
- **Investigations:** The application accepts up to ten document IDs, constructs a persisted multi-document dossier, compares extracted field values, records evidence references, and computes a severity-weighted heuristic risk score.
- **Investigator review and history:** SQLite stores accounts, documents, investigations, document membership, review decisions, revoked tokens, and audit events. History, dashboard summary, finding review, and audit-trail routes are present.
- **Accounts and authorization:** The code implements registration/login, password hashing with scrypt, HS256 signed expiring tokens, logout revocation, admin account controls, and ownership checks. The existing suite exercises authentication, logout, roles, and document/investigation ownership.
- **Reports and evidence:** PDF and JSON dossier outputs are generated from dossier data; evidence preview can render PDF regions from bounding boxes. Unit tests exercise synthetic dossier conflicts and check for generated report output.
- **Frontend workflows:** React contains authentication, upload, individual analysis controls, dossier review, cross-document findings, history, evidence preview, manual review, dashboard totals, and report download controls. The current light-theme stylesheet is present.

## Partially implemented

- **OCR reliability:** EasyOCR is wired to the application, but automated tests substitute a fake OCR reader. There is no measured accuracy benchmark, multilingual evaluation corpus, or end-to-end OCR validation against known source text.
- **Structured extraction:** Field labels and regular expressions are English-centric heuristics. Bounding-box association is conditional on matching extracted text to an available OCR/PDF region; values are not guaranteed to have precise source localization.
- **Layout understanding:** Headings, form fields, and possible table rows are inferred from text/font/span properties. The code itself disclaims that possible table rows are not verified table structures.
- **Cross-document and within-document checks:** Comparisons depend on fields successfully extracted and on the documents submitted as one case. Name similarity is a string heuristic; results can miss or overstate variations.
- **Visual forensics:** Implemented screening is limited principally to unusually large/small PDF text spans relative to a page median and exact duplicate embedded-image hashes. These are review indicators, not edit localization or proof of tampering.
- **Risk scoring:** The score is a severity-weighted prioritization heuristic, not a probability, calibrated model, or proof of fraud.
- **Dossier presentation:** The PDF contains dossier sections and actual generated data, but much of its content is serialized JSON rather than a fully structured investigator-facing report with purpose-built tables and evidence layouts.
- **Authentication/security:** Appropriate for a local prototype, not a production identity/access-management deployment. See security findings below.
- **Responsive interface:** Responsive CSS and a production build exist. There are no frontend unit, component, accessibility, or browser workflow tests in `package.json`.

## Missing or unsupported capabilities

- Reliable copy/paste localization, image-compression/edit detection, or general pixel-level manipulation localization.
- Signature or stamp/seal detection and any authenticity/forgery determination.
- Face/photo consistency comparison.
- Handwriting recognition and general semantic/table understanding.
- Calibrated extraction/classification confidence or model-accuracy evaluation.
- Automated React tests and a repeatable full browser/API integration suite.
- Configurable retention, secure deletion, and verified encryption-at-rest.
- Production controls such as rate limiting, registration abuse controls, deployment-grade TLS/access governance, and managed secret storage.
- The documented backend environment template `backend\.env.example` is absent, so the README setup command that copies it cannot run as written.

## Existing errors and concrete risks

1. **Working-directory-dependent storage (high priority):** `DATABASE_PATH`, `UPLOAD_DIR`, `REPORT_DIR`, and `AUDIT_LOG` use relative paths. Running the backend from the project root versus `backend` can select different SQLite databases and upload/report directories. Both root-level and `backend`-level database/upload/report artifacts exist in the project inventory. This creates a risk of apparent missing investigations/documents and split audit history.
2. **Broken environment setup instruction:** The root README instructs users to copy `backend\.env.example` to `.env`, but that template file is missing. An ignored `backend\.env` exists, but its contents were deliberately not read; therefore secret presence/quality was not evaluated. The project-root `.env` is absent.
3. **Frontend test coverage is missing:** The frontend manifest exposes build/dev/preview scripts but no test script. Successful compilation does not verify navigation, upload, auth, or report workflows.
4. **OCR integration coverage is mocked:** Tests verify response shaping and bounding-box fields using a fake reader, not the installed EasyOCR model on actual English/Hindi/Kannada documents. The audit did not assert OCR output against a source-ground-truth dataset.
5. **Local-prototype security limits:** Public self-registration has no visible rate limiting or abuse controls; there are no configurable retention/deletion controls or verified encryption-at-rest. Do not treat the current local-file/SQLite setup as production-ready for real sensitive records.

No additional runtime defect was reproduced in this audit. Findings above are code/configuration and test-coverage risks, not claims of a demonstrated exploit.

## Security observations

- `.env`, `backend\.env`, and `ai-document-forensics-react\.env` are ignored by the repository ignore rules. Their contents were not accessed or included in this report.
- The JWT secret is validated by code for a minimum of 32 UTF-8 bytes and startup validation is covered by tests. The audit did not inspect the actual secret value.
- Upload handling uses generated storage names and checks extension, file signature, decoding, size, PDF page count, and image dimensions.
- API CORS is restricted to localhost/loopback origins in the source; it is not a production origin configuration.
- Files and database are local filesystem artifacts. Encryption-at-rest, retention/deletion, rate limiting, and production-grade access governance are not implemented or verified.
- Audit history includes SQLite-backed records and a legacy JSONL read path. It should be checked for consistent root paths and owner scoping as part of storage-path remediation.

## Recommended implementation order

1. **Resolve storage configuration first:** Choose one canonical, absolute app-data root independent of current working directory; provide explicit configuration/migration behavior and regression tests before moving or cleaning any existing user data.
2. **Repair setup reproducibility:** Add a safe `.env.example` with placeholder-only values, align README setup instructions, and test environment loading without exposing secrets.
3. **Build a ground-truth synthetic validation set:** Add known digital/scanned PDFs and images in supported languages with expected text, page references, and coordinate checks; separate mocked unit tests from true model integration tests.
4. **Improve extraction traceability:** Test label/value variants, ambiguous/missing fields, OCR uncertainty, and source-region association. Keep confidence clearly identified as heuristic where it is not calibrated.
5. **Strengthen forensic indicators incrementally:** Add only explainable, source-linked detectors with synthetic positive/negative controls and false-positive review; explicitly defer unsupported signature, stamp, face, and compression claims.
6. **Improve dossier/report structure:** Use report sections and evidence tables with source/page references, actual findings, reviewer decisions, limitations, and stable pagination; test output content against generated dossiers.
7. **Add frontend/browser coverage:** Exercise auth, upload, analysis, history, review, evidence preview, responsive layouts, and PDF download against a local test backend.
8. **Set a documented security/deployment boundary:** Before any real sensitive documents, decide retention/deletion, registration policy/rate limits, deployment CORS/TLS, secret management, filesystem permissions, and backup controls.

## First five highest-priority problems

1. **Split storage locations:** Relative working-directory paths can point the same code at different databases and document/report stores.
2. **Reproducible configuration is broken:** README references a nonexistent backend `.env.example`; environment values were not inspected, so deployment readiness remains unverified.
3. **Extraction correctness is not established:** OCR uses heuristics and the current tests mock the OCR engine; field extraction is English-label/regex-centric and region linkage is conditional.
4. **Manipulation screening is narrow:** Font-size outliers and exact duplicate images do not meet broader copy/paste, compression, signature/stamp, or image-edit detection requirements.
5. **Validation and operational security are prototype-level:** There are no frontend tests, no model accuracy/ground-truth suite, and no rate limiting, retention/deletion, or verified at-rest encryption.

## Audit boundary

The backend unittest suite and frontend build were run. The audit did not inspect local environment-file contents, upload/report contents, secret values, or perform a live OCR run. No application feature changes have been made. Implementation should begin only after approval of the first remediation phase.
