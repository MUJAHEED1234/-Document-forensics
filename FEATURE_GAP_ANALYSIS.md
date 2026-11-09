# FORENSAI feature gap analysis

This assessment reflects the implementation in the repository after extending the existing FastAPI and React application. “Implemented” means a code path and test/demo exercise exist; heuristic results are still preliminary and require human review.

## Current status

| Requirement | Status | Evidence / limitation |
|---|---|---|
| Upload PDF, JPG, JPEG, PNG with IDs, validation, size/page limits | Implemented | `/upload`; multiple files uploaded by the React workspace, 15 MB per file, 50 pages per PDF |
| Digital PDF text, scanned PDF OCR, image OCR | Implemented with limitations | `/ocr/{id}`; EasyOCR returns recognized text, confidence and regions; select English (`en`), Hindi (`hi`), and/or Kannada (`kn`) through `FORENSAI_OCR_LANGUAGES`; first use may download model weights; not handwriting-certified |
| Field extraction and page/evidence references | Partial | `/structured-extraction/{id}`; label and pattern heuristics, bbox only when a source OCR/text region can be associated; not a general form/table model |
| Document type and confidence | Implemented as heuristic | `/classification/{id}` returns keyword scores and an explicitly uncalibrated confidence; `PUT /documents/{id}/classification` stores a manual correction |
| Layout/structure | Partial | `/document-structure/{id}` labels text regions, headings, possible form fields and table rows using layout heuristics; signature/stamp detection and semantic layout models are unsupported |
| Metadata, hash, PDF statistics, font outliers and duplicate embedded-image checks | Partial | Existing `/metadata`, `/fingerprint`, `/forensics`, `/visual-forensics`, and `/image-forensics` routes retained; exact duplicate embedded images are cited in dossiers; font-size and duplicate-image observations are screening indicators, not tampering detection |
| Contextual and cross-document comparison | Implemented with limitations | `POST /investigations`; compares normalized values for applicant name, birth date, document number, address, gender, issue/expiry dates and other extracted labels; flags potential name spelling variation separately; reports unextracted fields without asserting that they are absent; assumes investigators submitted related records |
| Evidence mapping and preview | Implemented with limitations | Finding references include source IDs/names, page, method, excerpt and available bbox; `/evidence-preview` overlays source coordinates where present; page-level source links are used when coordinates are absent |
| Dossier PDF and JSON retrieval | Implemented | Six required sections, stored dossier JSON, PDF export at `/investigations/{id}/report` |
| SQLite investigation history, membership, review decisions and audit | Implemented | `backend/database.py`; `/investigations`, finding review endpoint and `/audit-trail`; document contents are excluded from audit event details |
| Risk assessment and live dashboard totals | Implemented as heuristic | `/dashboard/summary` computes totals from SQLite investigations and review status; dossier risk points derive from finding severity and are not calibrated probabilities |
| Frontend analysis, correction, evidence, history, review, report actions | Implemented | React dashboard calls corresponding FastAPI routes; bearer-token authorization also protects evidence previews; aggregate metrics come from saved records |
| Authentication | Implemented for the local prototype | `/auth/register`, `/auth/login`, `/auth/logout`, `/auth/me`; scrypt password hashes, 30-minute HS256 JWTs, SQLite revocation, default investigator role, environment-bootstrapped administrator, admin account/role controls, and owner/admin authorization for documents and investigations |
| Encryption-at-rest, configurable retention/deletion, production access governance | Unsupported | Local hackathon prototype only; protect the host machine and use authorized synthetic data |
| Copy-paste localization, image compression/edit detection, signature/stamp detection, face/photo comparison, handwriting, LLM reasoning | Unsupported | Exact duplicate embedded-image hashes and relative PDF font-size screening are indicators only; no authenticity or identity claims are made |

## Previous integration gaps addressed

- Grouped documents could previously be compared but investigations were stored only as files. SQLite now persists dossiers, document membership, review decisions, and audit events.
- OCR returned plain text without region-level confidence or coordinates. OCR and selectable PDF text now retain regions where the engine supplies them.
- Classification was not editable; the keyword prediction now exposes its heuristic score and accepts an investigator correction.
- Dossier evidence was primarily raw JSON. The dashboard now shows cross-document comparison rows, source links/previews, and manual finding review actions.
- Running every analysis on an image could stop on a PDF-only endpoint. The dashboard skips those modules for non-PDF input.
- CORS accepted every origin. The local prototype now allows only localhost/loopback origins; this is not a substitute for authentication.
- Individual users now authenticate with expiring and revocable JWTs; investigator access is scoped to owned documents and investigations, while admins can review all records.
- Admins can create accounts, change roles, and disable accounts. Public registration creates investigators only.
- Existing ownerless database records are assigned to the configured bootstrap administrator; legacy data is not exposed to newly registered investigators.
- Cross-document comparisons distinguish normalized matches, likely name spelling variations, conflicts, and fields that were not extracted. Unlabeled generic date matches are not correlated across documents.
- Investigation dossiers include an explicitly heuristic severity-weighted risk summary, and PDF exports include risk and investigator review sections.
- Dashboard totals are computed from persisted investigation, document, finding, and review records; they are not hardcoded sample values.

## Implementation and verification order

1. Keep the existing upload, extraction, hash, metadata, PDF, visual and report APIs intact.
2. Persist submissions/investigations/reviews/audit in SQLite.
3. Add OCR regions, heuristic structure and classification correction while explicitly returning uncertainty.
4. Link comparisons/findings back to their source documents and add contextual/date checks.
5. Add authentication, risk summaries, dashboard aggregates, and related PDF dossier sections.
6. Exercise backend tests, the synthetic three-document workflow, and the production frontend build.

## Reproducible checks

From the project root in PowerShell:

```powershell
.\backend\venv\Scripts\python.exe -m unittest discover -s .\backend\tests -v
Set-Location .\ai-document-forensics-react
npm run build
```

The generated PDFs in `demo_dataset\` are fictional and are not identity credentials. Upload them together to demonstrate extraction, exact-value discrepancy reporting, highlighted PDF text-size screening, evidence references, review decisions, history, and dossier export. A font-size cue is not proof of manipulation.
