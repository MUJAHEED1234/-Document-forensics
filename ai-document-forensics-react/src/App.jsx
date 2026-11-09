import { useEffect, useMemo, useState } from "react";
import {
  Activity, AlertCircle, ArrowUpRight, CheckCircle2, ChevronRight,
  Clock3, Download, Eye, FileSearch, FileText, Fingerprint,
  GitCompareArrows, History, Image as ImageIcon, Layers3, LoaderCircle,
  ScanText, ShieldCheck, UploadCloud, UserCog, Users, X
} from "lucide-react";
import "./enhancements.css";
import "./premium-theme.css";

const API_BASE = (
  import.meta.env.VITE_API_BASE_URL ||
  `${window.location.origin}/api`
).replace(/\/$/, "");

const modules = [
  { key: "extract", label: "PDF text extraction", path: "extract", icon: FileText, description: "Read selectable text from PDF pages.", pdfOnly: true },
  { key: "ocr", label: "OCR recognition", path: "ocr", icon: ScanText, description: "Recognize text and retain OCR confidence and regions." },
  { key: "structured", label: "Structured information", path: "structured-extraction", icon: FileSearch, description: "Extract labelled fields with source references." },
  { key: "structure", label: "Document structure", path: "document-structure", icon: Layers3, description: "Inspect headings, form fields, and page regions." },
  { key: "classification", label: "Document classification", path: "classification", icon: FileSearch, description: "Review predicted type and manually correct it." },
  { key: "fingerprint", label: "SHA-256 fingerprint", path: "fingerprint", icon: Fingerprint, description: "Calculate a cryptographic file hash." },
  { key: "metadata", label: "Metadata analysis", path: "metadata", icon: FileSearch, description: "Inspect embedded document properties.", pdfOnly: true },
  { key: "forensics", label: "Digital forensics", path: "forensics", icon: ShieldCheck, description: "Run the backend's digital forensic checks.", pdfOnly: true },
  { key: "visual", label: "Visual forensics", path: "visual-forensics", icon: Layers3, description: "Inspect page-level visual characteristics.", pdfOnly: true },
  { key: "image", label: "Image forensics", path: "image-forensics", icon: ImageIcon, description: "Check exact duplicate embedded images.", pdfOnly: true }
];

const documentTypes = ["identity", "educational", "financial", "legal", "employment", "application_form", "government", "other", "unclassified", "mixed"];

function pretty(value) {
  return JSON.stringify(value, null, 2);
}

function Metric({ label, value, icon: Icon }) {
  return <div className="metric"><span className="metric-icon"><Icon size={17} /></span><div><small>{label}</small><strong>{value ?? "—"}</strong></div></div>;
}

function AuthenticatedEvidenceImage({ apiBase, token, reference }) {
  const [imageUrl, setImageUrl] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    let objectUrl = "";
    const query = `bbox=${encodeURIComponent(reference.bbox.join(","))}`;
    fetch(`${apiBase.replace(/\/$/, "")}/evidence-preview/${reference.document_id}/${reference.page}?${query}`, {
      headers: { Authorization: `Bearer ${token}` },
      signal: controller.signal
    }).then(response => {
      if (!response.ok) throw new Error(`Evidence preview failed (${response.status})`);
      return response.blob();
    }).then(blob => {
      objectUrl = URL.createObjectURL(blob);
      setImageUrl(objectUrl);
    }).catch(loadError => {
      if (loadError.name !== "AbortError") setError(loadError.message);
    });

    return () => {
      controller.abort();
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [apiBase, reference.bbox, reference.document_id, reference.page, token]);

  if (error) return <small className="evidence-error">{error}</small>;
  return imageUrl
    ? <img alt={`Page ${reference.page} with evidence region highlighted`} src={imageUrl} />
    : <small>Loading authenticated evidence preview…</small>;
}

function DossierFindings({ dossier, apiBase, token, onReview, busy, onOpenEvidence }) {
  const [findingQuery, setFindingQuery] = useState("");
  const findings = dossier.contextual_analysis?.findings || [];
  const decisions = dossier.review_decisions || [];
  const comparison = dossier.contextual_analysis?.cross_document_comparison || [];
  const comparisonStatus = dossier.contextual_analysis?.cross_document_comparison_status;
  const comparisonMessage = dossier.contextual_analysis?.cross_document_comparison_message;
  const documents = dossier.document_overview?.documents || [];
  const documentNames = new Map(documents.map(document => [document.document_id, document.source_filename]));
  const extractedInformation = dossier.extracted_information || [];
  const traceability = dossier.evidence_and_traceability || [];
  const risk = dossier.risk_assessment;
  const visibleFindings = findings.filter(finding => JSON.stringify(finding).toLowerCase().includes(findingQuery.toLowerCase()));
  return <div className="dossier-results">
    <div className="dossier-summary"><b>{findings.length} finding(s) recorded</b><span>{dossier.document_overview?.document_count || 0} documents analyzed</span></div>
    {risk && <section className="risk-card"><div><small>HEURISTIC RISK ASSESSMENT</small><strong>{risk.category} · {risk.score}/100</strong><span>This score prioritizes review; it is not proof of fraud or forgery.</span></div><details><summary>{risk.finding_contributions?.length || 0} finding contribution(s)</summary><ul>{(risk.finding_contributions || []).map(item => <li key={item.finding_id}>{item.type.replaceAll("_", " ")}: +{item.points} points ({item.severity})</li>)}</ul></details></section>}
    {comparisonStatus === "not_applicable"
      ? <div className="comparison-not-applicable"><GitCompareArrows size={17}/>{comparisonMessage || "Cross-document comparison not applicable"}</div>
      : !!comparison.length && <div className="comparison-table-wrap"><h3><GitCompareArrows size={17}/> Cross-document comparison</h3><table className="comparison-table"><thead><tr><th>Field</th><th>Result</th><th>Source values and missing documents</th></tr></thead><tbody>{comparison.map(row => <tr key={row.field}><td>{row.field.replaceAll("_", " ")}</td><td><span className={`severity-pill ${row.value_status || row.status}`}>{(row.value_status || row.status).replaceAll("_", " ")}</span>{row.status === "partially_observed" && <small className="comparison-value muted">Partially observed</small>}</td><td>{row.values.map((value, index) => <span className="comparison-value" key={`${value.document_id}-${index}`}>{value.source_filename} · {value.document_id}: {value.value}{value.page ? ` (p. ${value.page})` : ""}</span>)}{row.not_extracted_from_document_ids?.map(documentId => <span className="comparison-value muted" key={documentId}>{documentNames.get(documentId) || "Source filename unavailable"} · {documentId}: not extracted (not proof the field is absent)</span>)}</td></tr>)}</tbody></table></div>}
    <section className="extracted-information">
      <h3>Structured extraction</h3>
      {extractedInformation.map(document => {
        const fields = document.fields || {};
        const entries = Object.entries(fields).filter(([, values]) => Array.isArray(values) && values.length);
        return <article className="extracted-document" key={document.document_id}>
          <div className="extracted-document-heading">
            <b>{documentNames.get(document.document_id) || "Source filename unavailable"}</b>
            <small>Document ID: {document.document_id}</small>
          </div>
          {!entries.length
            ? <p className="no-findings">{document.message || "No structured fields detected"}</p>
            : entries.map(([field, values]) => <div className="extracted-field" key={field}>
              <b>{field.replaceAll("_", " ")}</b>
              {values.map((value, index) => <div className="extracted-value" key={`${field}-${index}`}>
                <span>{value.value}</span>
                <small>Page {value.page} · {value.method} · Confidence {value.confidence} ({value.confidence_basis})</small>
                {value.bbox && <small>Region: {value.bbox.join(", ")} {value.coordinate_system || ""}</small>}
                {value.evidence && <blockquote>{value.evidence}</blockquote>}
              </div>)}
            </div>)}
        </article>;
      })}
    </section>
    <details className="traceability-section">
      <summary>Evidence traceability</summary>
      {traceability.map(document => <div className="traceability-document" key={document.document_id}>
        <h4>{document.source_filename} · {document.document_id}</h4>
        {!document.finding_references?.length
          ? <p className="no-findings">No finding evidence references recorded for this document.</p>
          : document.finding_references.map((reference, index) => <article className="traceability-reference" key={`${reference.finding_id}-${index}`}>
            <b>{reference.finding_type?.replaceAll("_", " ")} · Finding {reference.finding_id}</b>
            <span>{reference.source_filename} · {reference.document_id}{reference.page ? ` · Page ${reference.page}` : ""}</span>
            <small>Status: {reference.finding_status?.replaceAll("_", " ")} · Method: {reference.analysis_method || "Not specified by the finding"}</small>
            {reference.text_excerpt && <blockquote>{reference.text_excerpt}</blockquote>}
            {reference.bbox && <small>Region: {reference.bbox.join(", ")} {reference.coordinate_system || ""}</small>}
            {reference.page && <button className="text-button" onClick={() => onOpenEvidence(reference)}><Eye size={14}/> Open source evidence</button>}
          </article>)}
      </div>)}
    </details>
    {!findings.length && <p className="no-findings">No cross-document conflicts or visual screening indicators were detected. This does not establish that the documents are authentic.</p>}
    {!!findings.length && <label className="finding-search">Findings search<input value={findingQuery} onChange={event => setFindingQuery(event.target.value)} placeholder="Search finding, field, or source"/></label>}
    {visibleFindings.map(finding => <article className="finding-card" key={finding.finding_id}>
      <div className="finding-heading"><b>{finding.type.replaceAll("_", " ")}</b><div className="finding-badges"><span className={`severity-pill ${(finding.severity || "low").toLowerCase()}`}>{finding.severity || "LOW"}</span><span>{finding.status.replaceAll("_", " ")}</span></div></div>
      <p>{finding.explanation}</p>
      {finding.risk_assessment_excluded && <small>Risk-score exclusion: {finding.risk_exclusion_reason}</small>}
      {finding.suggested_verification && <p className="verification-action"><b>Verify:</b> {finding.suggested_verification}</p>}
      {finding.confidence != null && <small>Heuristic confidence: {Math.round(finding.confidence * 100)}% · Not a calibrated probability</small>}
      {finding.heuristic_score != null && <small>Heuristic indicator score: {finding.heuristic_score} · Not a probability of fraud</small>}
      {decisions.find(decision => decision.finding_id === finding.finding_id) && <small className="review-state">Investigator status: {decisions.find(decision => decision.finding_id === finding.finding_id).status.replaceAll("_", " ")}</small>}
      {(finding.evidence || []).map((reference, index) => <div className="finding-evidence" key={`${reference.document_id}-${reference.page}-${index}`}>
        <b>{reference.source_filename}</b>
        <span>{reference.field ? `${reference.field}: ${reference.value}` : `Page ${reference.page}`}{reference.page ? ` · Page ${reference.page}` : ""}</span>
        {reference.evidence_text && <blockquote>{reference.evidence_text}</blockquote>}
        {reference.bbox && <small>Region: {reference.bbox.join(", ")} {reference.coordinate_system || ""}</small>}
        {reference.page && <button className="text-button" onClick={() => onOpenEvidence(reference)}><Eye size={14}/> Open source evidence</button>}
        {reference.bbox && reference.page && <AuthenticatedEvidenceImage apiBase={apiBase} token={token} reference={reference} />}
        {!reference.bbox && reference.page && <button className="text-button" onClick={() => onOpenEvidence(reference)}><Eye size={14}/> Open original at page {reference.page}</button>}
      </div>)}
      <div className="review-actions"><button disabled={busy} onClick={() => onReview(finding.finding_id, "requires_human_verification")}>Needs review</button><button disabled={busy} onClick={() => onReview(finding.finding_id, "verified_by_investigator")}>Mark verified</button><button disabled={busy} onClick={() => onReview(finding.finding_id, "dismissed_by_investigator")}>Dismiss</button></div>
    </article>)}
    <details className="dossier-json"><summary>View complete dossier data</summary><pre className="json-result">{pretty(dossier)}</pre></details>
  </div>;
}

function ClassificationResult({ data, onChange, busy }) {
  const [selected, setSelected] = useState(data.document_type || "unclassified");
  return <div className="classification-result">
    <div><small>Predicted type</small><b>{data.predicted_document_type || "unclassified"}</b></div>
    <div><small>Heuristic confidence</small><b>{Math.round((data.classification_confidence || 0) * 100)}% · Not calibrated</b></div>
    <div><small>Classification status</small><b>{data.classification_status?.replaceAll("_", " ")}</b></div>
    <label>Correct category<select value={selected} onChange={event => setSelected(event.target.value)}>{documentTypes.map(type => <option value={type} key={type}>{type.replaceAll("_", " ")}</option>)}</select></label>
    <button className="button primary" disabled={busy || selected === data.document_type} onClick={() => onChange(selected)}>Save manual correction</button>
  </div>;
}

export default function App() {
  const [files, setFiles] = useState([]);
  const [apiToken, setApiToken] = useState(
    () => sessionStorage.getItem("forensicaiApiToken") || ""
  );
  const [apiUser, setApiUser] = useState(null);
  const [authMode, setAuthMode] = useState("login");
  const [authEmail, setAuthEmail] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [managedUsers, setManagedUsers] = useState([]);
  const [newAccountEmail, setNewAccountEmail] = useState("");
  const [newAccountPassword, setNewAccountPassword] = useState("");
  const [newAccountRole, setNewAccountRole] = useState("investigator");
  const [dragging, setDragging] = useState(false);
  const [documentId, setDocumentId] = useState("");
  const [documentIds, setDocumentIds] = useState([]);
  const [uploadedDocuments, setUploadedDocuments] = useState([]);
  const [investigation, setInvestigation] = useState(null);
  const [history, setHistory] = useState([]);
  const [dashboardSummary, setDashboardSummary] = useState(null);
  const [historyQuery, setHistoryQuery] = useState("");
  const [auditEvents, setAuditEvents] = useState([]);
  const [results, setResults] = useState({});
  const [uploadProgress, setUploadProgress] = useState(0);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState("overview");
  const [apiBase, setApiBase] = useState(API_BASE);

  const completed = useMemo(() => Object.keys(results).length, [results]);
  const pageCount = results.metadata?.total_pages ?? results.forensics?.document_information?.total_pages ?? "—";
  const hash = results.fingerprint?.hash ?? results.forensics?.document_fingerprint?.hash ?? "—";
  const visibleHistory = history.filter(item =>
    `${item.investigation_id} ${item.documents.map(document => document.source_filename).join(" ")}`.toLowerCase().includes(historyQuery.toLowerCase())
  );

  async function authenticate(event) {
    event.preventDefault();
    if (!authEmail.trim() || !authPassword) {
      setError("Enter your email address and password.");
      return;
    }

    setBusy("authentication");
    setError("");
    try {
      const endpoint = authMode === "register" ? "register" : "login";
      const response = await fetch(`${apiBase.replace(/\/$/, "")}/auth/${endpoint}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: authEmail, password: authPassword })
      });
      if (!response.ok) {
        let detail = `Authentication failed (${response.status}).`;
        try {
          detail = (await response.json()).detail || detail;
        } catch {}
        throw new Error(detail);
      }
      const data = await response.json();
      sessionStorage.setItem("forensicaiApiToken", data.access_token);
      setApiUser(data.user);
      setApiToken(data.access_token);
      setAuthPassword("");
    } catch (authError) {
      setError(
        authError instanceof TypeError
          ? `Cannot reach the API at ${apiBase}. Ensure the FastAPI backend is running and the Vite proxy target is correct.`
          : authError.message || "Unable to authenticate with the API."
      );
    } finally {
      setBusy("");
    }
  }

  useEffect(() => {
    if (!apiToken) return;
    request("auth/me").then(async response => {
      const data = await response.json();
      setApiUser(data.user);
      await loadHistory(false);
    }).catch(authError => setError(`Session validation: ${authError.message}`));
  }, [apiToken]);

  async function signOut() {
    const token = apiToken;
    let logoutMessage = "";
    try {
      if (token) {
        const response = await fetch(`${apiBase.replace(/\/$/, "")}/auth/logout`, {
          method: "POST",
          headers: { Authorization: `Bearer ${token}` }
        });
        if (!response.ok) throw new Error(`Request failed (${response.status}).`);
      }
    } catch (logoutError) {
      logoutMessage = `Server sign-out failed; local session cleared. ${logoutError.message}`;
    } finally {
      sessionStorage.removeItem("forensicaiApiToken");
      setApiToken("");
      setApiUser(null);
      setFiles([]);
      setDocumentId("");
      setDocumentIds([]);
      setUploadedDocuments([]);
      setInvestigation(null);
      setResults({});
      setHistory([]);
      setDashboardSummary(null);
      setAuditEvents([]);
      setManagedUsers([]);
      setError(logoutMessage);
      setActiveTab("overview");
    }
  }

  function chooseFiles(selection) {
    const selected = Array.from(selection || []);
    if (!selected.length) return;
    if (selected.length + uploadedDocuments.length > 10) {
      setError("An investigation can include at most 10 documents.");
      return;
    }
    const allowed = [".pdf", ".jpg", ".jpeg", ".png"];
    for (const next of selected) {
      const ext = "." + (next.name.split(".").pop() || "").toLowerCase();
      if (!allowed.includes(ext)) {
        setError("Choose PDF, JPG, JPEG, or PNG files.");
        return;
      }
      if (next.size > 15 * 1024 * 1024) {
        setError("Each document must be no larger than 15 MB.");
        return;
      }
    }
    setError("");
    setFiles(selected);
  }

  async function request(path, options = {}) {
    if (!apiToken) throw new Error("Authenticate with the local API first.");
    const headers = new Headers(options.headers || {});
    headers.set("Authorization", `Bearer ${apiToken}`);
    const response = await fetch(`${apiBase.replace(/\/$/, "")}/${path}`, {
      ...options,
      headers
    });
    if (!response.ok) {
      let message = `Request failed (${response.status})`;
      try {
        const body = await response.json();
        message = body.detail || body.message || message;
      } catch {}
      if (response.status === 401) signOut();
      throw new Error(message);
    }
    return response;
  }

  async function uploadDocument() {
    if (!files.length) return setError("Select at least one document first.");
    setBusy("upload");
    setError("");
    setUploadProgress(0);
    setResults({});
    setInvestigation(null);
    const uploaded = [...uploadedDocuments];
    let uploadedFromSelection = 0;
    try {
      for (const file of files) {
        const form = new FormData();
        form.append("file", file);
        const response = await request("upload", { method: "POST", body: form });
        uploaded.push(await response.json());
        uploadedFromSelection += 1;
        setUploadProgress(Math.round(uploadedFromSelection / files.length * 100));
        setUploadedDocuments([...uploaded]);
      }
      const ids = uploaded.map(document => document.document_id);
      setDocumentIds(ids);
      setDocumentId(ids[0] || "");
      setFiles([]);
    } catch (e) {
      const ids = uploaded.map(document => document.document_id);
      setUploadedDocuments(uploaded);
      setDocumentIds(ids);
      setDocumentId(ids[0] || "");
      setFiles(files.slice(uploadedFromSelection));
      setError(`${e.message}. Earlier files were kept; retry the remaining selected files.`);
    } finally {
      setBusy("");
    }
  }

  async function runInvestigation() {
    if (!documentIds.length) return;
    setBusy("investigation");
    setError("");
    try {
      const response = await request("investigations", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ document_ids: documentIds })
      });
      const data = await response.json();
      setInvestigation(data);
      setActiveTab("investigation");
      loadHistory(false);
    } catch (e) {
      setError(`Investigation dossier: ${e.message}`);
    } finally {
      setBusy("");
    }
  }

  async function runModule(module) {
    if (!documentId) return;
    setBusy(module.key);
    setError("");
    try {
      const response = await request(`${module.path}/${documentId}`);
      const data = await response.json();
      setResults(prev => ({ ...prev, [module.key]: data }));
      setActiveTab(module.key);
    } catch (e) {
      setError(`${module.label}: ${e.message}`);
    } finally {
      setBusy("");
    }
  }

  async function runAll() {
    if (!documentId) return;
    setBusy("all");
    setError("");
    const next = {};
    for (const module of modules) {
      if (module.pdfOnly && uploadedDocuments[0]?.file_type !== ".pdf") {
        continue;
      }
      try {
        const response = await request(`${module.path}/${documentId}`);
        next[module.key] = await response.json();
        setResults(prev => ({ ...prev, [module.key]: next[module.key] }));
      } catch (e) {
        setError(`${module.label}: ${e.message}. Remaining analyses were stopped.`);
        break;
      }
    }
    setBusy("");
    setActiveTab("overview");
  }

  async function loadHistory(activate = true) {
    if (activate) {
      setBusy("history");
      setError("");
    }
    try {
      const [historyResponse, auditResponse, summaryResponse] = await Promise.all([
        request("investigations?limit=100"),
        request("audit-trail"),
        request("dashboard/summary")
      ]);
      const [historyData, auditData, summaryData] = await Promise.all([
        historyResponse.json(),
        auditResponse.json(),
        summaryResponse.json()
      ]);
      setHistory(historyData.investigations || []);
      setAuditEvents(auditData.events || []);
      setDashboardSummary(summaryData);
      if (activate) setActiveTab("history");
    } catch (e) {
      if (activate) setError(`Investigation history: ${e.message}`);
    } finally {
      if (activate) setBusy("");
    }
  }

  async function loadUsers() {
    setBusy("users");
    setError("");
    try {
      const response = await request("auth/admin/users");
      const data = await response.json();
      setManagedUsers(data.users || []);
      setActiveTab("users");
    } catch (loadError) {
      setError(`User management: ${loadError.message}`);
    } finally {
      setBusy("");
    }
  }

  async function createManagedUser(event) {
    event.preventDefault();
    setBusy("users");
    setError("");
    try {
      await request("auth/admin/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: newAccountEmail,
          password: newAccountPassword,
          role: newAccountRole
        })
      });
      setNewAccountEmail("");
      setNewAccountPassword("");
      const response = await request("auth/admin/users");
      setManagedUsers((await response.json()).users || []);
    } catch (createError) {
      setError(`Create account: ${createError.message}`);
    } finally {
      setBusy("");
    }
  }

  async function updateManagedUser(userId, changes) {
    setBusy(`user-${userId}`);
    setError("");
    try {
      await request(`auth/admin/users/${userId}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(changes)
      });
      const response = await request("auth/admin/users");
      setManagedUsers((await response.json()).users || []);
    } catch (updateError) {
      setError(`Update account: ${updateError.message}`);
    } finally {
      setBusy("");
    }
  }

  async function openHistoryInvestigation(id) {
    setBusy("history-item");
    setError("");
    try {
      const response = await request(`investigations/${id}`);
      const data = await response.json();
      const documents = data.document_overview?.documents || [];
      setInvestigation(data);
      setDocumentIds(documents.map(document => document.document_id));
      setDocumentId(documents[0]?.document_id || "");
      setUploadedDocuments(documents.map(document => ({
        document_id: document.document_id,
        filename: document.source_filename,
        file_type: `.${document.file_type}`
      })));
      setActiveTab("investigation");
    } catch (e) {
      setError(`Open investigation: ${e.message}`);
    } finally {
      setBusy("");
    }
  }

  async function updateClassification(category) {
    if (!documentId) return;
    setBusy("classification-save");
    setError("");
    try {
      const response = await request(`documents/${documentId}/classification`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ document_type: category })
      });
      const data = await response.json();
      setResults(previous => ({
        ...previous,
        classification: {
          ...previous.classification,
          document_type: data.document_type,
          manual_override: data.document_type,
          classification_status: data.classification_status
        }
      }));
    } catch (e) {
      setError(`Classification correction: ${e.message}`);
    } finally {
      setBusy("");
    }
  }

  async function reviewFinding(findingId, status) {
    if (!investigation?.investigation_id) return;
    setBusy(findingId);
    setError("");
    try {
      const response = await request(
        `investigations/${investigation.investigation_id}/findings/${findingId}/review`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            status,
            reviewer: "Local investigator",
            note: ""
          })
        }
      );
      const decision = await response.json();
      setInvestigation(previous => ({
        ...previous,
        review_decisions: [
          decision,
          ...(previous.review_decisions || []).filter(
            item => item.finding_id !== findingId
          )
        ]
      }));
    } catch (e) {
      setError(`Finding review: ${e.message}`);
    } finally {
      setBusy("");
    }
  }

  async function openEvidence(reference) {
    const path = reference.bbox
      ? `evidence-preview/${reference.document_id}/${reference.page}?bbox=${encodeURIComponent(reference.bbox.join(","))}`
      : `documents/${reference.document_id}/preview`;
    const popup = window.open("about:blank", "_blank");
    if (!popup) {
      setError("Allow pop-ups to open the protected source document.");
      return;
    }
    popup.opener = null;
    try {
      const response = await request(path);
      const objectUrl = URL.createObjectURL(await response.blob());
      popup.location.href = reference.page
        ? `${objectUrl}#page=${reference.page}`
        : objectUrl;
    } catch (openError) {
      popup.close();
      setError(`Open source evidence: ${openError.message}`);
    }
  }

  async function downloadReport() {
    if (!documentId) return;
    setBusy("report");
    setError("");
    try {
      const response = await request(`report/${documentId}`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `Forensic_Report_${documentId}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(`Report download: ${e.message}`);
    } finally {
      setBusy("");
    }
  }

  async function downloadDossier() {
    if (!investigation?.investigation_id) return;
    setBusy("dossier-report");
    setError("");
    try {
      const response = await request(`investigations/${investigation.investigation_id}/report`);
      const blob = await response.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `Investigation_Dossier_${investigation.investigation_id}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(`Dossier download: ${e.message}`);
    } finally {
      setBusy("");
    }
  }

  function reset() {
    setFiles([]); setDocumentId(""); setDocumentIds([]); setUploadedDocuments([]);
    setInvestigation(null); setResults({});
    setUploadProgress(0);
    setError(""); setActiveTab("overview");
  }

  const activeResult = results[activeTab];

  if (!apiToken) {
    return <main className="auth-gate">
      <form className="auth-card" onSubmit={authenticate}>
        <div className="brand-mark"><ShieldCheck size={22} /></div>
        <p className="eyebrow">{authMode === "register" ? "CREATE INVESTIGATOR ACCOUNT" : "SECURE ACCOUNT ACCESS"}</p>
        <h1>FORENSAI workspace</h1>
        <p>Sign in with your FORENSAI account. Access tokens expire and are revoked when you sign out.</p>
        {error && <div className="alert" role="alert"><AlertCircle size={17}/><span>{error}</span></div>}
        <label htmlFor="account-email">Email address</label>
        <input id="account-email" type="email" autoComplete="username" required value={authEmail} onChange={event => setAuthEmail(event.target.value)} />
        <label htmlFor="account-password">Password</label>
        <input id="account-password" type="password" autoComplete={authMode === "register" ? "new-password" : "current-password"} minLength={12} required value={authPassword} onChange={event => setAuthPassword(event.target.value)} />
        <button className="button primary" type="submit" disabled={busy === "authentication"}>{busy === "authentication" ? "Authenticating…" : authMode === "register" ? "Create investigator account" : "Sign in"}</button>
        <button className="text-button" type="button" onClick={() => {setAuthMode(authMode === "register" ? "login" : "register"); setError("");}}>{authMode === "register" ? "Already registered? Sign in" : "New investigator? Create an account"}</button>
        <small>API: {apiBase}</small>
      </form>
    </main>;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><div className="brand-mark"><ShieldCheck size={22} /></div><div><b>FORE<span>NSAI</span></b><small>DOCUMENT INTELLIGENCE</small></div></div>
        <div className="side-label">WORKSPACE</div>
        <button className={`nav-item ${activeTab === "overview" ? "selected" : ""}`} onClick={() => setActiveTab("overview")}><Activity size={17}/> Investigation dashboard</button>
        <button className={`nav-item ${activeTab === "history" ? "selected" : ""}`} onClick={loadHistory} disabled={busy === "history"}><History size={17}/> Investigation history</button>
        {apiUser?.role === "admin" && <button className={`nav-item ${activeTab === "users" ? "selected" : ""}`} onClick={loadUsers} disabled={busy === "users"}><Users size={17}/> User management</button>}
        <div className="side-label">ANALYSIS MODULES</div>
        {modules.map(m => <button key={m.key} className={`nav-item ${activeTab === m.key ? "selected" : ""}`} onClick={() => setActiveTab(m.key)} disabled={!documentId}><m.icon size={17}/>{m.label}{results[m.key] && <CheckCircle2 className="nav-check" size={14}/>}</button>)}
        <div className="sidebar-bottom"><div className="connection-dot"/><span>API workspace</span><small>LOCAL</small></div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div><div className="eyebrow">INVESTIGATION WORKSPACE <ChevronRight size={13}/> OVERVIEW</div><h1>Document forensics</h1><p>Upload, analyze, and generate a technical investigation report.</p></div>
          <div className="top-actions"><span className="status-pill"><span/> {apiUser?.email || "Authenticated"}</span><button className="icon-button" title="Reset workspace" onClick={reset}><X size={17}/></button><button className="button secondary" onClick={signOut}>Sign out</button></div>
        </header>

        <section className="content">
          <div className="section-heading"><div><h2>New investigation</h2><p>Upload up to 10 related documents for a joint investigation.</p></div><span className="step-tag">STEP 01 / 03</span></div>

          <div className={`upload-card ${dragging ? "dragging" : ""}`} onDragOver={e => {e.preventDefault(); setDragging(true);}} onDragLeave={() => setDragging(false)} onDrop={e => {e.preventDefault(); setDragging(false); chooseFiles(e.dataTransfer.files);}}>
            <div className="upload-symbol"><UploadCloud size={25}/></div>
            <div className="upload-copy"><h3>Drop related documents here</h3><p>or browse multiple files from your computer</p><small>PDF, JPG, JPEG, PNG <span>•</span> Up to 10 files, 15 MB each</small></div>
            <label className="button secondary browse-button">Browse files<input type="file" accept=".pdf,.jpg,.jpeg,.png" multiple onChange={e => chooseFiles(e.target.files)}/></label>
            {files.map((file, index) => <div className="file-selected" key={`${file.name}-${index}`}><FileText size={17}/><span>{file.name}</span><small>{(file.size / 1024).toFixed(1)} KB</small></div>)}
            {busy === "upload" && <div className="upload-progress"><span style={{width: `${uploadProgress}%`}}/><small>{uploadProgress}% uploaded · {Math.round(uploadProgress / 100 * files.length)} of {files.length} files</small></div>}
            <div className="upload-footer"><span><ShieldCheck size={14}/> Files are processed by your local API server.</span><button className="button primary" onClick={uploadDocument} disabled={!files.length || !!busy}>{busy === "upload" ? <><LoaderCircle className="spin" size={16}/> Uploading...</> : "Upload documents"}</button></div>
          </div>

          {error && <div className="alert"><AlertCircle size={17}/><span>{error}</span><button onClick={() => setError("")}><X size={15}/></button></div>}

          <div className="section-heading analysis-heading"><div><h2>Investigation overview</h2><p>Compare the uploaded document set and run individual checks on its first document.</p></div>{documentId && <div className="overview-actions"><button className="button secondary" onClick={runInvestigation} disabled={!!busy}>{busy === "investigation" ? <><LoaderCircle className="spin" size={16}/> Building dossier...</> : <><FileSearch size={16}/> Investigate document set</>}</button><button className="button primary" onClick={runAll} disabled={!!busy}>{busy === "all" ? <><LoaderCircle className="spin" size={16}/> Running analysis...</> : <><Activity size={16}/> Run single-document analyses</>}</button></div>}</div>

          <div className="metrics-grid dashboard-metrics">
            <Metric label="TOTAL INVESTIGATIONS" value={dashboardSummary?.total_investigations} icon={History}/>
            <Metric label="DOCUMENTS ANALYZED" value={dashboardSummary?.total_documents_analyzed} icon={FileText}/>
            <Metric label="DOCUMENTS NEEDING REVIEW" value={dashboardSummary?.documents_requiring_review} icon={Eye}/>
            <Metric label="POTENTIAL ANOMALIES" value={dashboardSummary?.potential_anomalies} icon={AlertCircle}/>
            <Metric label="COMPLETED INVESTIGATIONS" value={dashboardSummary?.completed_investigations} icon={CheckCircle2}/>
          </div>
          <div className="metrics-grid case-metrics">
            <Metric label="DOCUMENTS IN CASE" value={documentIds.length || "Awaiting upload"} icon={FileText}/>
            <Metric label="DOCUMENT PAGES" value={pageCount} icon={Layers3}/>
            <Metric label="COMPLETED MODULES" value={`${completed} / ${modules.length}`} icon={CheckCircle2}/>
            <Metric label="FINGERPRINT" value={hash === "—" ? "Not generated" : `${hash.slice(0, 12)}…`} icon={Fingerprint}/>
          </div>

          {uploadedDocuments.map(document => <div className="document-banner" key={document.document_id}><div className="doc-icon"><FileText size={21}/></div><div className="doc-details"><b>{document.filename}</b><span>Document ID: <code>{document.document_id}</code></span></div><button className="text-button" onClick={() => openEvidence({ document_id: document.document_id, page: 1 })}><Eye size={14}/> Preview</button><span className="uploaded-label"><CheckCircle2 size={14}/> Uploaded</span></div>)}

          <div className="section-heading modules-title"><div><h2>Analysis modules</h2><p>Run modules individually or execute the complete workflow.</p></div><span className="step-tag">STEP 02 / 03</span></div>
          <div className="module-grid">
            {modules.map(m => {
              const Icon = m.icon;
              const done = !!results[m.key];
              return <div className="module-card" key={m.key}><div className="module-top"><div className="module-icon"><Icon size={19}/></div>{done ? <span className="module-status done"><CheckCircle2 size={13}/> Complete</span> : <span className="module-status">Pending</span>}</div><h3>{m.label}</h3><p>{m.description}</p><button className="module-run" disabled={!documentId || !!busy} onClick={() => runModule(m)}>{busy === m.key ? <><LoaderCircle size={15} className="spin"/> Running</> : <>Run analysis <ArrowUpRight size={15}/></>}</button></div>;
            })}
          </div>

          <div className="section-heading results-heading"><div><h2>Analysis results</h2><p>Review the raw response returned by each backend endpoint.</p></div><span className="step-tag">STEP 03 / 03</span></div>
          <div className="results-panel">
            <div className="tabs"><button className={activeTab === "overview" ? "active" : ""} onClick={() => setActiveTab("overview")}>Overview</button>{investigation && <button className={activeTab === "investigation" ? "active" : ""} onClick={() => setActiveTab("investigation")}>Investigation dossier</button>}{modules.map(m => <button key={m.key} className={activeTab === m.key ? "active" : ""} onClick={() => setActiveTab(m.key)} disabled={!results[m.key]}>{m.label}</button>)}</div>
            <div className="result-body">
              {activeTab === "users" && apiUser?.role === "admin" ? <div className="admin-users">
                <div className="history-heading"><div><h3>Investigator accounts</h3><p>Create accounts, assign roles, or disable access.</p></div><button className="button secondary" onClick={loadUsers} disabled={busy === "users"}>Refresh</button></div>
                <form className="admin-create-user" onSubmit={createManagedUser}>
                  <label>Email<input type="email" required value={newAccountEmail} onChange={event => setNewAccountEmail(event.target.value)} /></label>
                  <label>Temporary password<input type="password" minLength={12} maxLength={128} required value={newAccountPassword} onChange={event => setNewAccountPassword(event.target.value)} /></label>
                  <label>Role<select value={newAccountRole} onChange={event => setNewAccountRole(event.target.value)}><option value="investigator">Investigator</option><option value="admin">Administrator</option></select></label>
                  <button className="button primary" disabled={busy === "users"}><UserCog size={15}/> Create account</button>
                </form>
                <div className="admin-user-list">{managedUsers.map(account => <article className="admin-user-row" key={account.user_id}>
                  <div><b>{account.email}</b><small>{account.user_id} · Created {new Date(account.created_at).toLocaleString()}</small></div>
                  <select value={account.role} disabled={account.user_id === apiUser.user_id || busy === `user-${account.user_id}`} onChange={event => updateManagedUser(account.user_id, { role: event.target.value })}><option value="investigator">Investigator</option><option value="admin">Administrator</option></select>
                  <span className={`severity-pill ${account.is_active ? "low" : "high"}`}>{account.is_active ? "Active" : "Disabled"}</span>
                  <button className="button secondary" disabled={account.user_id === apiUser.user_id || busy === `user-${account.user_id}`} onClick={() => updateManagedUser(account.user_id, { is_active: !account.is_active })}>{account.is_active ? "Disable" : "Enable"}</button>
                </article>)}</div>
              </div> : !documentId ? <div className="empty-state"><FileSearch size={28}/><b>No investigation loaded</b><span>Upload a document to begin forensic analysis.</span></div> :
              activeTab === "overview" ? <div className="overview-result"><div><CheckCircle2 size={20}/><b>Investigation workspace initialized</b></div><p>{completed ? `${completed} of ${modules.length} analysis modules have returned results.` : "Your document is uploaded. Run an analysis module to view its results here."}</p><div className="progress-track"><span style={{width: `${completed / modules.length * 100}%`}}/></div><small>{completed} / {modules.length} modules completed</small></div> :
              activeTab === "investigation" && investigation ? <DossierFindings dossier={investigation} apiBase={apiBase} token={apiToken} onReview={reviewFinding} busy={busy} onOpenEvidence={openEvidence} /> :
              activeTab === "history" ? <div className="history-results"><div className="history-heading"><h3>Saved investigations</h3><button className="button secondary" onClick={() => loadHistory()} disabled={busy === "history"}>{busy === "history" ? "Refreshing..." : "Refresh history"}</button></div>{history.length > 0 && <input className="history-search" value={historyQuery} onChange={event => setHistoryQuery(event.target.value)} placeholder="Search investigation ID or source filename"/>}{!history.length ? <div className="empty-state"><History size={27}/><b>No saved investigations</b><span>Complete an investigation to see it here.</span></div> : !visibleHistory.length ? <div className="empty-state"><FileSearch size={27}/><b>No matching investigations</b><span>Try a different search term.</span></div> : <div className="history-list">{visibleHistory.map(item => <article className="history-item" key={item.investigation_id}><div><b>{item.investigation_id}</b><small>{new Date(item.created_at).toLocaleString()} · {item.document_count} documents · {item.finding_count} findings</small><span>{item.documents.map(document => document.source_filename).join(", ")}</span></div><button className="button secondary" onClick={() => openHistoryInvestigation(item.investigation_id)} disabled={busy === "history-item"}>Open dossier</button></article>)}</div>}<details><summary>Audit events ({auditEvents.length})</summary><pre className="json-result">{pretty(auditEvents)}</pre></details></div> :
              activeTab === "classification" && activeResult ? <ClassificationResult key={`${activeResult.document_id}-${activeResult.document_type}`} data={activeResult} onChange={updateClassification} busy={busy === "classification-save"} /> :
              activeResult ? <pre className="json-result">{pretty(activeResult)}</pre> :
              <div className="empty-state"><Clock3 size={27}/><b>Analysis not run yet</b><span>Select “Run analysis” on this module to retrieve results.</span></div>}
            </div>
          </div>

          <div className="report-card"><div className="report-icon"><Download size={21}/></div><div><h3>Generate investigation report</h3><p>{investigation ? "Download the structured multi-document investigation dossier." : "Create a single-document technical forensic report."}</p></div>{investigation && <button className="button secondary" disabled={!!busy} onClick={downloadDossier}>{busy === "dossier-report" ? <><LoaderCircle size={16} className="spin"/> Preparing...</> : <><Download size={16}/> Download dossier</>}</button>}<button className="button primary" disabled={!documentId || !!busy} onClick={downloadReport}>{busy === "report" ? <><LoaderCircle size={16} className="spin"/> Preparing...</> : <><Download size={16}/> Download PDF report</>}</button></div>

          <div className="settings-card"><div><b>Backend connection</b><p>Change this if your FastAPI server uses a different address.</p></div><input value={apiBase} onChange={e => setApiBase(e.target.value)} aria-label="API base URL"/><span className="connection-note"><span/> Requests go to this API base URL</span></div>

          <footer>AI DOCUMENT FORENSICS SYSTEM <span>•</span> TECHNICAL ANALYSIS ONLY — DOES NOT PROVE AUTHENTICITY OR FORGERY</footer>
        </section>
      </main>
    </div>
  );
}
