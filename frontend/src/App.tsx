import { useEffect, useState, type FormEvent } from "react";
import { analyzeFile, analyzeHeaders } from "./api/client";
import type { AnalysisResponse, Evidence, Finding } from "./api/types";

type ApiState = "checking" | "online" | "offline";
type InputMode = "file" | "headers";
const MAX_FILE_BYTES = 5 * 1024 * 1024;

export default function App() {
  const [apiState, setApiState] = useState<ApiState>("checking");
  const [checkId, setCheckId] = useState(0);
  const [inputMode, setInputMode] = useState<InputMode>("file");
  const [file, setFile] = useState<File | null>(null);
  const [rawHeaders, setRawHeaders] = useState("");
  const [report, setReport] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [enrichIps, setEnrichIps] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    fetch("/api/health", { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error("API unavailable");
        return response.json();
      })
      .then(() => setApiState("online"))
      .catch((reason: unknown) => {
        if (!(reason instanceof DOMException && reason.name === "AbortError")) setApiState("offline");
      });
    return () => controller.abort();
  }, [checkId]);

  function retryApi() {
    setApiState("checking");
    setCheckId((id) => id + 1);
  }

  function clearAnalysis() {
    setReport(null);
    setError(null);
  }

  async function submitAnalysis(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    clearAnalysis();
    setAnalyzing(true);
    try {
      if (inputMode === "file") {
        if (!file) throw new Error("Choose an .eml file first.");
        if (!file.name.toLowerCase().endsWith(".eml")) throw new Error("Choose a file with the .eml extension.");
        if (file.size > MAX_FILE_BYTES) throw new Error("The .eml file must be 5 MB or smaller.");
        setReport(await analyzeFile(file, enrichIps));
      } else {
        if (!rawHeaders.trim()) throw new Error("Paste raw email headers first.");
        setReport(await analyzeHeaders(rawHeaders, enrichIps));
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "The analysis request failed.");
    } finally {
      setAnalyzing(false);
    }
  }

  function exportReport() {
    if (!report) return;
    const blob = new Blob([`${JSON.stringify(report, null, 2)}\n`], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `email-forensics-${new Date(report.analyzed_at).toISOString().replaceAll(":", "-")}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <main className="shell">
      <header className="topbar">
        <a className="wordmark" href="/" aria-label="Email Threat Forensics home">
          <span className="mark" aria-hidden="true">EF</span>
          <span>FIELDNOTE <span className="wordmark-muted">/ MAIL FORENSICS</span></span>
        </a>
        <div className="topbar-tools">
          <div className={`connection connection-${apiState}`} role="status">
            <span className="connection-dot" />
            {apiState === "checking" ? "CHECKING" : apiState === "online" ? "READY" : "OFFLINE"}
          </div>
          {apiState === "offline" && <button className="quiet-button" onClick={retryApi}>Retry</button>}
        </div>
      </header>

      <section className="workspace-heading">
        <div>
          <p className="eyebrow">CHECK AN EMAIL</p>
          <h1>Find warning signs<br /><span>before you reply.</span></h1>
          <p className="lede">See why an email may need a closer look. Links and files are never opened.</p>
        </div>
        <div className="privacy-note"><span className="privacy-mark" aria-hidden="true">●</span><span>PRIVATE SESSION<br /><small>Your email is not saved.</small></span></div>
      </section>

      <section className="analysis-layout" aria-label="Email analysis workspace">
        <form className="input-panel" onSubmit={submitAnalysis}>
          <div className="panel-heading">
            <span className="eyebrow">CHECK ANOTHER EMAIL</span>
            <span className="size-note">{inputMode === "file" ? "MAX 5 MB" : "MAX 64 KB"}</span>
          </div>
          <div className="mode-switch" role="group" aria-label="Input type">
            <button type="button" aria-pressed={inputMode === "file"} className={inputMode === "file" ? "selected" : ""} onClick={() => { setInputMode("file"); clearAnalysis(); }}>EMAIL FILE</button>
            <button type="button" aria-pressed={inputMode === "headers"} className={inputMode === "headers" ? "selected" : ""} onClick={() => { setInputMode("headers"); clearAnalysis(); }}>PASTE HEADERS</button>
          </div>

          {inputMode === "file" ? (
            <label className="file-picker">
              <span className="upload-mark" aria-hidden="true">＋</span>
              <span className="file-title">{file?.name ?? "Choose an email file"}</span>
              <span className="file-subtitle">Choose a saved .eml email file. It is checked on this device.</span>
              <input
                type="file"
                accept=".eml,message/rfc822"
                onChange={(event) => { setFile(event.target.files?.[0] ?? null); clearAnalysis(); }}
                aria-label="Choose an .eml email file"
              />
            </label>
          ) : (
            <label className="headers-field">
              <span className="field-label">Paste email header information <span>(advanced)</span></span>
              <textarea
                value={rawHeaders}
                onChange={(event) => { setRawHeaders(event.target.value); clearAnalysis(); }}
                placeholder={'From: sender@example.org\nReply-To: replies@example.net\nReceived: from ...'}
                maxLength={65_536}
                spellCheck={false}
                aria-label="Raw email headers"
              />
              <span className="field-hint">Up to 64 KB. Body content is ignored.</span>
            </label>
          )}

          {error && <p className="form-error" role="alert">{error}</p>}
          <button className="primary-button" type="submit" disabled={analyzing || apiState !== "online"}>
            {analyzing ? "CHECKING…" : "CHECK EMAIL"}<span aria-hidden="true">↗</span>
          </button>
          <p className="safe-note">Links are inspected as text. Attachments are never opened.</p>
          <label className="enrichment-choice"><input type="checkbox" checked={enrichIps} onChange={(event) => setEnrichIps(event.target.checked)} />
            <span><strong>Also check public IP registries online</strong><small>When selected, up to five public IPs are sent to their registries. MaxMind lookups use a local database when installed.</small></span>
          </label>
        </form>

        {report ? <AnalysisReport report={report} onExport={exportReport} onClear={clearAnalysis} /> : <EmptyReport apiState={apiState} />}
      </section>

      <footer className="page-footer">
        <span>EMAIL THREAT FORENSICS · LOCAL MVP</span>
        <span>No result is a claim about a person’s identity or physical location.</span>
      </footer>
    </main>
  );
}

function EmptyReport({ apiState }: { apiState: ApiState }) {
  return (
    <section className="results-panel empty-state" aria-live="polite">
      <div className="empty-symbol" aria-hidden="true">⌁</div>
      <p className="eyebrow">ANALYSIS REPORT</p>
      <h2>{apiState === "online" ? "Your results will appear here." : "The analysis service is offline."}</h2>
      <p>Choose an email or paste its header information to see any warning signs.</p>
      <div className="empty-footnote">WARNINGS INCLUDE A SHORT EXPLANATION</div>
    </section>
  );
}

function AnalysisReport({ report, onExport, onClear }: { report: AnalysisResponse; onExport: () => void; onClear: () => void }) {
  const evidence = new Map(report.evidence.map((item) => [item.evidence_ref, item]));
  return (
    <section className="results-panel" aria-live="polite" aria-label="Analysis report">
      <div className="report-heading">
        <div>
          <p className="eyebrow">YOUR RESULTS · {report.input_type === "eml" ? "EMAIL MESSAGE" : "HEADERS ONLY"}</p>
          <h2>Your results</h2>
        </div>
        <div className="report-actions">
          <button className="quiet-button" onClick={onExport}>Download report</button>
          <button className="quiet-button" onClick={onClear}>New analysis</button>
        </div>
      </div>

      <div className="assessment-row">
        <div>
          <span className="field-label">RESULT</span>
          <strong className={`assessment-value assessment-${report.classification}`}>{resultLabel(report.classification)}</strong>
          <small>{resultExplanation(report.classification)}</small>
        </div>
        <div>
          <span className="field-label">CONCERN LEVEL</span>
          <strong className={`assessment-value risk-${report.risk_level}`}>{concernLabel(report.risk_level)}</strong>
        </div>
        <time dateTime={report.analyzed_at}>{new Date(report.analyzed_at).toLocaleString()}</time>
      </div>
      <p className="assessment-caveat">These are warning signs, not proof. Check the message before acting.</p>

      <section className="report-section">
        <SectionTitle number="01" title={report.findings.length ? "Why we flagged it" : "What we checked"} count={report.findings.length} />
        {report.findings.length ? (
          <div className="finding-list">{report.findings.map((finding) => <FindingItem key={finding.rule_id} finding={finding} evidence={evidence} />)}</div>
        ) : <p className="muted-copy">We found no known warning signs. The message could still be unsafe.</p>}
      </section>

      {report.benign_indicators.length > 0 && <section className="report-section positive-signals"><SectionTitle number="+" title="Positive signs" count={report.benign_indicators.length} /><ul>{report.benign_indicators.map((signal) => <li key={signal}>{signal}</li>)}</ul></section>}

      <section className="report-section">
        <SectionTitle number="02" title="Sender checks" />
        <div className="auth-grid">{(["spf", "dkim", "dmarc"] as const).map((name) => (
          <div className="auth-item" key={name}><span>{authName(name)}</span><strong className={`auth-${report.authentication[name]}`}>{authLabel(report.authentication[name])}</strong></div>
        ))}</div>
        <p className="muted-copy">These checks try to confirm who sent the email. We only read the result written in the email, so it may be false.</p>
        <div className="alignment-list"><p><strong>Return address:</strong> {alignmentLabel(report.authentication.return_path_alignment)}</p><p><strong>SPF match:</strong> {alignmentLabel(report.authentication.spf_alignment)}</p><p><strong>DKIM match:</strong> {alignmentLabel(report.authentication.dkim_alignment)}</p><p className="muted-copy">A match means the domains share the same main domain. This uses a short list of common domain endings.</p></div>
      </section>

      {report.enrichment.status !== "not_requested" && <section className="report-section"><SectionTitle number="IP" title="IP enrichment" count={report.enrichment.ip_results.length} />
        <p className="muted-copy">{report.enrichment.note}</p>{report.enrichment.ip_results.map((item) => {
          const location = [item.city, item.region, item.country].filter(Boolean).join(", ");
          const network = item.organization || item.network;
          const coordinates = item.latitude && item.longitude ? `${item.latitude}, ${item.longitude}${item.accuracy_radius_km ? ` · about ${item.accuracy_radius_km} km accuracy radius` : ""}` : "";
          return <div className="indicator-row" key={item.address}><span>{item.address}</span><code>{[location, network, coordinates, item.registry_error].filter(Boolean).join(" · ") || "No record found"}</code></div>;
        })}
      </section>}

      <section className="report-section">
        <SectionTitle number="03" title="Mail path" count={report.routing.hops.length} />
        <details className="simple-details">
          <summary>Show technical mail path</summary>
          <p className="muted-copy">This path is reported by the email and may be incomplete or fake.</p>
          {report.routing.hops.map((hop) => (
            <div className="route-hop" key={hop.evidence_ref}>
              <span className="route-order">Server {hop.order}</span>
              <div><p>{hop.value}</p><div className="ip-list">{hop.candidate_ips.map((ip) => <span key={ip}>{ip} · {ipLabel(report.ip_indicators.find((item) => item.address === ip)?.category ?? "unknown")}</span>)}</div></div>
            </div>
          ))}
          {!report.routing.hops.length && <p className="muted-copy">No mail path details were found.</p>}
        </details>
      </section>

      <section className="report-section">
        <SectionTitle number="04" title="Links and files" count={report.url_indicators.length + report.attachments.length} />
        {report.url_indicators.map((item) => <div className="indicator-row" key={item.evidence_ref}><span>LINK</span><code>{item.scheme}://{item.host}{item.path}{item.query ? `?${item.query}` : ""}{item.redirector ? " · click tracker; destination unknown" : ""}</code></div>)}
        {report.attachments.map((item, index) => <div className="indicator-row" key={`${item.filename}-${index}`}><span>FILE</span><code>{item.filename || "Unnamed file"}</code></div>)}
        {!report.url_indicators.length && !report.attachments.length && <p className="muted-copy">No link or file details were found.</p>}
      </section>

      <section className="report-section">
        <SectionTitle number="05" title="All technical details" count={report.evidence.length} />
        <details className="simple-details">
          <summary>Show email details used in this result</summary>
          <div className="evidence-list">{report.evidence.map((item) => <EvidenceItem key={item.evidence_ref} item={item} />)}</div>
        </details>
      </section>

      <section className="report-section limitations-section">
        <SectionTitle number="06" title="Before you decide" />
        <ul>{simpleLimitations(report).map((item) => <li key={item}>{item}</li>)}</ul>
      </section>
    </section>
  );
}

function FindingItem({ finding, evidence }: { finding: Finding; evidence: Map<string, Evidence> }) {
  const [title, description] = findingCopy(finding);
  return (
    <article className="finding-item">
      <div className="finding-title-row"><h3>{title}</h3><span className={`severity severity-${finding.severity}`}>{severityLabel(finding.severity)}</span></div>
      <p>{description}</p>
      <details className="finding-evidence">
        <summary>Show why</summary>
        {finding.evidence_refs.map((ref) => {
        const item = evidence.get(ref);
        return item && <div key={ref}><span>{simpleField(item.field)}</span><code>{item.value}</code></div>;
        })}
      </details>
    </article>
  );
}

function EvidenceItem({ item }: { item: Evidence }) {
  return (
    <article className="evidence-item" id={item.evidence_ref}>
      <div><span className="field-label">{item.field}</span><span className="evidence-source">{item.source_type.replaceAll("_", " ")}</span></div>
      <code>{item.value}</code>
    </article>
  );
}

function SectionTitle({ number, title, count }: { number: string; title: string; count?: number }) {
  return <div className="section-title"><span>{number}</span><h3>{title}</h3>{count !== undefined && <small>{count}</small>}</div>;
}

function resultLabel(value: AnalysisResponse["classification"]) {
  return ({ suspicious: "Needs a closer look", inconclusive: "A small warning was found", no_known_indicators: "No warning signs found" })[value];
}

function resultExplanation(value: AnalysisResponse["classification"]) {
  return ({
    suspicious: "Some warning signs matched our checks.",
    inconclusive: "Only a low-level warning matched our checks.",
    no_known_indicators: "Our checks found no known warning signs.",
  })[value];
}

function concernLabel(value: AnalysisResponse["risk_level"]) {
  return ({ high: "High", medium: "Medium", low: "Low", undetermined: "Not rated" })[value];
}

function severityLabel(value: Finding["severity"]) {
  return ({ high: "IMPORTANT", medium: "REVIEW", low: "NOTE" })[value];
}

function authLabel(value: string) {
  const labels: Record<string, string> = { pass: "Passed", fail: "Failed", softfail: "Did not pass", neutral: "Neutral", none: "No result", temperror: "Temporary issue", permerror: "Permanent issue", unknown: "Not shown", ambiguous: "Conflicting results" };
  return labels[value] ?? value;
}

function authName(value: "spf" | "dkim" | "dmarc") {
  return ({ spf: "Sender's server", dkim: "Message signature", dmarc: "Sender's policy" })[value];
}

function alignmentLabel(value: string) {
  return ({ aligned: "Exact match", not_aligned: "No exact match", unknown: "Not enough details" })[value] ?? "Not checked";
}

function ipLabel(value: string) {
  const labels: Record<string, string> = { public: "Public address", private: "Private address", loopback: "This device", link_local: "Nearby network", multicast: "Group address", unspecified: "Unspecified", reserved: "Reserved address", unknown: "Unknown" };
  return labels[value] ?? "Unknown";
}

function findingCopy(finding: Finding): [string, string] {
  const copy: Record<string, [string, string]> = {
    reply_to_domain_mismatch: ["Sender and reply address differ", "Replies go to a different email domain from the sender."],
    reported_authentication_failure: ["An email security check failed", "The email reports a failed sender check. This report could be fake."],
    risky_attachment_extension: ["The attached file may be risky", "This file type can contain code. We did not open it."],
    credential_language_with_link: ["A password-related message includes a link", "The email mentions an account or password and includes a link."],
    link_uses_ip_address: ["A link points to a numbered address", "This link uses a number instead of a website name."],
    unencrypted_http_link: ["A link may not protect your information", "This link may not protect information sent between your device and the website."],
    display_name_address_mismatch: ["The sender name shows a different email address", "The name shown in the sender field contains an email address that does not match the actual sender address."],
    urgent_language_with_link: ["Urgent wording with a link", "The message pressures you to act and includes a link. Take a moment to check before clicking."],
    tracking_redirector: ["The link hides where it will go", "This email uses a click-tracking service. We did not open it, so the final website is unknown."],
    date_received_skew: ["The email dates do not line up", "The sender's date and the first receiving server's date differ by more than a day."],
    message_id_date_skew: ["The message ID time does not match", "A timestamp in the message ID differs from its Date field by more than a day."],
  };
  return copy[finding.rule_id] ?? [finding.title, finding.description];
}

function simpleField(value: string) {
  const labels: Record<string, string> = { From: "Sender", "Reply-To": "Reply address", Subject: "Subject", Received: "Mail path", "Authentication-Results": "Email security check", "Link destination host": "Link address", "Credential-related language": "Message text", "Attachment metadata": "File details" };
  return labels[value] ?? value;
}

function simpleLimitations(report: AnalysisResponse) {
  const notes = ["This is a basic check, not a guarantee that the email is safe.", "The email can contain false sender or server details."];
  if (report.input_type === "headers") notes.push("Only the email headers were checked. The message text and files were not available.");
  if (report.limitations.some((item) => item.includes("truncated"))) notes.push("Some message details were shortened before checking.");
  if (report.limitations.some((item) => item.includes("malformed"))) notes.push("Some parts of the message could not be read.");
  if (report.limitations.some((item) => item.includes("first 100 links"))) notes.push("Only the first 100 links were checked.");
  return notes;
}
