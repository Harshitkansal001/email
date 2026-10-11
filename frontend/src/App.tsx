import { useEffect, useState } from "react";

type ApiState = "checking" | "online" | "offline";

export default function App() {
  const [apiState, setApiState] = useState<ApiState>("checking");

  useEffect(() => {
    fetch("/api/health")
      .then((response) => {
        if (!response.ok) throw new Error("API unavailable");
        return response.json();
      })
      .then(() => setApiState("online"))
      .catch(() => setApiState("offline"));
  }, []);

  return (
    <main className="shell">
      <header className="topbar">
        <a className="wordmark" href="/" aria-label="Email Threat Forensics home">
          <span className="mark" aria-hidden="true">EF</span>
          <span>FIELDNOTE <span className="wordmark-muted">/ MAIL FORENSICS</span></span>
        </a>
        <div className={`connection connection-${apiState}`} role="status">
          <span className="connection-dot" />
          {apiState === "checking" ? "CONNECTING" : apiState === "online" ? "LOCAL API READY" : "API OFFLINE"}
        </div>
      </header>

      <section className="intro">
        <p className="eyebrow">EMAIL THREAT FORENSICS · LOCAL WORKSPACE</p>
        <h1>Evidence first.<br /><span>Conclusions with context.</span></h1>
        <p className="lede">A private workbench for examining suspicious email, its observable route, and the signals behind an assessment.</p>
      </section>

      <section className="setup-card" aria-labelledby="setup-title">
        <div className="card-index">01 / READY TO BUILD</div>
        <div>
          <h2 id="setup-title">Analysis workspace</h2>
          <p>The local app is connected. Email parsing and analysis will be added next.</p>
        </div>
        <div className="capabilities" aria-label="Planned inputs">
          <span>.eml FILE</span>
          <span>RAW HEADERS</span>
          <span>JSON REPORT</span>
        </div>
      </section>

      <footer>
        <span>LOCAL ONLY</span>
        <span>Nothing is analyzed or retained by this starter yet.</span>
      </footer>
    </main>
  );
}
