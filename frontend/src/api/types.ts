export type AuthStatus = "pass" | "fail" | "softfail" | "neutral" | "none" | "temperror" | "permerror" | "unknown" | "ambiguous";

export interface Evidence {
  evidence_ref: string;
  evidence_refs: string[];
  field: string;
  value: string;
  source_type: "email_header" | "email_body" | "attachment_metadata";
}

export interface Finding {
  rule_id: string;
  title: string;
  description: string;
  severity: "high" | "medium" | "low";
  source_type: "deterministic_rule";
  evidence_refs: string[];
}

export interface AnalysisResponse {
  schema_version: "1.0";
  analyzed_at: string;
  input_type: "eml" | "headers";
  classification: "suspicious" | "inconclusive" | "no_known_indicators";
  risk_level: "high" | "medium" | "low" | "undetermined";
  findings: Finding[];
  evidence: Evidence[];
  attachments: { filename: string | null; content_type: string; disposition: string | null; size_bytes: number | null }[];
  url_indicators: { evidence_ref: string; host: string; scheme: "http" | "https"; path: string; query: string | null; redirector: boolean; position: number | null; anchor_text: string | null; image_link: boolean; button_link: boolean; visible_text_mismatch: boolean }[];
  unique_targets: { host: string; path: string; evidence_refs: string[] }[];
  ip_indicators: { address: string; category: "public" | "private" | "loopback" | "link_local" | "multicast" | "unspecified" | "reserved"; evidence_refs: string[] }[];
  benign_indicators: string[];
  authentication: { spf: AuthStatus; dkim: AuthStatus; dmarc: AuthStatus; source: string; evidence_refs: string[]; from_domain: string | null; return_path_domain: string | null; return_path_alignment: "aligned" | "not_aligned" | "unknown"; dkim_domains: string[]; spf_alignment: "aligned" | "not_aligned" | "unknown"; dkim_alignment: "aligned" | "not_aligned" | "unknown"; alignment_note: string };
  routing: {
    status: "available" | "insufficient_evidence";
    ordering: "received_headers_reversed_oldest_first";
    hops: { order: number; evidence_ref: string; value: string; candidate_ips: string[] }[];
    note: string;
  };
  classifier: { status: "not_configured"; label: null; note: string };
  enrichment: { status: "not_requested" | "not_configured" | "complete" | "partial" | "unavailable"; ip_results: Record<string, string>[]; note: string };
  limitations: string[];
}
