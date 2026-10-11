import type { AnalysisResponse } from "./types";

interface ApiErrorResponse {
  error?: { code?: string; message?: string };
}

async function parseResponse(response: Response): Promise<AnalysisResponse> {
  if (response.ok) return response.json() as Promise<AnalysisResponse>;
  const body = (await response.json().catch(() => ({}))) as ApiErrorResponse;
  throw new Error(body.error?.message ?? "The analysis request failed.");
}

export async function analyzeFile(file: File, enrichIps = false, verifyRdns = false): Promise<AnalysisResponse> {
  const params = new URLSearchParams();
  if (enrichIps) params.set("enrich_ips", "true");
  if (verifyRdns) params.set("verify_rdns", "true");
  return parseResponse(await fetch(`/api/v1/analyze/file${params.size ? `?${params}` : ""}`, {
    method: "POST",
    headers: { "Content-Type": "application/octet-stream" },
    body: file,
  }));
}

export async function analyzeHeaders(rawHeaders: string, enrichIps = false, verifyRdns = false): Promise<AnalysisResponse> {
  return parseResponse(await fetch("/api/v1/analyze/headers", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ raw_headers: rawHeaders, enrich_ips: enrichIps, verify_rdns: verifyRdns }),
  }));
}
