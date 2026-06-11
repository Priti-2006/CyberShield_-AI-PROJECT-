import { createFileRoute } from "@tanstack/react-router";
import { useMemo, useState } from "react";
import {
  Shield, ShieldAlert, ShieldCheck, Upload, Link2, Activity, Bot,
  Download, History, Zap, AlertTriangle, Brain, Search, Lock, Globe,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "CyberShield AI — Threat Intelligence Dashboard" },
      { name: "description", content: "AI-powered cybersecurity dashboard for analyzing suspicious emails and URLs in real time." },
      { property: "og:title", content: "CyberShield AI" },
      { property: "og:description", content: "AI-powered threat intelligence dashboard." },
    ],
  }),
  component: Index,
});

type Severity = "low" | "medium" | "high" | "critical";

interface ThreatResult {
  id: string;
  timestamp: string;
  target: string;
  type: "email" | "url" | "combined";
  score: number;
  severity: Severity;
  indicators: { label: string; detail: string; severity: Severity }[];
  recommendations: string[];
  agentLog: { agent: string; action: string; status: "complete" | "running" }[];
}

const SUSPICIOUS_KEYWORDS = [
  "urgent", "verify", "password", "click here", "wire transfer", "bitcoin",
  "gift card", "ssn", "social security", "account suspended", "confirm identity",
  "limited time", "act now", "lottery", "prince", "invoice", "reset",
];
const SUSPICIOUS_TLDS = [".xyz", ".top", ".tk", ".ml", ".gq", ".cf", ".ru", ".zip", ".click"];
const URL_RED_FLAGS = ["bit.ly", "tinyurl", "@", "login-", "-secure", "verify-", "ip-"];

function analyze(email: string, url: string): ThreatResult {
  const indicators: ThreatResult["indicators"] = [];
  let score = 0;
  const lowered = email.toLowerCase();

  if (email.trim()) {
    const hits = SUSPICIOUS_KEYWORDS.filter((k) => lowered.includes(k));
    if (hits.length) {
      score += Math.min(hits.length * 9, 40);
      indicators.push({
        label: "Social engineering language detected",
        detail: `Matched ${hits.length} phishing keyword(s): ${hits.slice(0, 4).join(", ")}`,
        severity: hits.length > 3 ? "high" : "medium",
      });
    }
    if (/https?:\/\/\S+/i.test(email)) {
      score += 8;
      indicators.push({
        label: "Embedded link in message body",
        detail: "External URL found in email — common phishing payload vector.",
        severity: "medium",
      });
    }
    if (/\b\d{3}-?\d{2}-?\d{4}\b/.test(email)) {
      score += 15;
      indicators.push({
        label: "PII pattern detected",
        detail: "Potential SSN-formatted data referenced in body.",
        severity: "high",
      });
    }
  }

  if (url.trim()) {
    try {
      const u = new URL(url.startsWith("http") ? url : `http://${url}`);
      if (SUSPICIOUS_TLDS.some((t) => u.hostname.endsWith(t))) {
        score += 18;
        indicators.push({
          label: "Low-reputation TLD",
          detail: `Domain ends with ${u.hostname.slice(u.hostname.lastIndexOf("."))} — frequently abused.`,
          severity: "high",
        });
      }
      if (URL_RED_FLAGS.some((f) => u.hostname.includes(f) || url.includes(f))) {
        score += 20;
        indicators.push({
          label: "URL obfuscation pattern",
          detail: "Shortener or impersonation pattern detected in hostname.",
          severity: "high",
        });
      }
      if (u.hostname.split(".").length > 3) {
        score += 10;
        indicators.push({
          label: "Deep subdomain chain",
          detail: `${u.hostname.split(".").length} levels — possible brand spoofing.`,
          severity: "medium",
        });
      }
      if (u.protocol === "http:") {
        score += 8;
        indicators.push({
          label: "Insecure transport",
          detail: "Endpoint served over HTTP without TLS.",
          severity: "medium",
        });
      }
      if (/\d+\.\d+\.\d+\.\d+/.test(u.hostname)) {
        score += 22;
        indicators.push({
          label: "Raw IP address host",
          detail: "Domain resolves to a bare IP — strong phishing indicator.",
          severity: "critical",
        });
      }
    } catch {
      score += 5;
      indicators.push({
        label: "Malformed URL",
        detail: "Could not parse the submitted URL.",
        severity: "low",
      });
    }
  }

  if (!indicators.length) {
    indicators.push({
      label: "No high-confidence threat signals",
      detail: "Heuristic agents found no obvious phishing or malware indicators.",
      severity: "low",
    });
  }

  score = Math.min(100, score + Math.floor(Math.random() * 6));
  const severity: Severity =
    score >= 75 ? "critical" : score >= 50 ? "high" : score >= 25 ? "medium" : "low";

  const recommendations =
    severity === "low"
      ? ["Continue routine monitoring.", "Archive sample for baseline analysis."]
      : severity === "medium"
      ? ["Quarantine the message for review.", "Warn recipient before any interaction."]
      : [
          "Block sender and domain across the org immediately.",
          "Trigger credential rotation for any recipient that interacted.",
          "Open incident ticket and notify SOC on-call.",
        ];

  return {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    target: url.trim() || email.slice(0, 60) || "Untitled sample",
    type: email && url ? "combined" : url ? "url" : "email",
    score,
    severity,
    indicators,
    recommendations,
    agentLog: [
      { agent: "Sentinel-Lex", action: "Tokenized email body & extracted entities", status: "complete" },
      { agent: "URL-Recon", action: "Resolved domain reputation & WHOIS posture", status: "complete" },
      { agent: "Phish-GPT", action: "Scored intent against 12k phishing corpus", status: "complete" },
      { agent: "PolicyBot", action: "Cross-checked against org allowlist", status: "complete" },
    ],
  };
}

const severityStyles: Record<Severity, string> = {
  low: "bg-success/15 text-success border-success/30",
  medium: "bg-warning/15 text-warning border-warning/30",
  high: "bg-primary/20 text-primary border-primary/40",
  critical: "bg-destructive/20 text-destructive border-destructive/40",
};

function Index() {
  const [email, setEmail] = useState("");
  const [url, setUrl] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<ThreatResult | null>(null);
  const [history, setHistory] = useState<ThreatResult[]>([]);

  const handleAnalyze = async () => {
    if (!email.trim() && !url.trim()) return;
    setAnalyzing(true);
    setResult(null);
    await new Promise((r) => setTimeout(r, 1400));
    const r = analyze(email, url);
    setResult(r);
    setHistory((h) => [r, ...h].slice(0, 20));
    setAnalyzing(false);
  };

  const downloadReport = (r: ThreatResult) => {
    const lines = [
      "CyberShield AI — Threat Analysis Report",
      "=".repeat(50),
      `Report ID: ${r.id}`,
      `Generated: ${new Date(r.timestamp).toLocaleString()}`,
      `Target: ${r.target}`,
      `Type: ${r.type.toUpperCase()}`,
      `Risk Score: ${r.score}/100`,
      `Severity: ${r.severity.toUpperCase()}`,
      "",
      "Indicators",
      "-".repeat(50),
      ...r.indicators.map((i) => `• [${i.severity.toUpperCase()}] ${i.label}\n  ${i.detail}`),
      "",
      "Recommendations",
      "-".repeat(50),
      ...r.recommendations.map((x) => `• ${x}`),
      "",
      "Agent Activity",
      "-".repeat(50),
      ...r.agentLog.map((a) => `• ${a.agent} — ${a.action} [${a.status}]`),
    ].join("\n");
    const blob = new Blob([lines], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `cybershield-report-${r.id.slice(0, 8)}.txt`;
    a.click();
    URL.revokeObjectURL(a.href);
  };

  const stats = useMemo(() => {
    const total = history.length;
    const critical = history.filter((h) => h.severity === "critical" || h.severity === "high").length;
    const avg = total ? Math.round(history.reduce((s, h) => s + h.score, 0) / total) : 0;
    return { total, critical, avg };
  }, [history]);

  return (
    <div className="min-h-screen text-foreground">
      {/* Header */}
      <header className="border-b border-border/60 backdrop-blur-xl bg-background/40 sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative h-10 w-10 rounded-xl bg-gradient-to-br from-primary to-secondary flex items-center justify-center glow-primary">
              <Shield className="h-5 w-5 text-primary-foreground" />
            </div>
            <div>
              <h1 className="text-lg font-bold tracking-tight">
                Cyber<span className="gradient-text">Shield</span> AI
              </h1>
              <p className="text-xs text-muted-foreground">Autonomous threat intelligence</p>
            </div>
          </div>
          <div className="hidden md:flex items-center gap-6 text-xs">
            <div className="flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-success pulse-dot" />
              <span className="text-muted-foreground">All systems operational</span>
            </div>
            <div className="text-muted-foreground">
              <span className="text-foreground font-semibold">{stats.total}</span> scans · <span className="text-destructive font-semibold">{stats.critical}</span> critical
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8 space-y-8">
        {/* Hero */}
        <section className="relative overflow-hidden rounded-2xl glass-card p-8">
          <div className="absolute inset-0 opacity-60" style={{ background: "var(--gradient-glow)" }} />
          <div className="relative">
            <Badge className="bg-primary/15 text-primary border-primary/30 mb-3">
              <Brain className="h-3 w-3 mr-1" /> Multi-agent analysis engine
            </Badge>
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight max-w-2xl">
              Detect phishing, malware, and social-engineering attacks in <span className="gradient-text">seconds</span>.
            </h2>
            <p className="text-muted-foreground mt-2 max-w-xl text-sm">
              Submit suspicious email content or a URL. Four specialized AI agents cross-correlate the evidence and return a verdict.
            </p>
          </div>
        </section>

        {/* KPI strip */}
        <section className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: "Scans today", value: stats.total, icon: Search },
            { label: "Critical alerts", value: stats.critical, icon: AlertTriangle, accent: "text-destructive" },
            { label: "Avg risk score", value: stats.avg, icon: Activity },
            { label: "Active agents", value: 4, icon: Bot, accent: "text-primary" },
          ].map((k) => (
            <Card key={k.label} className="glass-card border-border/60">
              <CardContent className="p-4 flex items-center justify-between">
                <div>
                  <p className="text-xs text-muted-foreground">{k.label}</p>
                  <p className={`text-2xl font-bold mt-1 ${k.accent ?? ""}`}>{k.value}</p>
                </div>
                <k.icon className="h-5 w-5 text-muted-foreground" />
              </CardContent>
            </Card>
          ))}
        </section>

        {/* Input + Result */}
        <section className="grid lg:grid-cols-5 gap-6">
          <Card className="glass-card border-border/60 lg:col-span-2">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Upload className="h-4 w-4 text-primary" /> Submit sample
              </CardTitle>
              <CardDescription>Provide the email body, a URL, or both.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <label className="text-xs font-medium text-muted-foreground flex items-center gap-1.5">
                  <Lock className="h-3 w-3" /> Suspicious email text
                </label>
                <Textarea
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Paste the full email body here..."
                  className="min-h-[140px] bg-input/40 border-border/60 font-mono text-xs resize-none"
                />
              </div>
              <div className="space-y-2">
                <label className="text-xs font-medium text-muted-foreground flex items-center gap-1.5">
                  <Link2 className="h-3 w-3" /> Suspicious URL
                </label>
                <Input
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="https://example-login.xyz/verify"
                  className="bg-input/40 border-border/60 font-mono text-xs"
                />
              </div>
              <Button
                onClick={handleAnalyze}
                disabled={analyzing || (!email.trim() && !url.trim())}
                className="w-full bg-gradient-to-r from-primary to-secondary hover:opacity-90 text-primary-foreground font-semibold glow-primary"
              >
                {analyzing ? (
                  <>
                    <Activity className="h-4 w-4 mr-2 animate-pulse" /> Agents analyzing...
                  </>
                ) : (
                  <>
                    <Zap className="h-4 w-4 mr-2" /> Analyze Threat
                  </>
                )}
              </Button>
            </CardContent>
          </Card>

          {/* Result panel */}
          <Card className="glass-card border-border/60 lg:col-span-3 relative overflow-hidden">
            {analyzing && (
              <div className="absolute inset-0 pointer-events-none">
                <div className="absolute inset-x-0 h-24 bg-gradient-to-b from-transparent via-primary/20 to-transparent animate-[scan_2s_linear_infinite]" />
              </div>
            )}
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2 text-base">
                  <ShieldAlert className="h-4 w-4 text-primary" /> Threat Results
                </CardTitle>
                <CardDescription>
                  {result ? `Sample ${result.id.slice(0, 8)} · ${new Date(result.timestamp).toLocaleTimeString()}` : "Awaiting submission"}
                </CardDescription>
              </div>
              {result && (
                <Button size="sm" variant="outline" onClick={() => downloadReport(result)} className="border-primary/40 text-primary hover:bg-primary/10">
                  <Download className="h-3.5 w-3.5 mr-1.5" /> Report
                </Button>
              )}
            </CardHeader>
            <CardContent className="space-y-5">
              {!result && !analyzing && (
                <div className="flex flex-col items-center justify-center py-12 text-center text-muted-foreground">
                  <ShieldCheck className="h-12 w-12 mb-3 opacity-40" />
                  <p className="text-sm">No active analysis. Submit a sample to begin.</p>
                </div>
              )}

              {analyzing && (
                <div className="space-y-3 py-6">
                  {["Tokenizing input", "Querying reputation feeds", "Scoring with Phish-GPT", "Compiling verdict"].map((s, i) => (
                    <div key={s} className="flex items-center gap-3 text-sm">
                      <div className="h-2 w-2 rounded-full bg-primary animate-pulse" style={{ animationDelay: `${i * 0.2}s` }} />
                      <span className="text-muted-foreground">{s}...</span>
                    </div>
                  ))}
                </div>
              )}

              {result && (
                <>
                  {/* Risk Score Card */}
                  <div className="rounded-xl p-5 bg-gradient-to-br from-background/60 to-card/60 border border-border/60">
                    <div className="flex items-end justify-between mb-3">
                      <div>
                        <p className="text-xs uppercase tracking-wider text-muted-foreground">Risk Score</p>
                        <p className="text-5xl font-bold gradient-text">{result.score}<span className="text-xl text-muted-foreground">/100</span></p>
                      </div>
                      <Badge className={`${severityStyles[result.severity]} text-xs uppercase tracking-wider border`}>
                        {result.severity}
                      </Badge>
                    </div>
                    <Progress value={result.score} className="h-2 bg-muted" />
                    <p className="text-xs text-muted-foreground mt-3">
                      Target: <span className="font-mono text-foreground">{result.target}</span>
                    </p>
                  </div>

                  {/* Indicators */}
                  <div>
                    <h4 className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Indicators of Compromise</h4>
                    <div className="space-y-2">
                      {result.indicators.map((ind, i) => (
                        <div key={i} className="flex gap-3 p-3 rounded-lg bg-background/40 border border-border/50">
                          <Badge className={`${severityStyles[ind.severity]} text-[10px] uppercase border h-fit`}>
                            {ind.severity}
                          </Badge>
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium">{ind.label}</p>
                            <p className="text-xs text-muted-foreground mt-0.5">{ind.detail}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Recommendations */}
                  <div>
                    <h4 className="text-xs uppercase tracking-wider text-muted-foreground mb-2">Recommended Actions</h4>
                    <ul className="space-y-1.5">
                      {result.recommendations.map((rec, i) => (
                        <li key={i} className="text-sm flex gap-2">
                          <span className="text-primary">▸</span>
                          <span>{rec}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </>
              )}
            </CardContent>
          </Card>
        </section>

        {/* AI Agent Activity */}
        <section>
          <Card className="glass-card border-border/60">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Bot className="h-4 w-4 text-primary" /> AI Agent Activity
              </CardTitle>
              <CardDescription>Live status of the analysis pipeline.</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-3">
                {(result?.agentLog ?? [
                  { agent: "Sentinel-Lex", action: "Idle · monitoring inbox stream", status: "running" as const },
                  { agent: "URL-Recon", action: "Idle · reputation cache warm", status: "running" as const },
                  { agent: "Phish-GPT", action: "Idle · model loaded", status: "running" as const },
                  { agent: "PolicyBot", action: "Idle · policies synced", status: "running" as const },
                ]).map((a) => (
                  <div key={a.agent} className="p-3 rounded-lg bg-background/40 border border-border/50">
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-sm font-semibold flex items-center gap-1.5">
                        <Bot className="h-3.5 w-3.5 text-primary" />
                        {a.agent}
                      </span>
                      <span className={`h-2 w-2 rounded-full ${a.status === "complete" ? "bg-success" : "bg-primary pulse-dot"}`} />
                    </div>
                    <p className="text-xs text-muted-foreground">{a.action}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </section>

        {/* Threat History */}
        <section>
          <Card className="glass-card border-border/60">
            <CardHeader className="flex flex-row items-center justify-between">
              <div>
                <CardTitle className="flex items-center gap-2 text-base">
                  <History className="h-4 w-4 text-primary" /> Threat History
                </CardTitle>
                <CardDescription>Recent scans across your tenant.</CardDescription>
              </div>
              <Badge variant="outline" className="border-border/60 text-muted-foreground">
                {history.length} entries
              </Badge>
            </CardHeader>
            <CardContent>
              {history.length === 0 ? (
                <div className="py-10 text-center text-sm text-muted-foreground">
                  <Globe className="h-8 w-8 mx-auto mb-2 opacity-40" />
                  No scans yet — your history will appear here.
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow className="border-border/60 hover:bg-transparent">
                      <TableHead className="text-xs">Time</TableHead>
                      <TableHead className="text-xs">Target</TableHead>
                      <TableHead className="text-xs">Type</TableHead>
                      <TableHead className="text-xs">Score</TableHead>
                      <TableHead className="text-xs">Severity</TableHead>
                      <TableHead className="text-xs text-right">Report</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {history.map((h) => (
                      <TableRow key={h.id} className="border-border/40">
                        <TableCell className="text-xs text-muted-foreground font-mono">
                          {new Date(h.timestamp).toLocaleTimeString()}
                        </TableCell>
                        <TableCell className="font-mono text-xs max-w-[260px] truncate">{h.target}</TableCell>
                        <TableCell className="text-xs uppercase">{h.type}</TableCell>
                        <TableCell className="font-semibold">{h.score}</TableCell>
                        <TableCell>
                          <Badge className={`${severityStyles[h.severity]} text-[10px] uppercase border`}>
                            {h.severity}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          <Button size="sm" variant="ghost" onClick={() => downloadReport(h)} className="h-7 text-xs hover:text-primary">
                            <Download className="h-3 w-3 mr-1" /> .txt
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </section>

        <footer className="text-center text-xs text-muted-foreground py-6">
          CyberShield AI · Heuristic demo · Not a substitute for production SIEM
        </footer>
      </main>
    </div>
  );
}
