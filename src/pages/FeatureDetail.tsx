import { useParams, Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogTrigger, DialogTitle } from "@/components/ui/dialog";
import { ArrowLeft, Check, Shield, Zap, Lock, Scan, Code2, Server, Globe, Database, FileText, ChevronRight, Terminal } from "lucide-react";
import { useEffect } from "react";
import MermaidDiagram from "@/components/MermaidDiagram";
import { ZoomPanViewer } from "@/components/ZoomPanViewer";

const FeatureDetail = () => {
    const { featureId } = useParams();

    useEffect(() => {
        window.scrollTo(0, 0);
    }, [featureId]);

    const features = {
        "advanced-active-scanning": {
            title: "Advanced Active Scanning",
            subtitle: "The Core of SentinelX",
            icon: Scan,
            color: "text-blue-500",
            bg: "bg-blue-500/10",
            abstract: "Traditional DAST tools rely on static pattern matching, often failing to detect vulnerabilities in complex, single-page applications (SPAs) or APIs where context determines exploitability. SentinelX introduces a context-aware feedback loop that dynamically adjusts payloads based on real-time server responses, significantly reducing false negatives while conducting deep-logic verification.",
            methodology: (
                <div className="space-y-4 text-muted-foreground leading-relaxed">
                    <p>
                        Our approach utilizes a <strong>Feedback-Loop Fuzzing Engine</strong>. Unlike linear scanners that fire-and-forget, SentinelX analyzes the HTTP response (headers, body, timing) of each request to determine the next payload iteration.
                    </p>
                    <p>
                        For <strong>Time-Based Blind SQL Injection</strong>, we employ a statistical deviation model. Instead of a fixed timeout, the engine calculates the baseline latency of the target endpoint over 20 requests. It then injects sleep commands (`WAITFOR DELAY`, `pg_sleep`) with randomized durations. A vulnerability is confirmed only if the response latency strictly correlates with the injected duration across multiple trials (`p &lt; 0.01`).
                    </p>
                    <p>
                        This methodology allows us to bypass WAFs that filter static signatures, as our payloads are mutated dynamically to evade detection while maintaining functional exploitability.
                    </p>
                </div>
            ),
            codeSnippet: `// Core logic for Time-Based Analysis
async function verifyTimeBased(target: string, latencyBaseline: number) {
  const payloads = generatePolyglotPayloads('SQLi');
  
  for (const payload of payloads) {
    const start = performance.now();
    await fetch(target, { method: 'POST', body: payload });
    const duration = performance.now() - start;

    // Statistical significance check using Z-score
    const zScore = (duration - latencyBaseline) / stdDev;
    
    if (zScore > 3.5) { // 99.9% confidence interval
      return { 
        vuln: true, 
        vector: payload, 
        confidence: 'High' 
      };
    }
  }
}`,
            diagram: (
                <div className="relative p-6 bg-[#0d1117] rounded-xl border border-white/10 font-mono text-xs overflow-hidden h-full flex flex-col justify-center">
                    <div className="absolute top-0 right-0 p-2 opacity-20">
                        <Scan className="w-24 h-24 text-blue-500" />
                    </div>
                    <div className="space-y-4 relative z-10 w-full max-w-sm mx-auto">
                        <div className="flex items-center justify-between gap-2 p-2 rounded bg-white/5 border border-white/5">
                            <span className="text-blue-400">Target Phase</span>
                            <span className="text-white">Heuristic Analysis</span>
                        </div>
                        <div className="flex justify-center">
                            <div className="h-6 w-0.5 bg-white/10" />
                        </div>
                        <div className="p-3 border-l-2 border-blue-500 bg-blue-500/5 space-y-2">
                            <div className="flex justify-between text-slate-400">
                                <span>Payload A</span>
                                <span className="text-yellow-400 font-mono">1' OR '1'='1</span>
                            </div>
                            <div className="flex justify-between text-slate-400">
                                <span>Response</span>
                                <span className="text-red-400">STATUS 500</span>
                            </div>
                        </div>
                        <div className="flex justify-center">
                            <div className="h-6 w-0.5 bg-white/10" />
                        </div>
                        <div className="p-3 border-l-2 border-green-500 bg-green-500/5 space-y-2">
                            <div className="text-center text-green-400 font-bold mb-1">Feedback Loop Triggered</div>
                            <div className="flex justify-between text-slate-400">
                                <span>Payload B</span>
                                <span className="text-green-300 font-mono">1' UNION SELECT...</span>
                            </div>
                            <div className="flex justify-between text-slate-400">
                                <span>Result</span>
                                <span className="text-green-400">DATA EXFILTRATED</span>
                            </div>
                        </div>
                    </div>
                </div>
            ),
            capabilities: [
                {
                    title: "Time-Based Blind SQLi",
                    desc: "Injects sleep() commands and measures response latency to detect DB vulnerabilities without error messages."
                },
                {
                    title: "Polyglot Payloads",
                    desc: "Uses advanced payload chains that simultaneously test for XSS, SQLi, and SSTI in a single request."
                },
                {
                    title: "DOM-Based Analysis",
                    desc: "Executes JavaScript in a headless browser to detect client-side sinks and sources."
                }
            ],
            technicalSpecs: [
                "Payloads: 5,000+ curated vectors",
                "Engine: Rust + V8 (Deno)",
                "Concurrency: 100+ threads/worker",
                "False Positive Rate: < 0.1%"
            ],
            mermaid: `graph TD
    A[Start Scan] --> B{Context Analysis}
    B -->|SPA Detected| C[Headless Browser]
    B -->|API Detected| D[Schema Fuzzing]
    
    C --> E[DOM Tree Analysis]
    E --> F{Sinks Found?}
    F -->|Yes| G[Payload Generator]
    F -->|No| H[Passive Checks]
    
    D --> G
    G --> I[Inject Payload]
    I --> J{Response Analysis}
    J -->|Latency > 2s| K[Confirm Time-Based SQLi]
    J -->|Error Pattern| L[Infer Logic Flaw]
    
    K --> M[Report Vulnerability]
    L --> G
    M --> N[End Loop]
    style A fill:#1e293b,stroke:#3b82f6,color:#fff
    style K fill:#ef4444,stroke:#ef4444,color:#fff
    style M fill:#22c55e,stroke:#22c55e,color:#fff`
        },
        "cloud-native-security": {
            title: "Cloud-Native Security",
            subtitle: "Total Visibility",
            icon: Globe,
            color: "text-purple-500",
            bg: "bg-purple-500/10",
            abstract: "Modern microservices expose unique attack surfaces that traditional network scanners miss. Cloud-Native Security in SentinelX focuses on the intersection of application logic and infrastructure, targeting metadata services (IMDS), serverless function event data, and container orchestration APIs.",
            methodology: (
                <div className="space-y-4 text-muted-foreground leading-relaxed">
                    <p>
                        We use a <strong>Recursive Cloud Discovery</strong> technique. The scanner first attempts to identify the hosting environment (AWS, GCP, Azure, Kubernetes) by probing well-known internal IPs (e.g., `169.254.169.254`) and analyzing specific HTTP response headers (`Server: ECS`, `X-Amz-RequestId`).
                    </p>
                    <p>
                        Once identifed, SentinelX switches to a specialized payload set. For SSRF validation, we don't just check for connection; we attempt to extract non-sensitive metadata (like instance ID or region) to prove impact without triggering security alarms or accessing privileged credentials, adhering to "Safe Exploitation" principles.
                    </p>
                </div>
            ),
            codeSnippet: `// Cloud Metadata SSRF Detection
const IMDS_VECTORS = {
  aws: "http://169.254.169.254/latest/meta-data/",
  gcp: "http://metadata.google.internal/computeMetadata/v1/",
  azure: "http://169.254.169.254/metadata/instance"
};

async function checkCloudMetadata(entryPoint: string) {
  const environment = await fingerprintEnv(entryPoint);
  
  if (environment === 'AWS') {
    // Attempt Token Retrieval (IMDSv2)
    const token = await fetchWithHeader(IMDS_VECTORS.aws, 
      { 'X-aws-ec2-metadata-token-ttl-seconds': '21600' }
    );
    
    if (token) return reportVuln('SSRF confirmed (AWS IMDSv2 access)');
  }
}`,
            diagram: (
                <div className="relative p-6 bg-[#0d1117] rounded-xl border border-white/10 font-mono text-xs overflow-hidden h-full flex flex-col justify-center">
                    <div className="grid grid-cols-3 gap-4 text-center mb-8">
                        <div className="p-3 bg-white/5 rounded border border-white/5 opacity-50">
                            <Server className="w-6 h-6 mx-auto mb-2 text-purple-400" />
                            <div className="text-purple-200">App</div>
                        </div>
                        <div className="flex items-center justify-center">
                            <div className="h-0.5 w-full bg-gradient-to-r from-white/10 to-purple-500 animate-pulse" />
                        </div>
                        <div className="p-3 bg-white/5 rounded border border-white/5 ring-1 ring-purple-500 shadow-[0_0_15px_rgba(168,85,247,0.3)]">
                            <Database className="w-6 h-6 mx-auto mb-2 text-teal-400" />
                            <div className="text-teal-200">Metadata API</div>
                        </div>
                    </div>
                    <div className="space-y-2 font-mono text-xs bg-black/40 p-3 rounded-lg border border-white/5">
                        <div className="flex gap-2">
                            <span className="text-purple-400">GET</span>
                            <span className="text-slate-300">/latest/meta-data/iam/security-credentials/</span>
                        </div>
                        <div className="flex gap-2">
                            <span className="text-green-400">200 OK</span>
                            <span className="text-slate-500">{"{ \"Code\": \"Success\", ... }"}</span>
                        </div>
                    </div>
                </div>
            ),
            capabilities: [
                {
                    title: "SSRF on Metadata Services",
                    desc: "Specifically targets 169.254.169.254 to detect exposed cloud credentials on AWS, GCP, and Azure."
                },
                {
                    title: "GraphQL Introspection",
                    desc: "Automatically maps out entire GraphQL schemas and tests for uncontrolled depth and excessive complexity."
                },
                {
                    title: "Subdomain Takeover",
                    desc: "Checks for dangling CNAME records pointing to unclaimed S3 buckets or GitHub pages."
                }
            ],
            technicalSpecs: [
                "Cloud Providers: AWS, GCP, Azure",
                "Protocols: HTTP/1.1, HTTP/2, gRPC",
                "Discovery: Passive DNS + Certificate Transparency",
                "Orchestration: Kubernetes Native"
            ],
            mermaid: `graph LR
    A[Scanner] --> B{Env Detection}
    B -->|AWS| C[IMDSv2 Check]
    B -->|GCP| D[Metadata Header]
    B -->|K8s| E[Service Account]

    C --> F{Token Acquired?}
    F -->|Yes| G[SSRF Confirmed]
    F -->|No| H[Try Legacy Paths]

    G --> I[Extract Instance ID]
    I --> J[Validate Impact]
    J --> K[Report Finding]

    style G fill:#ef4444,stroke:#ef4444,color:#fff
    style K fill:#22c55e,stroke:#22c55e,color:#fff`
        },
        "modern-auth-testing": {
            title: "Modern Auth Testing",
            subtitle: "Identity is the Perimeter",
            icon: Lock,
            color: "text-amber-500",
            bg: "bg-amber-500/10",
            abstract: "Authentication has moved from simple session cookies to complex stateless tokens (JWT) and delegated flows (OAuth 2.0). These protocols are robust in theory but fragile in implementation. SentinelX creates a comprehensive model of the authentication state machine to identify logic flaws.",
            methodology: (
                <div className="space-y-4 text-muted-foreground leading-relaxed">
                    <p>
                        We utilize <strong>Token Entropy Analysis</strong> and <strong>State Replay</strong>. SentinelX captures valid session tokens and subjects them to cryptographic analysis (detecting weak secrets in HS256) and structural mutation (none-algorithm exploits).
                    </p>
                    <p>
                        For IDOR (Insecure Direct Object Reference) detection, the engine runs parallel sessions: User A and User B. It replays User A's requests using User B's session signals. If the server responds with a 200 OK and data belonging to User A, an IDOR is flagged. This requires intelligent differentiation between "public" data and "private" user data.
                    </p>
                </div>
            ),
            codeSnippet: `// IDOR Detection Logic (Simplified)
async function testIDOR(resourceId: string, userBSession: Session) {
  // 1. Fetch resource as Owner (User A) - Establish Baseline
  const original = await fetchResource(resourceId, userASession);

  // 2. Replay request as Attacker (User B)
  const replay = await fetchResource(resourceId, userBSession);

  // 3. Compare Responses
  if (replay.status === 200 && compareContent(original, replay) > 0.95) {
     // If User B sees 95% same content as User A
     return { vulnerability: 'IDOR', resource: resourceId };
  }
}`,
            diagram: (
                <div className="relative p-6 bg-[#0d1117] rounded-xl border border-white/10 font-mono text-xs h-full flex flex-col justify-center">
                    <div className="space-y-4">
                        <div className="flex justify-between items-center text-slate-300">
                            <span>JWT Header Analysis</span>
                            <Badge variant="outline" className="text-green-400 border-green-500/30 bg-green-500/10 p-1 px-2 h-auto text-[10px]">PASS</Badge>
                        </div>
                        <div className="p-2 bg-slate-800 rounded text-slate-400 truncate text-[10px]">
                            {"eyJhbGciOiJSUzI1NiJ9..."}
                        </div>

                        <div className="flex justify-between items-center text-slate-300 mt-4">
                            <span>Signature Stripping Attack</span>
                            <Badge variant="outline" className="text-red-400 border-red-500/30 bg-red-500/10 p-1 px-2 h-auto text-[10px]">VULNERABLE</Badge>
                        </div>
                        <div className="relative">
                            <div className="p-2 bg-amber-500/10 border border-amber-500/30 rounded text-amber-200 truncate text-[10px] pr-20">
                                {"eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."}
                            </div>
                            <div className="absolute top-1/2 -translate-y-1/2 right-2 flex items-center gap-1 text-red-400 text-[10px] font-bold">
                                <Zap className="w-3 h-3 fill-current" />
                                <span>ACCEPTED</span>
                            </div>
                        </div>
                        <div className="p-2 bg-black/40 rounded border border-white/5 text-[10px] text-slate-400">
                            &gt; Server accepted unsigned JWT with 'alg: none'
                        </div>
                    </div>
                </div>
            ),
            capabilities: [
                {
                    title: "OAuth 2.0 Audits",
                    desc: "Checks for weak redirect_uris, state parameter leakage, and implicit grant vulnerabilities."
                },
                {
                    title: "JWT Attack Suite",
                    desc: "Tests for 'none' algorithm, weak secrets (HMAC brute-force), and key confusion attacks."
                },
                {
                    title: "IDOR Detection",
                    desc: "Replays traffic with swapped user IDs to detect Insecure Direct Object References."
                }
            ],
            technicalSpecs: [
                "Auth Types: Bearer, Cookie, Basic, Digest",
                "OAuth Flows: Code, Implicit, Client Creds",
                "Dictionary: 10M+ Common Passwords",
                "Logic: Stateful Session Replay"
            ],
            mermaid: `sequenceDiagram
    participant A as User A (Victim)
    participant S as SentinelX
    participant B as User B (Attacker)
    participant API as Target API

    note over A,API: Baseline Establishment
    S->>API: Login as User A
    API-->>S: Session Token A
    S->>API: GET /api/profile/101 (Token A)
    API-->>S: 200 OK {Data: "User A Sensitive"}

    note over S,API: IDOR Attack Phase
    S->>API: Login as User B
    API-->>S: Session Token B
    S->>API: GET /api/profile/101 (Token B)
    
    alt Vulnerable
        API-->>S: 200 OK {Data: "User A Sensitive"}
        S->>S: Flag IDOR Vulnerability
    else Secure
        API-->>S: 403 Forbidden
        S->>S: Mark Secure
    end`
        },
        "unified-reporting": {
            title: "Unified Reporting",
            subtitle: "Compliance Ready",
            icon: FileText,
            color: "text-green-500",
            bg: "bg-green-500/10",
            abstract: "Security data is useless if it's not actionable. The Unified Reporting engine in SentinelX is designed to bridge the gap between DevSecOps and C-Level compliance needs. It aggregates findings from all scanners, normalizes the data, and maps it to industry standards automatically.",
            methodology: (
                <div className="space-y-4 text-muted-foreground leading-relaxed">
                    <p>
                        We act as a <strong>Data Normalization Layer</strong>. Raw findings from SQLi scanners, SSL analyzers, and Cloud audits are ingested into a central JSON schema. This schema is enriched with CVSS v3.1 vector calculations and context-aware risk scoring.
                    </p>
                    <p>
                        For compliance mapping, we utilize a many-to-many relationship graph. A single finding (e.g., "Unencrypted S3 Bucket") is simultaneously mapped to PCI-DSS 3.4 (Protect stored cardholder data), HIPAA 164.312 (Encryption), and SOC2 CC6.1. This automated cross-referencing saves hundreds of hours of manual audit preparation.
                    </p>
                </div>
            ),
            codeSnippet: `// Auto-Mapping Logic
interface RiskFinding {
  id: string;
  vector: string;
  cwe_id: number; // Common Weakness Enumeration
}

function enrichFinding(finding: RiskFinding): ComplianceReport {
  const complianceMap = loadComplianceDatabase();
  
  return {
    ...finding,
    cvss_score: calculateCVSS(finding.vector),
    compliance: {
      pci_dss: complianceMap.pci.filter(r => r.cwe_includes.has(finding.cwe_id)),
      soc2: complianceMap.soc2.filter(r => r.cwe_includes.has(finding.cwe_id)),
      iso27001: complianceMap.iso27001.filter(r => r.cwe_includes.has(finding.cwe_id))
    },
    remediation_playbook: getPlaybook(finding.cwe_id)
  };
}`,
            mermaid: `graph TD
    A[Raw Findings] --> B[Data Normalization]
    B --> C{Map to Standards}
    C -->|Finding: Unencrypted S3| D[PCI-DSS 3.4]
    C -->|Finding: No MFA| E[SOC2 CC6.1]
    
    D --> F[Risk Scoring Engine]
    E --> F
    
    F --> G{CVSS Calculator}
    G --> H[Generate Score: 9.8]
    
    H --> I[Output Artifacts]
    I --> J[PDF Report]
    I --> K[SARIF JSON]
    I --> L[Jira Ticket]

    style H fill:#ef4444,stroke:#ef4444,color:#fff
    style J fill:#22c55e,stroke:#22c55e,color:#fff`,
            capabilities: [
                {
                    title: "One-Click PDF/JSON",
                    desc: "Generate auditor-friendly PDFs or machine-readable JSON for your SIEM integration."
                },
                {
                    title: "Compliance Mapping",
                    desc: "Automatically tags vulnerabilities with relevant ISO 27001, SOC2, and PCI-DSS controls."
                },
                {
                    title: "Developer Reproducibility",
                    desc: "Every finding comes with a generated `curl` command to instantly reproduce the issue."
                }
            ],
            technicalSpecs: [
                "Formats: PDF, JSON, XML, HTML",
                "Standards: CVSS v3.1, OWASP Top 10",
                "Integrations: Jira, Slack, GitHub Issues",
                "Data Retention: Configurable"
            ]
        }
    };

    const data = features[featureId as keyof typeof features];

    if (!data) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-background text-foreground">
                <div className="text-center">
                    <h1 className="text-4xl font-bold mb-4">Feature Not Found</h1>
                    <Button asChild><Link to="/">Return Home</Link></Button>
                </div>
            </div>
        );
    }

    const Icon = data.icon;

    return (
        <div className="min-h-screen bg-background text-foreground antialiased selection:bg-primary/20 pb-20">
            {/* Nav */}
            <nav className="fixed top-0 w-full bg-background/80 backdrop-blur-xl border-b border-border/40 z-50">
                <div className="container mx-auto px-6 h-20 flex items-center justify-between">
                    <Link to="/" className="flex items-center text-muted-foreground hover:text-primary transition-colors">
                        <ArrowLeft className="h-5 w-5 mr-2" />
                        <span className="font-medium">Back to Overview</span>
                    </Link>
                    <div className="flex items-center space-x-3">
                        <Shield className="h-6 w-6 text-primary" />
                        <span className="text-xl font-bold tracking-tight">SentinelX</span>
                    </div>
                </div>
            </nav>

            <main className="pt-32 container mx-auto px-6">
                {/* Header */}
                <div className="max-w-4xl mx-auto text-center mb-20">
                    <div className={`inline-flex p-4 rounded-2xl ${data.bg} mb-8`}>
                        <Icon className={`h-12 w-12 ${data.color}`} />
                    </div>
                    <Badge variant="outline" className="mb-6 py-1.5 px-4 text-sm border-primary/20 text-primary bg-primary/5 uppercase tracking-wider">
                        {data.subtitle}
                    </Badge>
                    <h1 className="text-5xl md:text-6xl font-bold mb-8 tracking-tight">{data.title}</h1>
                    <p className="text-xl md:text-2xl text-muted-foreground leading-relaxed max-w-3xl mx-auto font-light">
                        {data.abstract}
                    </p>
                </div>

                {/* Main Content Grid */}
                <div className="max-w-7xl mx-auto">

                    {/* Methodology & Architecture Section */}
                    <div className="grid lg:grid-cols-12 gap-12 mb-20">
                        {/* Left: Text Content */}
                        <div className="lg:col-span-7 space-y-12">
                            <div>
                                <h2 className="text-3xl font-bold mb-6 flex items-center">
                                    <Code2 className="w-6 h-6 mr-3 text-primary" />
                                    Engineering Methodology
                                </h2>
                                <div className="prose prose-invert prose-lg max-w-none border-l-2 border-primary/20 pl-6">
                                    {data.methodology}
                                </div>
                            </div>

                            <div>
                                <h3 className="text-xl font-bold mb-4 flex items-center text-foreground/80">
                                    <Terminal className="w-5 h-5 mr-3" />
                                    Implementation Logic
                                </h3>
                                <div className="mockup-code bg-[#0d1117] border border-white/10 rounded-xl overflow-hidden shadow-2xl">
                                    <pre className="p-6 text-sm font-mono text-blue-100 overflow-x-auto">
                                        <code>{data.codeSnippet}</code>
                                    </pre>
                                </div>
                            </div>
                        </div>

                        {/* Right: Visuals & Specs */}
                        <div className="lg:col-span-5 space-y-8">
                            {/* Visual Diagram */}
                            <Dialog>
                                <DialogTrigger asChild>
                                    <div className="h-[400px] rounded-2xl border border-border/50 bg-card/30 backdrop-blur shadow-2xl overflow-hidden p-1 group hover:border-primary/30 transition-all hover:scale-[1.02] cursor-pointer relative">
                                        <div className="absolute top-4 right-4 z-10 bg-black/50 backdrop-blur px-3 py-1 rounded-full text-xs text-white/70 opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-2">
                                            <Scan className="w-3 h-3" />
                                            Click to Expand
                                        </div>
                                        <div className="bg-[#0d1117] rounded-xl h-full w-full overflow-hidden pointer-events-none">
                                            <MermaidDiagram chart={data.mermaid} />
                                        </div>
                                    </div>
                                </DialogTrigger>
                                <DialogContent className="max-w-[90vw] h-[80vh] bg-[#0d1117] border-white/10 p-0 overflow-hidden flex flex-col">
                                    <DialogTitle className="sr-only">Diagram View</DialogTitle>
                                    <div className="flex items-center justify-between p-4 border-b border-white/10 bg-white/5 z-50 relative">
                                        <div className="flex items-center gap-2">
                                            <Badge variant="outline" className={`${data.color} ${data.bg} border-current`}>
                                                {data.title}
                                            </Badge>
                                            <span className="text-sm text-muted-foreground">Architecture Flow (Interactive)</span>
                                        </div>
                                    </div>
                                    <div className="flex-1 w-full h-full overflow-hidden bg-[#0d1117] relative">
                                        <ZoomPanViewer>
                                            <div className="min-w-[800px] min-h-[600px] flex items-center justify-center">
                                                <MermaidDiagram chart={data.mermaid} />
                                            </div>
                                        </ZoomPanViewer>
                                    </div>
                                </DialogContent>
                            </Dialog>

                            {/* Specs */}
                            <div className="p-8 rounded-3xl border border-primary/10 bg-gradient-to-br from-primary/5 to-transparent relative overflow-hidden">
                                <h3 className="text-lg font-bold mb-6 flex items-center">
                                    <Server className="w-5 h-5 mr-2 text-primary" />
                                    Technical Specifications
                                </h3>
                                <div className="grid gap-4">
                                    {data.technicalSpecs.map((spec, i) => (
                                        <div key={i} className="flex items-center text-sm text-foreground/80 bg-background/40 p-4 rounded-xl border border-white/5 hover:bg-background/60 transition-colors">
                                            <div className="h-2 w-2 rounded-full bg-primary mr-3 shadow-[0_0_8px_rgba(124,58,237,0.5)]" />
                                            {spec}
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Capabilities Bottom Section */}
                    <div className="border-t border-border/40 pt-16">
                        <h2 className="text-3xl font-bold mb-10 text-center">Core Capabilities</h2>
                        <div className="grid md:grid-cols-3 gap-8">
                            {data.capabilities.map((cap, idx) => (
                                <div key={idx} className="group p-8 rounded-3xl border border-border/50 bg-card/10 hover:bg-card/30 hover:border-primary/20 transition-all duration-300">
                                    <div className="mb-4 p-3 bg-primary/10 rounded-xl inline-block group-hover:bg-primary/20 transition-colors">
                                        <Check className="w-6 h-6 text-primary" />
                                    </div>
                                    <h3 className="text-xl font-bold mb-3 text-foreground group-hover:text-primary transition-colors">
                                        {cap.title}
                                    </h3>
                                    <p className="text-muted-foreground leading-relaxed text-sm">
                                        {cap.desc}
                                    </p>
                                </div>
                            ))}
                        </div>
                    </div>

                    <div className="mt-20 text-center">
                        <Button size="lg" className="h-14 px-10 text-lg rounded-full shadow-lg shadow-primary/20 hover:shadow-primary/30" asChild>
                            <a href="https://github.com/Armaan42/SentinelX" target="_blank" rel="noopener noreferrer">
                                View Source Code on GitHub
                                <ArrowLeft className="ml-2 h-4 w-4 rotate-180" />
                            </a>
                        </Button>
                    </div>

                </div>
            </main>
        </div>
    );
};

export default FeatureDetail;
