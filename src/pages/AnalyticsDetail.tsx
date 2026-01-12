import { Link, useParams } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ArrowLeft, Code, Shield, Network, Zap, Clock, FileCheck } from "lucide-react";

const AnalyticsDetail = () => {
    const { analysisId } = useParams();

    const getContent = () => {
        switch (analysisId) {
            case 'remediation':
                return {
                    title: "Remediation Effort Analysis",
                    subtitle: "Technical Debt & Resourcing Estimation",
                    icon: Code,
                    iconColor: "text-primary",
                    description: "Our AI-driven engine calculates the estimated time to remediate vulnerabilities based on code complexity, file modification history, and industry standard fix times. This metric helps in sprint planning and allocating security resources effectively.",
                    metrics: [
                        { label: "Avg. Fix Time", value: "45m", icon: Clock },
                        { label: "Auto-Fixable", value: "68%", icon: Zap },
                        { label: "Critical Path", value: "12 Issues", icon: FileCheck }
                    ],
                    sections: [
                        {
                            title: "Technical Methodology",
                            content: "We traverse the Abstract Syntax Tree (AST) of the vulnerable code paths to calculate the Cyclomatic Complexity Number (CCN). We combine this with the 'churn rate' of the file from git history. High churn + high complexity = higher remediation time estimate."
                        },
                        {
                            title: "Industry Benchmark",
                            content: "Your average remediation time of 45 mins is 15% better than the Series B SaaS average (53 mins). This indicates a healthy, modular codebase that is easy to maintain."
                        },
                        {
                            title: "Actionable Next Steps",
                            content: "To reduce technical debt, we recommend applying automated fixes for the 'low-hanging fruit' vulnerabilities first. Run the following command to auto-patch known CVEs where possible:",
                            code: "npx sentinel-fix --auto --level=safe --dry-run"
                        }
                    ]
                };
            case 'compliance':
                return {
                    title: "Compliance Readiness Assessment",
                    subtitle: "Audit Gap Analysis & Control Mapping",
                    icon: Shield,
                    iconColor: "text-cyber-green",
                    description: "Real-time mapping of technical findings to regulatory controls (SOC2, ISO 27001, PCI-DSS, HIPAA), providing an instant 'Audit Readiness' score. This ensures you are always prepared for an external audit.",
                    metrics: [
                        { label: "SOC2 Controls", value: "18/22", icon: FileCheck },
                        { label: "Audit Risk", value: "Low", icon: Shield },
                        { label: "Evidence Collected", value: "142", icon: FileText } // Changed icon to FileText in imports
                    ],
                    sections: [
                        {
                            title: "Mapping Logic",
                            content: "We utilize a proprietary 'Control Map' database that links specific CVEs and CWEs to compliance clauses. For example, a missing 'HttpOnly' flag on a cookie is automatically mapped to SOC2 CC6.1 (Logical Access) and PCI-DSS 6.5.10."
                        },
                        {
                            title: "Audit Readiness Benchmark",
                            content: "Your current readiness score of 82% places you in the top quartile for pre-audit startups. Most organizations struggle to reach 60% readiness without manual intervention."
                        },
                        {
                            title: "Evidence Generation",
                            content: "You can generate a pre-filled compliance artifact package for your auditor. This includes raw logs, config snapshots, and the remediation history.",
                            code: "npx sentinel-compliance generate --standard=soc2 --output=./audit-evidence"
                        }
                    ]
                };
            case 'attack-surface':
                return {
                    title: "Attack Surface Visualization",
                    subtitle: "Vector Analysis & Entry Point Discovery",
                    icon: Network,
                    iconColor: "text-destructive",
                    description: "A comprehensive breakdown of your application's exposed surface area, categorizing vulnerabilities by their exploitation vector. This identifies the 'path of least resistance' for attackers.",
                    metrics: [
                        { label: "Public Endpoints", value: "42", icon: Globe }, // Changed icon to Globe
                        { label: "Open Ports", value: "3", icon: Network },
                        { label: "Risk Density", value: "High", icon: AlertTriangle } // Changed icon to AlertTriangle
                    ],
                    sections: [
                        {
                            title: "Attack Scenario",
                            content: "A typical kill-chain observed on this surface: An attacker discovers an exposed `.git` directory (Configuration vector), extracts AWS keys, and pivots to the backend (Application vector). We simulate this path during the scan."
                        },
                        {
                            title: "Vector Decomposition",
                            content: "We use passive OSINT techniques combined with active port scanning to map the perimeter. 'Application' findings are strictly layer 7 (HTTP), while 'Network' includes transport layer issues like weak TLS ciphers."
                        },
                        {
                            title: "Hardening Strategy",
                            content: "To reduce the surface area, we recommend closing unused ports and placing internal admin panels behind a VPN or Zero Trust proxy. You can verify your firewall rules with:",
                            code: "npx sentinel-scan --target=network --ports=all --verify-firewall"
                        }
                    ]
                };
            case 'severity-distribution':
                return {
                    title: "Severity Distribution Analysis",
                    subtitle: "Criticality Assessment & Risk Profiling",
                    icon: AlertTriangle,
                    iconColor: "text-destructive",
                    description: "A statistical breakdown of vulnerabilities categorized by their potential impact on confidentiality, integrity, and availability. This distribution highlights the immediate threat level of the application.",
                    metrics: [
                        { label: "Critical Issues", value: "2", icon: AlertTriangle },
                        { label: "Risk Density", value: "High", icon: Activity },
                        { label: "Triage Time", value: "4h", icon: Clock }
                    ],
                    sections: [
                        {
                            title: "CVSS v3.1 Scoring Algorithm",
                            content: "We strictly adhere to the Common Vulnerability Scoring System (CVSS) v3.1. A 'Critical' rating requires a score of 9.0+, usually implying remote code execution (RCE) or complete auth bypass with no user interaction required."
                        },
                        {
                            title: "Peer Comparison",
                            content: "Your application has a higher-than-average ratio of 'High' severity issues compared to the FinTech industry median. This suggests a need for stricter input validation libraries."
                        },
                        {
                            title: "Immediate Triage",
                            content: "We have generated a prioritized burn-down list. Please assign the Critical issues to senior engineers immediately. You can export the ticket data to Jira/Linear via:",
                            code: "npx sentinel-export --format=jira --severity=critical"
                        }
                    ]
                };
            case 'owasp-radar':
                return {
                    title: "OWASP Top 10 Coverage",
                    subtitle: "Category-Based Defense Assessment",
                    icon: Target,
                    iconColor: "text-accent", // Assuming 'accent' maps to a valid color class, or use 'text-purple-500' etc.
                    description: "This radar chart visualizes the application's resilience against the OWASP Top 10 security risks. It highlights which categories (e.g., Injection, Broken Auth) are well-defended and which are weak.",
                    metrics: [
                        { label: "Coverage Score", value: "82%", icon: Shield },
                        { label: "Weakest Link", value: "A03", icon: AlertTriangle },
                        { label: "Avg. Immunity", value: "High", icon: Activity }
                    ],
                    sections: [
                        {
                            title: "Mapping Methodology",
                            content: "Every finding is tagged with a CWE ID, which we map to the OWASP 2021 categories. A category score is derived from: (Passed Checks / Total Checks) * Impact Weight. A03 (Injection) is your weakest area."
                        },
                        {
                            title: "Training Implication",
                            content: "The low score in 'Security Misconfiguration' (A05) suggests that your DevOps team might benefit from specific hardening training or using Infrastructure-as-Code (IaC) templates."
                        },
                        {
                            title: "Unit Testing Strategy",
                            content: "To improve the 'Injection' axis, implement unit tests that specifically attempt SQLi payloads. You can interactively test the injection vector using our REPL tool:",
                            code: "npx sentinel-repl --module=sqli --target=http://localhost:3000/api/users"
                        }
                    ]
                };
            case 'top-vulnerabilities':
                return {
                    title: "Top Weighted Vulnerabilities",
                    subtitle: "Impact-Based Prioritization",
                    icon: BarChart3,
                    iconColor: "text-cyber-amber", // Assuming valid class
                    description: "An ordered list of the most dangerous vulnerabilities, ranked by a composite score of Severity x Confidence x Business Impact. This list represents your 'Critical Path' to a secure state.",
                    metrics: [
                        { label: "Highest Impact", value: "SQLi", icon: AlertTriangle },
                        { label: "Total Weighted", value: "850", icon: Activity },
                        { label: "Fix Priority", value: "P0", icon: Clock }
                    ],
                    sections: [
                        {
                            title: "Attack Simulation",
                            content: "For the top item (SQL Injection), our engine successfully extracted the database version banner 'PostgreSQL 14.5'. This confirms the flaw is trivially exploitable by automated tools like SQLMap."
                        },
                        {
                            title: "Business Impact",
                            content: "Exploitation of these top 3 vulnerabilities could lead to a full data breach (P0). In a regulated environment, this would trigger a mandatory gdpr breach notification within 72 hours."
                        },
                        {
                            title: "Investigation & Fix",
                            content: "You can replay the exact HTTP request that triggered the exploit to verify the fix locally. Use the curl command below:",
                            code: "curl -X POST http://localhost:3000/login -d \"user=admin' OR 1=1--\""
                        }
                    ]
                };
            case 'security-score':
                return {
                    title: "Security Score & Confidence",
                    subtitle: "Holistic Posture Evaluation",
                    icon: Shield,
                    iconColor: "text-primary",
                    description: "A composite letter grade (A-F) representing the overall health of the application. It is dynamically calculated based on scan coverage, finding density, and the rate of false positives.",
                    metrics: [
                        { label: "Overall Score", value: "B+", icon: Shield },
                        { label: "Confidence", value: "95%", icon: Target },
                        { label: "Scan Depth", value: "Deep", icon: Activity }
                    ],
                    sections: [
                        {
                            title: "Score Breakdown",
                            content: "Base Score (100) - Critical Deductions (15) - High Deductions (10) + Mitigation Credits (5). Your 'B+' indicates a solid foundation but with 1-2 critical outliers that prevent an 'A' grade."
                        },
                        {
                            title: "Confidence Factors",
                            content: "Our confidence is high (95%) because we successfully verified 14 vulnerabilities with active payloads (Time-Based SQLi, Reflection). Only 5% of findings are purely heuristic/static analysis."
                        },
                        {
                            title: "Roadmap to 'A' Grade",
                            content: "To reach an 'A' score, you must remediate the SQL Injection and the Broken Access Control issue in /admin. Once fixed, re-run the full active scan:",
                            code: "npx sentinel-scan --full --report=json"
                        }
                    ]
                };
            default:
                return null;
        }
    };

    const content = getContent();

    if (!content) {
        return (
            <div className="min-h-screen bg-background flex items-center justify-center">
                <div className="text-center">
                    <h1 className="text-2xl font-bold mb-4">Analysis Not Found</h1>
                    <Link to="/demo">
                        <Button>Return to Demo</Button>
                    </Link>
                </div>
            </div>
        );
    }

    const Icon = content.icon;

    return (
        <div className="min-h-screen bg-background text-foreground flex flex-col font-sans selection:bg-primary/20">
            {/* Navbar removed */}

            <main className="flex-grow container mx-auto px-6 py-24 max-w-5xl">
                <div className="mb-10">
                    <Link to="/demo">
                        <Button variant="ghost" className="pl-0 hover:pl-2 transition-all group text-muted-foreground hover:text-primary">
                            <ArrowLeft className="w-4 h-4 mr-2 group-hover:-translate-x-1 transition-transform" />
                            Back to Scan Results
                        </Button>
                    </Link>
                </div>

                <div className="grid grid-cols-1 lg:grid-cols-3 gap-12">
                    {/* Main Content */}
                    <div className="lg:col-span-2 space-y-8">
                        <div className="space-y-4">
                            <div className={`inline-flex p-3 rounded-xl bg-muted/30 border border-border/50 ${content.iconColor}`}>
                                <Icon className="w-8 h-8" />
                            </div>
                            <h1 className="text-4xl font-bold tracking-tight">{content.title}</h1>
                            <p className="text-xl text-muted-foreground">{content.subtitle}</p>
                        </div>

                        <Card className="bg-card/50 border-border/50 backdrop-blur-sm">
                            <CardContent className="p-6">
                                <p className="text-lg leading-relaxed text-foreground/90">
                                    {content.description}
                                </p>
                            </CardContent>
                        </Card>

                        <div className="space-y-8">
                            {content.sections.map((section, idx) => (
                                <div key={idx} className="prose dark:prose-invert max-w-none">
                                    <h3 className="text-2xl font-semibold mb-3 flex items-center gap-3">
                                        <div className="w-1.5 h-6 bg-primary rounded-full" />
                                        {section.title}
                                    </h3>
                                    <p className="text-muted-foreground leading-relaxed text-lg">
                                        {section.content}
                                    </p>
                                    {section.code && (
                                        <div className="mt-4 p-4 bg-black/40 rounded-lg border border-border/50 font-mono text-sm text-green-400 overflow-x-auto">
                                            <div className="flex items-center gap-2 mb-2 text-xs text-muted-foreground border-b border-border/30 pb-2">
                                                <span className="text-primary">❯</span> SHELL COMMAND
                                            </div>
                                            {section.code}
                                        </div>
                                    )}
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Sidebar Metrics */}
                    <div className="space-y-6">
                        <Card className="sticky top-32 bg-muted/20 border-border/50">
                            <CardHeader>
                                <CardTitle className="text-lg">Key Metrics</CardTitle>
                                <CardDescription>Real-time analysis data</CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-6">
                                {content.metrics.map((metric, idx) => {
                                    const MetricIcon = metric.icon;
                                    return (
                                        <div key={idx} className="flex items-center justify-between p-3 rounded-lg bg-background/50 border border-border/50">
                                            <div className="flex items-center gap-3">
                                                <div className="p-2 rounded-md bg-primary/10 text-primary">
                                                    <MetricIcon className="w-4 h-4" />
                                                </div>
                                                <span className="text-sm font-medium text-muted-foreground">{metric.label}</span>
                                            </div>
                                            <span className="font-bold text-lg">{metric.value}</span>
                                        </div>
                                    );
                                })}

                                <div className="pt-4 border-t border-border/50">
                                    <Button className="w-full bg-primary/10 text-primary hover:bg-primary/20 border-primary/20">
                                        Download Brief
                                    </Button>
                                </div>
                            </CardContent>
                        </Card>
                    </div>
                </div>
            </main>

            {/* Footer removed */}
        </div>
    );
};

// Types needed for imports, placed here to avoid import errors since we are writing file content directly
// Types needed for imports, placed here to avoid import errors since we are writing file content directly
import { Globe, AlertTriangle, FileText, BarChart3, Target, Activity } from "lucide-react";

export default AnalyticsDetail;
