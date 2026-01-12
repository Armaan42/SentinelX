import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
    Shield,
    Scan,
    Zap,
    Lock,
    CheckCircle,
    Github,
    Download,
    Eye,
    Network,
    Code2,
    Cpu,
    Layers,
    ShieldCheck,
    ChevronRight,
    Monitor,
    Globe
} from "lucide-react";

import heroImage from "@/assets/hero-security.jpg";
import SecurityFragmentation from "@/components/SecurityFragmentation";

import ComparisonSection from "@/components/ComparisonSection";

const Index = () => {
    const [isVisible, setIsVisible] = useState(false);

    useEffect(() => {
        setIsVisible(true);
    }, []);

    const features = [
        {
            id: "advanced-active-scanning",
            icon: Scan,
            title: "Advanced Active Scanning",
            description: "Enterprise-grade engine for complex injection vectors.",
            details: [
                "Time-Based Blind SQLi",
                "Dom-Based XSS Analysis",
                "OS Command Injection",
                "NoSQL Injection"
            ],
            color: "text-blue-500",
            bg: "bg-blue-500/10"
        },
        {
            id: "cloud-native-security",
            icon: Network,
            title: "Cloud-Native Security",
            description: "Full visibility into cloud infrastructure and APIs.",
            details: [
                "SSRF (Cloud Metadata)",
                "GraphQL Introspection",
                "Docker API Exposures",
                "REST Method Tampering"
            ],
            color: "text-purple-500",
            bg: "bg-purple-500/10"
        },
        {
            id: "modern-auth-testing",
            icon: Lock,
            title: "Modern Auth Testing",
            description: "Rigorous analysis of authentication flows.",
            details: [
                "JWT Weaknesses (alg: none)",
                "OAuth Open Redirects",
                "IDOR Detection",
                "Session Fixation"
            ],
            color: "text-amber-500",
            bg: "bg-amber-500/10"
        },
        {
            id: "unified-reporting",
            icon: Zap,
            title: "Unified Reporting",
            description: "Actionable intelligence with compliance mapping.",
            details: [
                "Severity Scoring (CVSS)",
                "Remediation Guides",
                "OWASP Top 10 Mapping",
                "Export to PDF/JSON"
            ],
            color: "text-green-500",
            bg: "bg-green-500/10"
        }
    ];

    const techStack = [
        {
            name: "TypeScript",
            role: "Zero-Runtime Errors",
            description: "Ensures the scanning engine never crashes mid-audit due to malformed payloads or type mismatches.",
            icon: Code2,
            color: "text-blue-500",
            bg: "bg-blue-500/10"
        },
        {
            name: "Supabase Edge",
            role: "Global Low-Latency",
            description: "Runs vulnerability checks from the location nearest to the target server, reducing network overhead by 60%.",
            icon: Zap,
            color: "text-green-500",
            bg: "bg-green-500/10"
        },
        {
            name: "React + Vite",
            role: "High-Frequency Updates",
            description: "Handles 100+ live log events per second without UI freezing, essential for real-time attack feedback.",
            icon: Cpu,
            color: "text-cyan-500",
            bg: "bg-cyan-500/10"
        },
        {
            name: "Tailwind CSS",
            role: "Atomic Consistency",
            description: "Provides a lightweight, strictly consistent design system that loads instantly on any device.",
            icon: Layers,
            color: "text-purple-500",
            bg: "bg-purple-500/10"
        }
    ];

    const stats = [
        { value: "100%", label: "TypeScript" },
        { value: "Global", label: "Edge Network" },
        { value: "OWASP", label: "Top 10 Coverage" },
        { value: "Open", label: "Source Ready" }
    ];

    return (
        <div className="min-h-screen bg-background text-foreground antialiased selection:bg-primary/20">
            {/* Navigation */}
            <nav className="fixed top-0 w-full bg-background/80 backdrop-blur-xl border-b border-border/40 z-50 transition-all duration-300">
                <div className="container mx-auto px-6 h-20 flex items-center justify-between">
                    <div className="flex items-center space-x-3 group cursor-pointer">
                        <div className="p-2 bg-primary/10 rounded-xl group-hover:bg-primary/20 transition-colors">
                            <Shield className="h-6 w-6 text-primary" />
                        </div>
                        <span className="text-xl font-bold tracking-tight">SentinelX</span>
                    </div>

                    <div className="hidden md:flex items-center space-x-10">
                        <a href="#features" className="text-sm font-medium text-muted-foreground hover:text-primary transition-colors">Features</a>
                        <a href="#technology" className="text-sm font-medium text-muted-foreground hover:text-primary transition-colors">Technology</a>
                        <div className="flex items-center space-x-4 ml-4">
                            <Button variant="ghost" size="sm" asChild className="font-medium hover:bg-muted">
                                <a href="https://github.com/Armaan42/SentinelX" target="_blank" rel="noopener noreferrer">
                                    <Github className="h-4 w-4 mr-2" />
                                    GitHub
                                </a>
                            </Button>
                            <Button size="sm" className="font-medium px-6 shadow-lg shadow-primary/20 hover:shadow-primary/30 transition-all" asChild>
                                <a href="#download">Get Started</a>
                            </Button>
                        </div>
                    </div>
                </div>
            </nav>

            {/* Hero Section */}
            <section className="relative min-h-screen flex items-center pt-32 pb-20 overflow-hidden">
                {/* Modern Gradient Background */}
                <div className="absolute inset-0 bg-grid-white/[0.02] bg-[size:50px_50px] pointer-events-none" />
                <div className="absolute inset-0 flex items-center justify-center bg-background [mask-image:radial-gradient(ellipse_at_center,transparent_20%,black)] pointer-events-none" />
                <div className="absolute top-0 right-0 w-[600px] h-[600px] bg-primary/20 rounded-full blur-[120px] opacity-20 animate-pulse pointer-events-none" />
                <div className="absolute bottom-0 left-0 w-[600px] h-[600px] bg-purple-500/10 rounded-full blur-[120px] opacity-20 pointer-events-none" />

                <div className="container mx-auto px-6 relative z-10">
                    <div className="grid lg:grid-cols-2 gap-16 items-center">
                        {/* Left Column: Content */}
                        <div className={`text-left transition-all duration-1000 transform ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
                            <div className="inline-flex items-center rounded-full border border-primary/20 bg-primary/5 px-4 py-1.5 text-sm font-medium text-primary mb-8 backdrop-blur-md hover:bg-primary/10 transition-colors cursor-default">
                                <span className="relative flex h-2 w-2 mr-2">
                                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary opacity-75"></span>
                                    <span className="relative inline-flex rounded-full h-2 w-2 bg-primary"></span>
                                </span>
                                SentinelX Framework v1.0
                            </div>

                            <h1 className="text-5xl md:text-7xl font-bold tracking-tight mb-8 leading-[1.1]">
                                Secure the <br />
                                <span className="bg-gradient-to-r from-foreground via-foreground to-muted-foreground bg-clip-text text-transparent">
                                    Modern Edge
                                </span>
                            </h1>

                            <p className="text-xl text-muted-foreground mb-10 max-w-xl leading-relaxed">
                                The first <span className="text-foreground font-semibold">Serverless DAST</span> framework designed for the cloud era.
                                Detect critical vulnerabilities with zero infrastructure overhead.
                            </p>

                            <div className="flex flex-col sm:flex-row gap-5 items-start mb-16">
                                <Button size="lg" className="h-14 px-8 text-lg rounded-full shadow-xl shadow-primary/20 hover:shadow-primary/40 transition-all hover:-translate-y-1" asChild>
                                    <a href="https://github.com/Armaan42/SentinelX" target="_blank" rel="noopener noreferrer">
                                        <Download className="h-5 w-5 mr-2" />
                                        Install Scanner
                                    </a>
                                </Button>
                                <Button variant="outline" size="lg" className="h-14 px-8 text-lg rounded-full border-muted-foreground/20 hover:bg-secondary/50 transition-all hover:-translate-y-1" asChild>
                                    <Link to="/demo">
                                        <Eye className="h-5 w-5 mr-2" />
                                        Live Demo
                                    </Link>
                                </Button>
                            </div>

                            <div className="flex items-center gap-8 text-sm font-medium text-muted-foreground">
                                {stats.map((stat, i) => (
                                    <div key={i} className="flex flex-col">
                                        <span className="text-2xl font-bold text-foreground">{stat.value}</span>
                                        <span className="text-xs uppercase tracking-wide opacity-70">{stat.label}</span>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Right Column: Terminal Visual */}
                        <div className={`relative hidden lg:block transition-all duration-1000 delay-300 transform ${isVisible ? 'opacity-100 translate-x-0' : 'opacity-0 translate-x-10'}`}>
                            <div className="relative rounded-xl bg-[#0d1117] border border-border/40 shadow-2xl overflow-hidden font-mono text-sm leading-relaxed">
                                {/* Terminal Header */}
                                <div className="flex items-center justify-between px-4 py-3 bg-white/5 border-b border-white/5">
                                    <div className="flex space-x-2">
                                        <div className="w-3 h-3 rounded-full bg-red-500/50" />
                                        <div className="w-3 h-3 rounded-full bg-yellow-500/50" />
                                        <div className="w-3 h-3 rounded-full bg-green-500/50" />
                                    </div>
                                    <div className="text-xs text-muted-foreground">sentinelx-cli — v1.0.0</div>
                                </div>

                                {/* Terminal Body */}
                                <div className="p-6 space-y-2 h-[400px] overflow-hidden relative">
                                    <div className="absolute inset-0 bg-gradient-to-b from-transparent via-transparent to-[#0d1117] pointer-events-none z-10" />

                                    <div className="flex text-emerald-400">
                                        <span className="mr-2">$</span>
                                        <span className="typing-effect">sentinelx scan --target production.api</span>
                                    </div>
                                    <div className="text-slate-400 pb-2">[+] Initializing SentinelX Engine...</div>
                                    <div className="text-slate-400">[+] Target confirmed: https://api.production.com</div>

                                    <div className="grid grid-cols-2 gap-4 py-4">
                                        <div className="bg-white/5 p-3 rounded border border-white/5">
                                            <div className="text-xs text-slate-500 mb-1">Injection Vectors</div>
                                            <div className="text-emerald-400 font-bold">Checking...</div>
                                        </div>
                                        <div className="bg-white/5 p-3 rounded border border-white/5">
                                            <div className="text-xs text-slate-500 mb-1">Auth Bypass</div>
                                            <div className="text-amber-400 font-bold">Scanning...</div>
                                        </div>
                                    </div>

                                    <div className="text-slate-300">
                                        <span className="text-red-400">[!] CRITICAL:</span> SQL Injection detected
                                        <div className="ml-4 text-xs text-slate-500 mt-1">/v1/users?id=1' OR '1'='1</div>
                                    </div>

                                    <div className="text-slate-300 mt-2">
                                        <span className="text-amber-400">[!] HIGH:</span> JWT 'none' algorithm allowed
                                        <div className="ml-4 text-xs text-slate-500 mt-1">Authorization: Bearer eyJhbGciOiJub25l...</div>
                                    </div>

                                    <div className="mt-4 pt-4 border-t border-white/10 flex justify-between items-center text-xs">
                                        <span className="text-slate-500">Scan Progress: 42%</span>
                                        <span className="text-emerald-500 animate-pulse">● Live</span>
                                    </div>
                                </div>
                            </div>

                            {/* Decorative Elements around Terminal */}
                            <div className="absolute -z-10 top-10 -right-10 w-72 h-72 bg-primary/20 rounded-full blur-[80px]" />
                            <div className="absolute -z-10 -bottom-10 -left-10 w-72 h-72 bg-blue-500/20 rounded-full blur-[80px]" />
                        </div>
                    </div>
                </div>
            </section>

            {/* Security Fragmentation Component */}
            <SecurityFragmentation />

            {/* Features Section */}
            <section id="features" className="py-32 bg-secondary/5 relative overflow-hidden">
                {/* Decorative background blobs */}
                <div className="absolute top-0 right-0 w-[600px] h-[600px] bg-primary/5 rounded-full blur-[100px] opacity-30 pointer-events-none" />
                <div className="absolute bottom-0 left-0 w-[600px] h-[600px] bg-secondary/10 rounded-full blur-[100px] opacity-30 pointer-events-none" />

                <div className="container mx-auto px-6 relative">
                    <div className="text-center mb-24 max-w-3xl mx-auto">
                        <h2 className="text-3xl md:text-5xl font-bold mb-6 tracking-tight">
                            Enterprise-Grade <span className="text-primary">Intelligence</span>
                        </h2>
                        <p className="text-lg text-muted-foreground leading-relaxed">
                            Built to meet the rigorous demands of modern security teams. SentinelX combines depth of inspection with speed of execution.
                        </p>
                    </div>

                    <div className="grid md:grid-cols-2 gap-8 max-w-6xl mx-auto">
                        {features.map((feature, index) => (
                            <Link to={`/feature/${feature.id}`} key={index} className="block group">
                                <Card className="bg-card/40 backdrop-blur-xl border-border/50 hover:border-primary/40 transition-all duration-300 hover:shadow-2xl hover:shadow-primary/5 h-full overflow-hidden cursor-pointer relative">
                                    <div className="absolute top-4 right-4 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                                        <div className="p-2 bg-primary/10 rounded-full">
                                            <ChevronRight className="h-4 w-4 text-primary" />
                                        </div>
                                    </div>
                                    <CardHeader className="p-8">
                                        <div className={`h-14 w-14 rounded-2xl ${feature.bg} flex items-center justify-center mb-6 group-hover:scale-110 transition-transform duration-500`}>
                                            <feature.icon className={`h-7 w-7 ${feature.color}`} />
                                        </div>
                                        <CardTitle className="text-2xl mb-4 group-hover:text-primary transition-colors">{feature.title}</CardTitle>

                                        <ul className="space-y-3 mb-6">
                                            {feature.details.map((detail, idx) => (
                                                <li key={idx} className="flex items-start text-sm text-foreground/80">
                                                    <div className={`mt-1.5 h-1.5 w-1.5 rounded-full mr-3 shrink-0 ${feature.bg.replace('/10', '')}`} />
                                                    {detail}
                                                </li>
                                            ))}
                                        </ul>

                                        <CardDescription className="text-sm leading-relaxed text-muted-foreground border-t border-border/40 pt-6">
                                            {feature.description}
                                        </CardDescription>
                                    </CardHeader>
                                    <div className={`h-1 w-full bg-gradient-to-r from-transparent via-${feature.color.split('-')[1]}-500/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500`} />
                                </Card>
                            </Link>
                        ))}
                    </div>
                </div>
            </section>

            {/* Comparison Section */}
            <ComparisonSection />

            {/* Tech Stack */}
            <section id="technology" className="py-32">
                <div className="container mx-auto px-6">
                    <div className="max-w-6xl mx-auto">
                        <div className="grid md:grid-cols-2 gap-20 items-center">
                            <div>
                                <Badge variant="outline" className="mb-6 py-1.5 px-4 text-sm border-primary/20 text-primary bg-primary/5">
                                    Architecture
                                </Badge>
                                <h2 className="text-4xl md:text-5xl font-bold mb-8 leading-tight tracking-tight">
                                    Built on the <br />
                                    <span className="text-primary">Modern Web Stack</span>
                                </h2>
                                <p className="text-lg text-muted-foreground mb-10 leading-relaxed">
                                    Leveraging Deno for secure edge execution and React for high-performance visualization.
                                    SentinelX is designed for speed, security, and developer experience.
                                </p>

                                <div className="p-8 bg-card border border-border/60 rounded-3xl flex items-start gap-5 shadow-sm hover:shadow-md transition-shadow">
                                    <div className="p-4 bg-primary/10 rounded-2xl">
                                        <ShieldCheck className="h-8 w-8 text-primary" />
                                    </div>
                                    <div>
                                        <h3 className="text-xl font-bold mb-2">SLSA Level 3 Certified</h3>
                                        <p className="text-muted-foreground leading-relaxed">
                                            Full supply chain security with verifiable build provenance and integrity checks.
                                        </p>
                                    </div>
                                </div>
                            </div>

                            <div className="grid grid-cols-1 gap-4">
                                {techStack.map((tech, index) => {
                                    const Icon = tech.icon;
                                    return (
                                        <div key={index} className="flex items-start gap-5 p-5 rounded-2xl border border-border/50 bg-card/30 hover:bg-card hover:border-primary/20 transition-all duration-300 group hover:-translate-x-1 shadow-sm hover:shadow-xl">
                                            <div className={`shrink-0 h-12 w-12 rounded-xl ${tech.bg} flex items-center justify-center group-hover:scale-110 transition-transform duration-300`}>
                                                <Icon className={`h-6 w-6 ${tech.color}`} />
                                            </div>
                                            <div>
                                                <div className="flex items-center gap-3 mb-1">
                                                    <h4 className="font-bold text-base">{tech.name}</h4>
                                                    <span className={`text-[10px] uppercase tracking-wider font-semibold py-0.5 px-2 rounded-full bg-background border border-border/50 opacity-70`}>
                                                        {tech.role}
                                                    </span>
                                                </div>
                                                <p className="text-sm text-muted-foreground leading-relaxed">{tech.description}</p>
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* CTA / Download */}
            <section id="download" className="py-32 relative overflow-hidden">
                <div className="absolute inset-0 bg-primary/5 skew-y-3 transform origin-bottom-left" />

                <div className="container mx-auto px-6 relative z-10 text-center">
                    <h2 className="text-4xl md:text-5xl font-bold mb-10 tracking-tight">
                        Ready to Unify Your Security Operations?
                    </h2>

                    <div className="max-w-2xl mx-auto bg-background/80 backdrop-blur-xl rounded-2xl border border-border shadow-2xl overflow-hidden mb-12 transform hover:scale-[1.01] transition-transform">
                        <div className="flex items-center justify-between px-4 py-3 bg-muted/50 border-b border-border">
                            <div className="flex space-x-2">
                                <div className="w-3 h-3 rounded-full bg-red-500/20 border border-red-500/50" />
                                <div className="w-3 h-3 rounded-full bg-yellow-500/20 border border-yellow-500/50" />
                                <div className="w-3 h-3 rounded-full bg-green-500/20 border border-green-500/50" />
                            </div>
                            <span className="text-xs text-muted-foreground font-mono">bash</span>
                        </div>
                        <div className="p-8 font-mono text-sm text-left">
                            <div className="flex items-center text-primary mb-2">
                                <span className="mr-2">$</span>
                                <span className="typing-cursor">npx sentinelx-cli scan --target example.com</span>
                            </div>
                            <div className="text-muted-foreground/50">
                                &gt; Initializing SentinelX Engine...<br />
                                &gt; Target: example.com<br />
                                &gt; Active Scanners: SQLi, XSS, SSRF, JWT...
                            </div>
                        </div>
                    </div>

                    <div className="flex justify-center flex-col sm:flex-row gap-4">
                        <Button variant="default" size="lg" className="h-12 px-8 rounded-full" asChild>
                            <a href="https://github.com/Armaan42/SentinelX" target="_blank" rel="noopener noreferrer">
                                <Github className="h-5 w-5 mr-2" />
                                Start on GitHub
                            </a>
                        </Button>
                        <Button variant="ghost" size="lg" className="h-12 px-8 rounded-full hover:bg-muted" asChild>
                            <a href="#">Read Documentation</a>
                        </Button>
                    </div>
                </div>
            </section>

            {/* Footer */}
            <footer className="bg-background border-t border-border py-20 px-6">
                <div className="container mx-auto max-w-7xl">
                    <div className="grid md:grid-cols-6 gap-12 lg:gap-20 mb-20">
                        <div className="md:col-span-2">
                            <Link to="/" className="flex items-center space-x-2 mb-6">
                                <div className="p-2 bg-primary/10 rounded-xl">
                                    <Shield className="h-6 w-6 text-primary" />
                                </div>
                                <span className="text-xl font-bold tracking-tight">SentinelX</span>
                            </Link>
                            <p className="text-muted-foreground text-sm leading-relaxed max-w-sm mb-8">
                                Redefining application security with edge-first, autonomous vulnerability detection.
                                Securing the future, scan by scan.
                            </p>
                            <div className="flex gap-4">
                                <a href="#" className="p-2 rounded-full bg-muted/50 hover:bg-muted hover:text-primary transition-colors">
                                    <Github className="h-5 w-5" />
                                </a>
                                <a href="#" className="p-2 rounded-full bg-muted/50 hover:bg-muted hover:text-primary transition-colors">
                                    <Globe className="h-5 w-5" />
                                </a>
                            </div>
                        </div>

                        <div className="md:col-span-1">
                            <h4 className="font-bold mb-6 text-foreground">Product</h4>
                            <ul className="space-y-4 text-sm text-muted-foreground">
                                <li><a href="#features" className="hover:text-primary transition-colors">Scanner Engine</a></li>
                                <li><a href="#technology" className="hover:text-primary transition-colors">Compliance</a></li>
                                <li><a href="#" className="hover:text-primary transition-colors">Integrations</a></li>
                                <li><a href="#download" className="hover:text-primary transition-colors">CLI Tool</a></li>
                            </ul>
                        </div>

                        <div className="md:col-span-1">
                            <h4 className="font-bold mb-6 text-foreground">Resources</h4>
                            <ul className="space-y-4 text-sm text-muted-foreground">
                                <li><a href="#" className="hover:text-primary transition-colors">Documentation</a></li>
                                <li><a href="#" className="hover:text-primary transition-colors">API Reference</a></li>
                                <li><a href="#" className="hover:text-primary transition-colors">Security Guides</a></li>
                                <li><a href="#" className="hover:text-primary transition-colors">Community</a></li>
                            </ul>
                        </div>

                        <div className="md:col-span-2">
                            <h4 className="font-bold mb-6 text-foreground">Stay Secure</h4>
                            <p className="text-sm text-muted-foreground mb-6 leading-relaxed">
                                Subscribe to our newsletter for the latest zero-day alerts and updates.
                            </p>
                            <div className="flex gap-2">
                                <input
                                    type="email"
                                    placeholder="Enter your email"
                                    className="flex-1 bg-muted/30 border border-border/50 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-primary focus:ring-1 focus:ring-primary/20 transition-all"
                                />
                                <Button size="sm" className="rounded-xl px-6">Subscribe</Button>
                            </div>
                        </div>
                    </div>

                    <div className="pt-10 border-t border-border/50 flex flex-col md:flex-row justify-between items-center gap-6 text-sm text-muted-foreground">
                        <p>© 2026 SentinelX Inc. All rights reserved.</p>
                        <div className="flex gap-8">
                            <a href="#" className="hover:text-foreground transition-colors">Privacy Policy</a>
                            <a href="#" className="hover:text-foreground transition-colors">Terms of Service</a>
                            <a href="#" className="hover:text-foreground transition-colors">Cookie Policy</a>
                        </div>
                    </div>
                </div>
            </footer>
        </div>
    );
};

export default Index;
