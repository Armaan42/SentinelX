import { Link } from "react-router-dom";
import { X, Check, ArrowRight } from "lucide-react";

const ComparisonSection = () => {
    return (
        <section className="py-24 bg-background/50 relative overflow-hidden" id="comparison">
            {/* Abstract Background */}
            <div className="absolute top-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-primary/30 to-transparent" />
            <div className="absolute bottom-0 inset-x-0 h-px bg-gradient-to-r from-transparent via-primary/30 to-transparent" />

            <div className="container mx-auto px-6 relative z-10">
                <div className="text-center mb-16">
                    <h2 className="text-3xl md:text-5xl font-bold mb-6 tracking-tight">
                        Outsmart the <span className="text-primary">Competition</span>
                    </h2>
                    <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                        Why security teams are switching from legacy scanners to the SentinelX active engine.
                    </p>
                </div>

                <Link to="/comparison">
                    <div className="relative max-w-5xl mx-auto rounded-3xl border border-border/50 bg-card/20 backdrop-blur-sm overflow-hidden shadow-2xl cursor-pointer hover:shadow-primary/20 transition-all duration-500 group">
                        {/* Hover Hint */}
                        <div className="absolute inset-0 z-50 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity bg-black/40 backdrop-blur-[2px]">
                            <div className="bg-primary text-primary-foreground px-6 py-3 rounded-full font-bold shadow-2xl transform scale-90 group-hover:scale-100 transition-transform flex items-center gap-2">
                                <span>Click to View Detailed Benchmark</span>
                                <ArrowRight className="h-4 w-4" />
                            </div>
                        </div>

                        <div className="grid grid-cols-1 md:grid-cols-3">
                            {/* Legacy Column */}
                            <div className="p-8 md:p-10 border-b md:border-b-0 md:border-r border-border/50 bg-destructive/5 relative">
                                <div className="absolute top-0 left-0 w-full h-1 bg-destructive/20" />
                                <h3 className="text-xl font-bold text-muted-foreground mb-2">Legacy Scanners</h3>
                                <p className="text-sm text-muted-foreground mb-8">Nessus, Qualys, InsightVM</p>

                                <div className="space-y-6">
                                    {[
                                        "Passive Detection Only",
                                        "High False Positives",
                                        "Slow, Bloated Reports",
                                        "Expensive Per-Seat Licensing",
                                        "Requires Manual Configuration",
                                        "Vendor Lock-in",
                                        "Stalled CI/CD Pipelines"
                                    ].map((item, i) => (
                                        <div key={i} className="flex items-center text-muted-foreground">
                                            <X className="h-5 w-5 text-destructive mr-3 shrink-0" />
                                            <span className="text-sm font-medium">{item}</span>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            <div className="md:col-span-2 p-8 md:p-10 bg-primary/5 relative flex flex-col justify-between">
                                <div>
                                    <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-primary via-purple-500 to-primary" />
                                    <div className="absolute -top-3 -right-3">
                                        <span className="bg-primary text-primary-foreground text-xs font-bold px-3 py-1 rounded-bl-xl rounded-tr-xl shadow-lg">SUPREME</span>
                                    </div>

                                    <div className="flex flex-col md:flex-row md:items-center justify-between mb-8">
                                        <div>
                                            <h3 className="text-2xl font-bold text-foreground mb-2">SentinelX Engine</h3>
                                            <p className="text-sm text-primary">The modern active security standard</p>
                                        </div>
                                    </div>

                                    <div className="grid md:grid-cols-2 gap-x-8 gap-y-6">
                                        {[
                                            { title: "Active Verification", desc: "Exploits vulnerabilities safely to prove existence." },
                                            { title: "Zero False Positives", desc: "If we report it, it's real. No more chasing ghosts." },
                                            { title: "Serverless Speed", desc: "Runs on the edge. Scans complete in seconds." },
                                            { title: "Open Core", desc: "Community-driven audits. Enterprise-grade power." },
                                            { title: "One-Click Automate", desc: "Integrates instantly with GitHub Actions & CI/CD." },
                                            { title: "Live Payload Injection", desc: "Tests for 1000+ real-world attack vectors." },
                                            { title: "API-First Design", desc: "Built for developers, fully programmable via API." },
                                            { title: "Self-Hosted Capable", desc: "Run it in your own VPC for total data sovereignty." }
                                        ].map((item, i) => (
                                            <div key={i} className="flex items-start">
                                                <div className="mt-1 bg-primary/20 p-1 rounded-full mr-3 shrink-0">
                                                    <Check className="h-4 w-4 text-primary" />
                                                </div>
                                                <div>
                                                    <h4 className="font-bold text-foreground text-sm">{item.title}</h4>
                                                    <p className="text-xs text-muted-foreground mt-0.5">{item.desc}</p>
                                                </div>
                                            </div>
                                        ))}
                                    </div>
                                </div>

                                {/* Visual Benchmark */}
                                <div className="mt-10 pt-8 border-t border-border/50">
                                    <h4 className="text-sm font-bold text-muted-foreground mb-4 uppercase tracking-wider">Time to Value Benchmark</h4>
                                    <div className="space-y-4">
                                        {/* Legacy Bar */}
                                        <div className="relative">
                                            <div className="flex items-center justify-between text-xs mb-1">
                                                <span className="font-medium text-muted-foreground">Legacy Tools (Qualys/Nessus)</span>
                                                <span className="text-destructive font-bold">45+ Minutes</span>
                                            </div>
                                            <div className="h-3 w-full bg-secondary rounded-full overflow-hidden">
                                                <div className="h-full bg-destructive/50 w-[85%] rounded-full" />
                                            </div>
                                        </div>

                                        {/* SentinelX Bar */}
                                        <div className="relative">
                                            <div className="flex items-center justify-between text-xs mb-1">
                                                <span className="font-medium text-foreground">SentinelX</span>
                                                <span className="text-primary font-bold">~2 Minutes</span>
                                            </div>
                                            <div className="h-3 w-full bg-secondary rounded-full overflow-hidden relative">
                                                <div className="absolute inset-0 bg-primary/20 animate-pulse"></div>
                                                <div className="h-full bg-gradient-to-r from-primary to-purple-500 w-[5%] rounded-full relative z-10 shadow-[0_0_10px_rgba(124,58,237,0.5)]" />
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </Link>
            </div>
        </section>
    );
};

export default ComparisonSection;
