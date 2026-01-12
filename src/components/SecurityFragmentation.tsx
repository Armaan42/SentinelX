import { Card, CardContent } from "@/components/ui/card";
import { Wrench, EyeOff, Clock, ShieldAlert, AlertTriangle, Network, CloudFog, FileDigit, ArrowUpRight, ArrowRight } from "lucide-react";
import { Link } from "react-router-dom";

const SecurityFragmentation = () => {
    return (
        <section className="py-32 px-6 relative overflow-hidden bg-background">
            {/* Background Elements */}
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-full max-w-7xl opacity-50 pointer-events-none">
                <div className="absolute top-20 left-10 w-96 h-96 bg-primary/10 rounded-full blur-[100px] animate-pulse" />
                <div className="absolute bottom-20 right-10 w-[500px] h-[500px] bg-destructive/5 rounded-full blur-[120px]" />
            </div>

            <div className="container mx-auto max-w-6xl relative z-10">
                <div className="text-center mb-20">
                    <div className="inline-flex items-center justify-center p-2.5 px-4 bg-destructive/5 rounded-full mb-8 border border-destructive/10">
                        <ShieldAlert className="h-5 w-5 text-destructive mr-2" />
                        <span className="text-sm font-semibold text-destructive uppercase tracking-vide">The Industry Challenge</span>
                    </div>

                    <h2 className="text-4xl md:text-5xl lg:text-6xl font-bold mb-8 leading-tight tracking-tight">
                        The <span className="text-destructive relative inline-block">
                            Security Fragmentation
                            <svg className="absolute w-full h-3 -bottom-1 left-0 text-destructive/20" viewBox="0 0 100 10" preserveAspectRatio="none">
                                <path d="M0 5 Q 50 10 100 5" stroke="currentColor" strokeWidth="3" fill="none" />
                            </svg>
                        </span> Problem
                    </h2>
                    <p className="text-xl md:text-2xl text-muted-foreground max-w-3xl mx-auto leading-relaxed">
                        Modern security teams are drowning in disconnected tools, creating dangerous blind spots
                        and slowing down remediation when it matters most.
                    </p>
                </div>

                <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 relative">
                    {[
                        {
                            id: "tool-sprawl",
                            icon: Wrench,
                            title: "Tool Sprawl",
                            desc: "Managing 10+ separate tools for SAST, DAST, SCA, and container security creates operational chaos.",
                            stat: "10+ Tools Avg",
                            color: "text-blue-500",
                            bg: "bg-blue-500/10",
                            border: "group-hover:border-blue-500/30"
                        },
                        {
                            id: "visibility-gaps",
                            icon: EyeOff,
                            title: "Visibility Gaps",
                            desc: "Siloed data means you never get the full picture. Vulnerabilities hide in the seams between tools.",
                            stat: "60% Blind Spots",
                            color: "text-amber-500",
                            bg: "bg-amber-500/10",
                            border: "group-hover:border-amber-500/30"
                        },
                        {
                            id: "slow-remediation",
                            icon: Clock,
                            title: "Slow Remediation",
                            desc: "Context switching between dashboards delays incident response by an average of 40%.",
                            stat: "40% Slower",
                            color: "text-red-500",
                            bg: "bg-red-500/10",
                            border: "group-hover:border-red-500/30"
                        },
                        {
                            id: "compliance-fatigue",
                            icon: ShieldAlert,
                            title: "Compliance Fatigue",
                            desc: "Manual evidence collection for SOC2, ISO, and GDPR consumes hundreds of engineering hours.",
                            stat: "200+ Hours/Yr",
                            color: "text-purple-500",
                            bg: "bg-purple-500/10",
                            border: "group-hover:border-purple-500/30"
                        },
                        {
                            id: "false-positives",
                            icon: AlertTriangle,
                            title: "False Positives",
                            desc: "Security teams waste 50% of their time chasing bugs that don't exist, leading to alert fatigue.",
                            stat: "50% Wasted Time",
                            color: "text-orange-500",
                            bg: "bg-orange-500/10",
                            border: "group-hover:border-orange-500/30"
                        },
                        {
                            id: "shadow-apis",
                            icon: Network,
                            title: "Shadow APIs",
                            desc: "30% of APIs are undocumented and unmonitored, becoming the #1 attack vector for data breaches.",
                            stat: "30% Unknown",
                            color: "text-pink-500",
                            bg: "bg-pink-500/10",
                            border: "group-hover:border-pink-500/30"
                        },
                        {
                            id: "cloud-drift",
                            icon: CloudFog,
                            title: "Cloud Drift",
                            desc: "Infrastructure changes daily. A secure setup on Monday can be wide open by Friday due to 'drift'.",
                            stat: "Daily Drill",
                            color: "text-cyan-500",
                            bg: "bg-cyan-500/10",
                            border: "group-hover:border-cyan-500/30"
                        },
                        {
                            id: "manual-ops",
                            icon: FileDigit,
                            title: "Manual Ops",
                            desc: "Copy-pasting data from scanners to Jira creates a 'human middleware' bottleneck.",
                            stat: "Human Slow",
                            color: "text-emerald-500",
                            bg: "bg-emerald-500/10",
                            border: "group-hover:border-emerald-500/30"
                        }
                    ].map((item, index) => (
                        <Link key={index} to={`/problem/${item.id}`} className="group relative block cursor-pointer">
                            <div className={`absolute inset-0 bg-gradient-to-br from-card/50 to-background rounded-3xl blur-xl transition-all duration-500 group-hover:blur-2xl opacity-0 group-hover:opacity-100 ${item.bg}`} />
                            <Card className={`relative h-full bg-card/40 backdrop-blur-xl border-border/60 rounded-3xl transition-all duration-500 transform group-hover:-translate-y-2 group-hover:shadow-2xl ${item.border}`}>
                                <CardContent className="p-10 flex flex-col h-full items-center text-center relative">
                                    <div className="absolute top-6 right-6 opacity-0 group-hover:opacity-100 transition-opacity">
                                        <ArrowUpRight className="w-5 h-5 text-muted-foreground" />
                                    </div>
                                    <div className={`p-5 rounded-2xl mb-8 ${item.bg} ${item.color} group-hover:scale-110 transition-transform duration-500`}>
                                        <item.icon className="h-10 w-10" />
                                    </div>
                                    <h3 className="text-2xl font-bold mb-5 tracking-tight">{item.title}</h3>
                                    <p className="text-muted-foreground leading-relaxed text-sm mb-6 flex-grow">
                                        {item.desc}
                                    </p>
                                    <div className="text-lg font-bold text-foreground mb-4">
                                        {item.stat}
                                    </div>
                                    <div className={`h-1.5 w-16 rounded-full ${item.bg.replace('/10', '')} opacity-20 group-hover:opacity-100 transition-all duration-500`} />
                                </CardContent>
                            </Card>
                        </Link>
                    ))}
                </div>

                {/* Bridge to Solution */}
                <div className="mt-24 text-center">
                    <div className="inline-flex items-center justify-center space-x-4 p-2 px-6 border border-border/60 rounded-full bg-background/50 backdrop-blur-xl shadow-lg hover:shadow-xl transition-all cursor-default">
                        <div className="h-2 w-2 rounded-full bg-primary animate-pulse" />
                        <span className="text-sm font-medium text-foreground">SentinelX unifies this chaos</span>
                        <div className="h-4 w-px bg-border" />
                        <ArrowRight className="h-4 w-4 text-primary" />
                    </div>
                </div>
            </div>
        </section>
    );
};

export default SecurityFragmentation;
