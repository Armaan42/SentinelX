import { useParams, Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { ArrowLeft, Check, X, Wrench, EyeOff, Clock, ShieldAlert, ArrowRight, Lightbulb, Shield, AlertTriangle, Network, CloudFog, FileDigit, Skull } from "lucide-react";
import { useEffect } from "react";

const ProblemDetail = () => {
    const { problemId } = useParams();

    useEffect(() => {
        window.scrollTo(0, 0);
    }, [problemId]);

    const problems = {
        "tool-sprawl": {
            title: "The Tool Sprawl Crisis",
            subtitle: "More Tools ≠ More Security",
            icon: Wrench,
            color: "text-blue-500",
            bg: "bg-blue-500/10",

            // "Newbie Friendly" Deep Dive
            overview: `Imagine trying to fix a car, but for every single bolt, you need to go to a different store to rent a wrench. That is what modern security feels like. Teams are forced to buy one tool for code scanning (SAST), another for website scanning (DAST), and a third for cloud security (CSPM).`,
            painPoint: "This leads to 'Context Switching'. Engineers spend more time logging into different dashboards and correlating data than actually fixing vulnerabilities.",

            // The SentinelX Solution
            solution: "SentinelX unifies all these engines into one platform. We don't just glue them together; we make them talk to each other. A finding in your cloud infrastructure automatically triggers a deeper check in your code.",

            didYouKnow: {
                title: "The Average Enterprise...",
                text: "Uses over 45 different security tools. That involves 45 different logins, 45 different bills, and 45 different ways to report a bug."
            },

            scenario: {
                title: "The 'Missed Signal' Breach",
                description: "In 2013, Target was breached because their security team ignored an alert. Why? because they received thousands of alerts a day. The 'real' alert was buried under mountains of low-priority noise from 10 different tools. Tool sprawl doesn't just annoy people; it hides attacks."
            },

            comparison: {
                legacy: [
                    "Requires 5-10 separate subscriptions",
                    "Data is trapped in silos (PDF reports)",
                    "Engineers must manually match findings",
                    "High maintenance overhead"
                ],
                sentinelx: [
                    "One unified platform for all scans",
                    "All data flows into one central dashboard",
                    "AI automatically correlates related bugs",
                    "Zero maintenance, cloud-native SaaS"
                ]
            }
        },
        "visibility-gaps": {
            title: "Visibility Blind Spots",
            subtitle: "You Can't Fix What You Can't See",
            icon: EyeOff,
            color: "text-amber-500",
            bg: "bg-amber-500/10",

            overview: `Think of your infrastructure like a large warehouse. Traditional security tools are like flashlights—they can only see a small beam of light where you point them. If you have a dark corner that no one checks, that is where the bugs hide.`,
            painPoint: "Most hacks happen in 'Shadow IT'—forgotten servers, old development API keys, or test databases that were never turned off.",

            solution: "SentinelX acts like a floodlight. We use recursive discovery to find every single asset you own, including the ones your team forgot about. We map your entire attack surface before we even start scanning.",

            didYouKnow: {
                title: "Attack Surface Reality",
                text: "69% of organizations have experienced a cyberattack in which the attack started through an unknown, unmanaged, or poorly managed internet-facing asset."
            },

            scenario: {
                title: "The Forgotten Test Server",
                description: "A major bank left a 'test' server running on AWS. It wasn't connected to their main dashboard, so no one patched it. Hackers found it, used it as a stepping stone, and pivoted into the main network to steal 100M+ records. If you can't see it, you can't secure it."
            },

            comparison: {
                legacy: [
                    "Scans only what you manually list",
                    "Misses subdomains and test servers",
                    "Static scheduling (once a month)",
                    "Ignores modern API complexity"
                ],
                sentinelx: [
                    "Auto-discovers new assets daily",
                    "Finds hidden subdomains & APIs",
                    "Continuous monitoring (24/7)",
                    "Understands GraphQL & gRPC"
                ]
            }
        },
        "slow-remediation": {
            title: "The Remediation Lag",
            subtitle: "Finding Bugs is Easy. Fixing is Hard.",
            icon: Clock,
            color: "text-red-500",
            bg: "bg-red-500/10",

            overview: `In many companies, a security report is just a giant PDF of "problems" thrown over the wall to developers. The developers look at it and say "I can't reproduce this." So the ticket sits there for months.`,
            painPoint: "The time between finding a bug and fixing it (MTTR) is increasing because security tools give vague, confusing instructions.",

            solution: "SentinelX treats vulnerabilities as 'Engineering Tasks', not just alerts. We generate the exact code snippet needed to fix the bug and the exact command to verify it. We speak the developer's language.",

            didYouKnow: {
                title: "The 200-Day Problem",
                text: "It takes an average of 200+ days to identify and contain a data breach. Speed is the only defense against modern ransomware."
            },

            scenario: {
                title: "The Equifax Lag",
                description: "Equifax knew about the vulnerability that caused their massive breach months in advance. The patch existed. But due to internal bureaucracy and confusing report handoffs, the patch wasn't applied in time. Slow remediation isn't an inconvenience; it's an existential risk."
            },

            comparison: {
                legacy: [
                    "Generates 100-page PDF reports",
                    "Vague descriptions ('Fix SQL Injection')",
                    "No proof of concept provided",
                    "Security vs. Developer friction"
                ],
                sentinelx: [
                    "Creates Jira tickets with code fixes",
                    "Exact line-of-code pointers",
                    "Generates 'curl' reproduction commands",
                    "Collaborative workflow"
                ]
            }
        },
        "compliance-fatigue": {
            title: "Compliance Fatigue",
            subtitle: "Stop Chasing Paperwork",
            icon: ShieldAlert,
            titleClassName: "text-purple-400",
            color: "text-purple-500",
            bg: "bg-purple-500/10",

            overview: `Every year, companies pause "real work" for weeks to gather screenshots and spreadsheets for auditors (SOC2, ISO 27001). It is boring, manual, and prone to error. It burns out your best engineers.`,
            painPoint: "Compliance becomes a box-ticking exercise rather than actual security.",

            solution: "SentinelX automates the evidence. Because we see everything, we can automatically map a passing scan to a specific compliance requirement. You can download a perfectly formatted audit report in one click.",

            didYouKnow: {
                title: "Audit Burnout",
                text: "40% of CTOs say compliance audits are the single biggest distraction for their engineering teams, costing millions in lost productivity."
            },

            scenario: {
                title: "The 'Checkbox' Security Fallacy",
                description: "Startups often rush to get SOC2 compliant to close huge deals. They manually screenshot evidence for a week, pass the audit, and then stop checking. A week later, they get hacked. Compliance is a snapshot; Security is a video. You need to be secure every day, not just on audit day."
            },

            comparison: {
                legacy: [
                    "Manual screenshot collection",
                    "Excel spreadsheets for tracking",
                    "Panic mode before audit week",
                    "Static point-in-time check"
                ],
                sentinelx: [
                    "Automated evidence gathering",
                    "Real-time compliance dashboard",
                    "Audit-ready every single day",
                    "Continuous control validation"
                ]
            }
        },
        "false-positives": {
            title: "False Positive Fatigue",
            subtitle: "The Boy Who Cried Wolf",
            icon: AlertTriangle,
            color: "text-orange-500",
            bg: "bg-orange-500/10",

            overview: `Imagine a fire alarm that rings every time you make toast. Eventually, you take the batteries out. That is "Alert Fatigue". Legacy scanners flag "possible" issues that aren't actually exploitable, flooding your inbox with noise.`,
            painPoint: "Security teams eventually start ignoring alerts, meaning they miss the one real fire that actually burns the house down.",

            solution: "SentinelX uses 'Active Verification'. We don't just guess there's a bug; we prove it by safely exploiting it. If we can't pop a shell or extract data, we don't page you.",

            didYouKnow: {
                title: "The Noise Ratio",
                text: "The average SOC analyst handles 11,000 security alerts per day. It is mathematically impossible to review them all."
            },

            scenario: {
                title: "The 3AM Page",
                description: "Your Lead Engineer gets paged at 3 AM for a 'Critical SQL Injection'. They wake up, panic, check the logs, and realize it was just a false positive from a generic scanner that didn't understand your framework. They go back to sleep. Next time the pager goes off, they might just ignore it."
            },

            comparison: {
                legacy: [
                    "Flags theoretical risks",
                    "No proof of exploitability",
                    "Requires manual triage",
                    "High 'Noise-to-Signal' ratio"
                ],
                sentinelx: [
                    "Flags confirmed exploits",
                    "Includes proof-of-concept",
                    "Self-triaging engine",
                    "Zero noise guarantee"
                ]
            }
        },
        "shadow-apis": {
            title: "Shadow & Zombie APIs",
            subtitle: "The Backdoor You Left Open",
            icon: Network,
            color: "text-pink-500",
            bg: "bg-pink-500/10",

            overview: `Developers love creating APIs. Sometimes they create a temporary API for testing and forget to delete it. These 'Zombie APIs' have no authentication, no monitoring, and direct access to your database.`,
            painPoint: "Hackers love Zombie APIs because they bypass your expensive WAF and firewalls completely.",

            solution: "SentinelX snoops on your traffic and analyzes your frontend code to find every single API endpoint you have, referenced or not. We build a dynamic inventory of your API surface.",

            didYouKnow: {
                title: "API Breaches",
                text: "Gartner predicts that API abuses will become the most frequent attack vector for enterprise web application data breaches."
            },

            scenario: {
                title: "The Optus API Leak",
                description: "A large telecom company left an API endpoint open without authentication. It was intended for internal testing. Someone found it and scraped customer data for 9 million people. It wasn't 'hacked'; the door was simply left wide open in a dark alley."
            },

            comparison: {
                legacy: [
                    "Scans only documented APIs",
                    "Misses deprecated versions",
                    "Tests simple inputs only",
                    "Blind to business logic"
                ],
                sentinelx: [
                    "Discovers undocumented routes",
                    "Flags 'v1' zombie endpoints",
                    "Fuzzes complex JSON bodies",
                    "Detects logic flaws"
                ]
            }
        },
        "cloud-drift": {
            title: "Cloud Configuration Drift",
            subtitle: "Entropy is the Enemy",
            icon: CloudFog,
            color: "text-cyan-500",
            bg: "bg-cyan-500/10",

            overview: `You set up your cloud securely on Day 1. But on Day 2, a junior dev opens a port for debugging. On Day 3, a terraform script fails. By Day 30, your secure cloud is full of holes. This gradual decay is called 'Drift'.`,
            painPoint: "Audits are usually done quarterly. Drift happens daily. That leaves you vulnerable for 89 days out of 90.",

            solution: "SentinelX monitors your cloud infrastructure in real-time. We benchmark your current state against your 'Golden State' every hour, instantly flagging authorized changes.",

            didYouKnow: {
                title: "The Miscofiguration Epidemic",
                text: "99% of cloud security failures will be the customer's fault (misconfiguration), not the cloud provider's fault."
            },

            scenario: {
                title: "The S3 Bucket Leak",
                description: "A developer makes an S3 bucket 'Public' for five minutes to transfer a file. They get distracted and forget to switch it back. Bots scan the internet for open buckets every second. Within 10 minutes, sensitive customer documents are indexed on the dark web."
            },

            comparison: {
                legacy: [
                    "Quarterly audits",
                    "Manual config review",
                    "Static checklists",
                    "Reactive alerting"
                ],
                sentinelx: [
                    "Continuous monitoring",
                    "Automated drift detection",
                    "Dynamic policy engine",
                    "Proactive remediation"
                ]
            }
        },
        "manual-ops": {
            title: "Manual Operations",
            subtitle: "Human Middleware",
            icon: FileDigit,
            color: "text-emerald-500",
            bg: "bg-emerald-500/10",

            overview: `In many teams, a highly paid security engineer spends 4 hours a day copying data from a security dashboard and pasting it into a Jira ticket. This is 'Human Middleware'. It is slow, boring, and expensive.`,
            painPoint: "Your smartest people are doing the dumbest work.",

            solution: "SentinelX is API-first. We integrate directly into your workflow. Found a bug? We automatically create a Jira ticket, assign it to the right developer, and even open a Pull Request with a fix.",

            didYouKnow: {
                title: "The Cost of Manual Ops",
                text: "Security teams spend over 50% of their time on reporting and administrative tasks instead of hunting threats."
            },

            scenario: {
                title: "The Spreadsheet Silo",
                description: "Vulnerabilities are tracked in an Excel sheet. A dev marks a bug as 'Fixed' in Jira, but forgets to update the sheet. The security team thinks it's still open and re-tests it. Confusion reigns. Meanwhile, the bug was never actually deployed to production."
            },

            comparison: {
                legacy: [
                    "Copy-paste workflows",
                    "Spreadsheets for tracking",
                    "Email-based alerts",
                    "Siloed from DevOps"
                ],
                sentinelx: [
                    "2-way Jira sync",
                    "Automated PR generation",
                    "Slack/Teams integration",
                    "Native DevSecOps"
                ]
            }
        }
    };

    const data = problems[problemId as keyof typeof problems];

    if (!data) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-background text-foreground">
                <div className="text-center">
                    <h1 className="text-4xl font-bold mb-4">Problem Not Found</h1>
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
                        <span className="font-medium">Back to Home</span>
                    </Link>
                    <div className="flex items-center space-x-3">
                        <Shield className="h-6 w-6 text-primary" />
                        <span className="text-xl font-bold tracking-tight">SentinelX</span>
                    </div>
                </div>
            </nav>

            <main className="pt-32 container mx-auto px-6 max-w-6xl">
                {/* Hero Header */}
                <div className="text-center mb-16">
                    <div className={`inline-flex p-5 rounded-2xl ${data.bg} mb-8`}>
                        <Icon className={`h-16 w-16 ${data.color}`} />
                    </div>
                    <h1 className="text-5xl md:text-6xl font-bold mb-4 tracking-tight">{data.title}</h1>
                    <p className={`text-xl md:text-2xl font-light opacity-90 ${data.color}`}>
                        {data.subtitle}
                    </p>
                </div>

                {/* Main Content Grid */}
                <div className="grid lg:grid-cols-2 gap-12 mb-20 items-stretch">
                    {/* Left: The Problem Detail (Educational) */}
                    <div className="space-y-8">
                        <div className="bg-card/50 border border-border/50 rounded-3xl p-8 backdrop-blur-sm h-full flex flex-col">
                            <h2 className="text-2xl font-bold mb-6 flex items-center">
                                <span className="bg-red-500/10 text-red-500 p-2 rounded-lg mr-3">
                                    <X className="w-5 h-5" />
                                </span>
                                The Real Problem
                            </h2>
                            <div className="space-y-6 text-lg text-muted-foreground leading-relaxed flex-grow">
                                <p>{data.overview}</p>
                                <p className="text-foreground font-medium border-l-4 border-red-500/50 pl-4 py-1 bg-red-500/5 rounded-r">
                                    "{data.painPoint}"
                                </p>
                            </div>

                            {/* Scenario Card */}
                            <div className={`mt-8 p-6 rounded-xl border border-dashed border-red-500/30 bg-red-500/5 relative overflow-hidden`}>
                                <div className="absolute top-0 right-0 p-12 bg-red-500/10 blur-[40px] rounded-full" />
                                <div className="flex items-center gap-3 mb-3 text-red-400">
                                    <Skull className="w-5 h-5" />
                                    <span className="text-sm font-bold uppercase tracking-widest">Real World Disaster</span>
                                </div>
                                <h4 className="text-lg font-bold text-foreground mb-2">{data.scenario.title}</h4>
                                <p className="text-sm text-muted-foreground leading-relaxed">{data.scenario.description}</p>
                            </div>
                        </div>
                    </div>

                    {/* Right: The Solution Detail */}
                    <div className="space-y-8">
                        <div className="bg-card/50 border border-border/50 rounded-3xl p-8 backdrop-blur-sm h-full relative overflow-hidden group">
                            <div className={`absolute top-0 right-0 p-32 ${data.bg} blur-[100px] opacity-20`} />
                            <h2 className="text-2xl font-bold mb-6 flex items-center relative z-10">
                                <span className="bg-green-500/10 text-green-500 p-2 rounded-lg mr-3">
                                    <Check className="w-5 h-5" />
                                </span>
                                How SentinelX Fixes It
                            </h2>
                            <div className="space-y-6 text-lg text-muted-foreground leading-relaxed relative z-10">
                                <p>{data.solution}</p>
                                <div className="bg-black/20 p-6 rounded-xl border border-white/5 flex items-start gap-4">
                                    <Lightbulb className="w-6 h-6 text-yellow-500 shrink-0 mt-1" />
                                    <div>
                                        <h4 className="text-sm font-bold text-yellow-500 uppercase tracking-widest mb-1">{data.didYouKnow.title}</h4>
                                        <p className="text-sm italic opacity-80">{data.didYouKnow.text}</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Comparison Table */}
                <div className="mb-20">
                    <h2 className="text-3xl font-bold text-center mb-10">The Difference is Clear</h2>
                    <div className="rounded-3xl border border-border/50 overflow-hidden bg-card/30 backdrop-blur-md">
                        <div className="grid md:grid-cols-2">
                            {/* Legacy Side */}
                            <div className="p-8 md:p-12 border-b md:border-b-0 md:border-r border-border/50 bg-red-500/5">
                                <h3 className="text-xl font-bold mb-8 text-red-400 flex items-center gap-3">
                                    <div className="p-2 bg-red-500/10 rounded-lg"><X className="w-5 h-5" /></div>
                                    Legacy Approach
                                </h3>
                                <ul className="space-y-6">
                                    {data.comparison.legacy.map((item, i) => (
                                        <li key={i} className="flex items-start gap-3 opacity-70">
                                            <div className="w-1.5 h-1.5 rounded-full bg-red-500 mt-2.5 shrink-0" />
                                            <span className="text-lg">{item}</span>
                                        </li>
                                    ))}
                                </ul>
                            </div>

                            {/* SentinelX Side */}
                            <div className="p-8 md:p-12 bg-green-500/5 relative overflow-hidden">
                                <div className="absolute top-0 right-0 w-64 h-64 bg-green-500/10 blur-[80px] rounded-full pointer-events-none" />
                                <h3 className="text-xl font-bold mb-8 text-green-400 flex items-center gap-3 relative z-10">
                                    <div className="p-2 bg-green-500/10 rounded-lg"><Check className="w-5 h-5" /></div>
                                    SentinelX Approach
                                </h3>
                                <ul className="space-y-6 relative z-10">
                                    {data.comparison.sentinelx.map((item, i) => (
                                        <li key={i} className="flex items-start gap-3">
                                            <div className="w-6 h-6 rounded-full bg-green-500/20 text-green-500 flex items-center justify-center shrink-0 text-xs">
                                                <Check className="w-3.5 h-3.5" />
                                            </div>
                                            <span className="text-lg font-medium">{item}</span>
                                        </li>
                                    ))}
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>

                {/* CTA */}
                <div className="text-center bg-primary/5 rounded-3xl p-12 border border-primary/10">
                    <h2 className="text-3xl font-bold mb-6">Ready to solve the {data.title.toLowerCase()}?</h2>
                    <Button size="lg" className="h-14 px-8 text-lg rounded-full" asChild>
                        <Link to="/demo">
                            See SentinelX in Action <ArrowRight className="ml-2 w-5 h-5" />
                        </Link>
                    </Button>
                </div>
            </main>
        </div>
    );
};

export default ProblemDetail;
