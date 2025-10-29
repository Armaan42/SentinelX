import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { 
  Shield, 
  Scan, 
  Settings, 
  BarChart3, 
  Zap, 
  Lock, 
  CheckCircle, 
  ArrowRight, 
  Github, 
  Download,
  Server,
  Eye,
  Network,
  Terminal
} from "lucide-react";

import heroImage from "@/assets/hero-security.jpg";

const Index = () => {
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    setIsVisible(true);
  }, []);

  const features = [
    {
      icon: Scan,
      title: "External Vulnerability Scanning",
      description: "Advanced scanning engine detects vulnerabilities in web applications and network services with customizable templates."
    },
    {
      icon: Settings,
      title: "Internal Security Auditing", 
      description: "Comprehensive OS hardening, compliance checks, and misconfiguration detection for complete system security."
    },
    {
      icon: Zap,
      title: "Automation Ready",
      description: "Seamless integration with security pipelines, SIEM systems, and SOC workflows for proactive security management."
    },
    {
      icon: BarChart3,
      title: "Unified Reporting",
      description: "Centralized, prioritized reports correlating findings from both external and internal security assessments."
    }
  ];

  const techStack = [
    { name: "Python", description: "Core scanning logic and analysis engine" },
    { name: "Bash Scripting", description: "System integration and orchestration" },
    { name: "Linux", description: "Native platform optimization" },
    { name: "SLSA", description: "Supply chain security and build provenance" }
  ];

  const stats = [
    { value: "100%", label: "Python & Bash" },
    { value: "Zero", label: "External Dependencies" },
    { value: "Linux", label: "Native Platform" },
    { value: "Open", label: "Source Ready" }
  ];

  return (
    <div className="min-h-screen bg-background">
      {/* Navigation */}
      <nav className="fixed top-0 w-full bg-background/80 backdrop-blur-md border-b border-border z-50">
        <div className="container mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Shield className="h-8 w-8 text-primary" />
            <span className="text-xl font-bold gradient-text">SentinelX</span>
          </div>
          
          <div className="hidden md:flex items-center space-x-8">
            <a href="#features" className="text-muted-foreground hover:text-primary transition-colors">Features</a>
            <a href="#technology" className="text-muted-foreground hover:text-primary transition-colors">Technology</a>
            <a href="#download" className="text-muted-foreground hover:text-primary transition-colors">Download</a>
            <Button variant="outline" size="sm" asChild>
              <a href="https://github.com/Armaan42/SentinelX" target="_blank" rel="noopener noreferrer">
                <Github className="h-4 w-4 mr-2" />
                GitHub
              </a>
            </Button>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative min-h-screen flex items-center justify-center overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-background to-muted/30" />
        <div 
          className="absolute inset-0 bg-cover bg-center opacity-10"
          style={{ backgroundImage: `url(${heroImage})` }}
        />
        
        <div className={`relative z-10 text-center px-4 transition-all duration-700 ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-10'}`}>
          <Badge variant="secondary" className="mb-6 text-sm px-4 py-2">
            Introducing SentinelX Framework
          </Badge>
          
          <h1 className="text-4xl md:text-6xl font-bold mb-6 leading-tight">
            <span className="text-primary">Unified Security</span>
            <br />
            <span className="text-foreground">for the Modern Enterprise</span>
          </h1>
          
          <p className="text-lg md:text-xl text-muted-foreground mb-8 max-w-2xl mx-auto">
            Cybersecurity framework combining external vulnerability scanning 
            and internal system auditing in one powerful platform.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
            <Button size="lg" asChild>
              <a href="https://github.com/Armaan42/SentinelX" target="_blank" rel="noopener noreferrer">
                <Download className="h-5 w-5 mr-2" />
                Get Started Free
              </a>
            </Button>
            <Button variant="outline" size="lg" asChild>
              <Link to="/demo">
                <Eye className="h-5 w-5 mr-2" />
                View Demo
              </Link>
            </Button>
          </div>
          
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6 mt-16 max-w-3xl mx-auto">
            {stats.map((stat, index) => (
              <div key={index} className="text-center p-4 rounded-lg bg-card/50 border border-border">
                <div className="text-xl font-semibold text-primary mb-1">{stat.value}</div>
                <div className="text-xs text-muted-foreground">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Problem Statement */}
      <section className="py-20 px-4">
        <div className="container mx-auto max-w-4xl text-center">
          <h2 className="text-3xl md:text-4xl font-bold mb-8">
            The <span className="text-destructive">Security Fragmentation</span> Problem
          </h2>
          <p className="text-lg text-muted-foreground mb-12">
            Organizations struggle with disjointed security tools, creating blind spots, 
            operational complexity, and delayed incident response in today's threat landscape.
          </p>
          
          <div className="grid md:grid-cols-3 gap-8">
            {[
              { icon: "🔧", title: "Multiple Tools", desc: "Managing separate external and internal security solutions" },
              { icon: "👁️", title: "Blind Spots", desc: "Fragmented visibility across security domains" },
              { icon: "⏰", title: "Delayed Response", desc: "Slow incident detection and remediation workflows" }
            ].map((item, index) => (
              <Card key={index} className="bg-card border-border hover:border-primary/50 transition-all">
                <CardContent className="p-6 text-center">
                  <div className="text-3xl mb-3">{item.icon}</div>
                  <h3 className="font-semibold mb-2 text-destructive">{item.title}</h3>
                  <p className="text-muted-foreground text-sm">{item.desc}</p>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 px-4 bg-muted/20">
        <div className="container mx-auto">
          <div className="text-center mb-16">
            <Badge variant="secondary" className="mb-4">Core Capabilities</Badge>
            <h2 className="text-3xl md:text-4xl font-bold mb-6">
              <span className="text-primary">Comprehensive Security</span> in One Platform
            </h2>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              SentinelX eliminates security tool fragmentation with unified scanning, auditing, and reporting capabilities.
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-8 mb-12">
            <Card className="bg-card border-border hover:border-primary/50 transition-all">
              <CardHeader>
                <div className="flex items-center space-x-3 mb-4">
                  <div className="p-2 rounded-lg bg-primary/10">
                    <Network className="h-6 w-6 text-primary" />
                  </div>
                  <CardTitle className="text-xl">External Vulnerability Scanning</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-start space-x-3">
                  <CheckCircle className="h-5 w-5 text-primary mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="font-medium text-foreground">Advanced Web Application Testing</p>
                    <p className="text-sm text-muted-foreground">Detect OWASP Top 10 and custom vulnerabilities</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3">
                  <CheckCircle className="h-5 w-5 text-primary mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="font-medium text-foreground">Network Service Analysis</p>
                    <p className="text-sm text-muted-foreground">Port scanning, service enumeration, and exploitation</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3">
                  <CheckCircle className="h-5 w-5 text-primary mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="font-medium text-foreground">Customizable Templates</p>
                    <p className="text-sm text-muted-foreground">Modular scanning rules and exploit payloads</p>
                  </div>
                </div>
              </CardContent>
            </Card>

            <Card className="bg-card border-border hover:border-primary/50 transition-all">
              <CardHeader>
                <div className="flex items-center space-x-3 mb-4">
                  <div className="p-2 rounded-lg bg-secondary/10">
                    <Server className="h-6 w-6 text-secondary" />
                  </div>
                  <CardTitle className="text-xl">Internal Security Auditing</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-start space-x-3">
                  <CheckCircle className="h-5 w-5 text-secondary mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="font-medium text-foreground">OS Hardening Assessment</p>
                    <p className="text-sm text-muted-foreground">Linux system configuration and security posture</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3">
                  <CheckCircle className="h-5 w-5 text-secondary mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="font-medium text-foreground">Compliance Benchmarking</p>
                    <p className="text-sm text-muted-foreground">CIS, NIST, and custom compliance frameworks</p>
                  </div>
                </div>
                <div className="flex items-start space-x-3">
                  <CheckCircle className="h-5 w-5 text-secondary mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="font-medium text-foreground">Permission & Configuration Analysis</p>
                    <p className="text-sm text-muted-foreground">File systems, services, and access controls</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            {features.map((feature, index) => (
              <Card key={index} className="bg-card border-border hover:border-primary/50 transition-all">
                <CardHeader className="text-center pb-3">
                  <div className="p-3 rounded-lg bg-primary/10 w-fit mx-auto mb-3">
                    <feature.icon className="h-6 w-6 text-primary" />
                  </div>
                  <CardTitle className="text-base">{feature.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <CardDescription className="text-center text-sm">{feature.description}</CardDescription>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Technology Stack */}
      <section id="technology" className="py-20 px-4">
        <div className="container mx-auto max-w-4xl text-center">
          <Badge variant="secondary" className="mb-4">Technology Stack</Badge>
          <h2 className="text-3xl md:text-4xl font-bold mb-6">
            Built with <span className="text-primary">Modern Technologies</span>
          </h2>
          <p className="text-lg text-muted-foreground mb-12">
            SentinelX leverages proven technologies for maximum performance, security, and extensibility.
          </p>

          <div className="grid md:grid-cols-2 gap-6">
            {techStack.map((tech, index) => (
              <Card key={index} className="bg-card border-border hover:border-primary/50 transition-all text-left">
                <CardHeader>
                  <div className="flex items-center space-x-3">
                    <Terminal className="h-5 w-5 text-primary" />
                    <CardTitle className="text-lg">{tech.name}</CardTitle>
                  </div>
                </CardHeader>
                <CardContent>
                  <CardDescription className="text-sm">{tech.description}</CardDescription>
                </CardContent>
              </Card>
            ))}
          </div>

          <div className="mt-12 p-6 bg-muted/20 rounded-lg border border-border">
            <h3 className="text-lg font-semibold mb-3 flex items-center justify-center">
              <Lock className="h-5 w-5 text-secondary mr-2" />
              SLSA Supply Chain Security
            </h3>
            <p className="text-muted-foreground text-sm">
              Every SentinelX build includes SLSA attestations, ensuring verifiable provenance 
              and supply chain integrity for enterprise-grade security.
            </p>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section id="download" className="py-20 px-4 bg-muted/30">
        <div className="container mx-auto max-w-4xl text-center">
          <h2 className="text-3xl md:text-4xl font-bold mb-6">
            Ready to Unify Your Security Operations?
          </h2>
          <p className="text-lg text-muted-foreground mb-8">
            Join security teams worldwide using SentinelX for comprehensive vulnerability management.
          </p>
          
          <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
            <Button size="lg" asChild>
              <a href="https://github.com/Armaan42/SentinelX" target="_blank" rel="noopener noreferrer">
                <Download className="h-5 w-5 mr-2" />
                Download SentinelX
              </a>
            </Button>
            <Button variant="outline" size="lg" asChild>
              <a href="https://github.com/Armaan42/SentinelX" target="_blank" rel="noopener noreferrer">
                <Github className="h-5 w-5 mr-2" />
                View Source Code
              </a>
            </Button>
          </div>

          <div className="mt-8 text-sm text-muted-foreground">
            Open source • Linux native • Enterprise ready
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="bg-background border-t border-border py-12 px-4">
        <div className="container mx-auto max-w-6xl">
          <div className="grid md:grid-cols-3 gap-8">
            <div className="col-span-2">
              <div className="flex items-center space-x-2 mb-4">
                <Shield className="h-6 w-6 text-primary" />
                <span className="text-lg font-bold">SentinelX</span>
              </div>
              <p className="text-muted-foreground mb-4 text-sm">
                Unified cybersecurity framework for vulnerability scanning and system auditing.
              </p>
              <div className="flex space-x-4">
                <Button variant="ghost" size="sm" asChild>
                  <a href="https://github.com/Armaan42/SentinelX" target="_blank" rel="noopener noreferrer">
                    <Github className="h-4 w-4" />
                  </a>
                </Button>
              </div>
            </div>
            
            <div>
              <h4 className="font-semibold mb-4">Product</h4>
              <div className="space-y-2 text-sm text-muted-foreground">
                <div><a href="#features" className="hover:text-primary transition-colors">Features</a></div>
                <div><a href="#technology" className="hover:text-primary transition-colors">Technology</a></div>
                <div><a href="#download" className="hover:text-primary transition-colors">Download</a></div>
              </div>
            </div>
          </div>
          
          <div className="border-t border-border mt-12 pt-8 text-center text-sm text-muted-foreground">
            © 2025 SentinelX Security Framework. Open source cybersecurity for modern enterprises.
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Index;