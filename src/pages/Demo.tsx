import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  ArrowLeft, 
  Scan,
  Download,
  Globe,
  Lock,
  Server,
  FileText
} from "lucide-react";
import { Link } from "react-router-dom";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

interface Vulnerability {
  name: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  description: string;
  recommendation: string;
}

interface ScanResult {
  target: string;
  scanDate: string;
  securityScore: number;
  riskLevel: string;
  vulnerabilities: Vulnerability[];
  sslValid: string;
  cmsDetected: string;
  totalFindings: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

const Demo = () => {
  const [targetUrl, setTargetUrl] = useState("");
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentScanPhase, setCurrentScanPhase] = useState("");

  const simulateVulnerabilityScan = async (url: string): Promise<ScanResult> => {
    // Simulate scanning phases
    const phases = [
      { name: "Analyzing SSL/TLS Configuration", duration: 800 },
      { name: "Checking HTTP Security Headers", duration: 700 },
      { name: "Detecting Technology Stack", duration: 900 },
      { name: "Scanning for Open Directories", duration: 600 },
      { name: "Testing API Endpoints", duration: 800 },
      { name: "Vulnerability Assessment", duration: 700 }
    ];

    let progress = 0;
    for (const phase of phases) {
      setCurrentScanPhase(phase.name);
      await new Promise(resolve => setTimeout(resolve, phase.duration));
      progress += 100 / phases.length;
      setScanProgress(Math.min(progress, 100));
    }

    // Generate realistic vulnerabilities based on common patterns
    const allVulnerabilities: Vulnerability[] = [
      {
        name: "Missing HSTS Header",
        severity: "Medium",
        description: "HTTPS is used, but HSTS header is not enforced, allowing SSL stripping attacks.",
        recommendation: "Add Strict-Transport-Security header in your web server configuration with max-age=31536000."
      },
      {
        name: "X-Frame-Options Missing",
        severity: "Low",
        description: "Page can be framed, allowing clickjacking attacks.",
        recommendation: "Add X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN header."
      },
      {
        name: "Content-Security-Policy Not Set",
        severity: "Medium",
        description: "Missing CSP header allows potential XSS attacks and unauthorized resource loading.",
        recommendation: "Implement a Content-Security-Policy header with appropriate directives."
      },
      {
        name: "Directory Listing Enabled",
        severity: "Medium",
        description: "/uploads/ reveals file index, potential sensitive information leak.",
        recommendation: "Disable directory indexing in server configuration (Options -Indexes)."
      },
      {
        name: "Outdated CMS Version Detected",
        severity: "High",
        description: "WordPress 5.7.2 detected with known RCE vulnerability (CVE-2021-29447).",
        recommendation: "Update to the latest WordPress version immediately (6.0+)."
      },
      {
        name: "API Debug Endpoint Exposed",
        severity: "Critical",
        description: "/api/debug endpoint exposed with sensitive stack traces and configuration details.",
        recommendation: "Restrict debug endpoints to development environments only or implement IP whitelisting."
      },
      {
        name: "Weak SSL/TLS Configuration",
        severity: "High",
        description: "Server supports TLS 1.0/1.1 which are deprecated and vulnerable to attacks.",
        recommendation: "Disable TLS 1.0/1.1 and enable only TLS 1.2 and TLS 1.3."
      },
      {
        name: "Missing X-Content-Type-Options",
        severity: "Low",
        description: "Browser MIME-type sniffing is not prevented, allowing content-type attacks.",
        recommendation: "Add X-Content-Type-Options: nosniff header."
      },
      {
        name: "Referrer-Policy Not Configured",
        severity: "Low",
        description: "Referrer information may leak sensitive data to external sites.",
        recommendation: "Set Referrer-Policy: strict-origin-when-cross-origin or stricter."
      },
      {
        name: "Sensitive Files Accessible",
        severity: "High",
        description: "/.git/config and /backup files are publicly accessible.",
        recommendation: "Block access to sensitive files and directories via web server configuration."
      }
    ];

    // Randomly select 5-7 vulnerabilities for variety
    const numVulns = Math.floor(Math.random() * 3) + 5;
    const selectedVulnerabilities = allVulnerabilities
      .sort(() => Math.random() - 0.5)
      .slice(0, numVulns);

    // Count severity levels
    const totalFindings = {
      critical: selectedVulnerabilities.filter(v => v.severity === "Critical").length,
      high: selectedVulnerabilities.filter(v => v.severity === "High").length,
      medium: selectedVulnerabilities.filter(v => v.severity === "Medium").length,
      low: selectedVulnerabilities.filter(v => v.severity === "Low").length
    };

    // Calculate security score (100 - weighted vulnerabilities)
    const score = Math.max(
      45,
      100 - (totalFindings.critical * 20 + totalFindings.high * 10 + totalFindings.medium * 5 + totalFindings.low * 2)
    );

    // Determine risk level
    let riskLevel = "Low";
    if (score < 50) riskLevel = "Critical";
    else if (score < 65) riskLevel = "High";
    else if (score < 80) riskLevel = "Medium";

    return {
      target: url,
      scanDate: new Date().toLocaleDateString("en-US", { 
        year: "numeric", 
        month: "long", 
        day: "numeric" 
      }),
      securityScore: score,
      riskLevel,
      vulnerabilities: selectedVulnerabilities,
      sslValid: "February 2026",
      cmsDetected: "WordPress 5.7.2",
      totalFindings
    };
  };

  const handleScan = async () => {
    if (!targetUrl.trim()) {
      return;
    }

    setIsScanning(true);
    setScanProgress(0);
    setScanResult(null);

    try {
      const result = await simulateVulnerabilityScan(targetUrl);
      setScanResult(result);
    } catch (error) {
      console.error("Scan error:", error);
    } finally {
      setIsScanning(false);
      setCurrentScanPhase("");
    }
  };

  const generatePDF = () => {
    if (!scanResult) return;

    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    
    // Title
    doc.setFontSize(20);
    doc.setFont("helvetica", "bold");
    doc.text("Website Vulnerability Report", pageWidth / 2, 20, { align: "center" });
    
    // Report details
    doc.setFontSize(10);
    doc.setFont("helvetica", "normal");
    doc.text(`Target: ${scanResult.target}`, 14, 35);
    doc.text(`Scan Date: ${scanResult.scanDate}`, 14, 42);
    doc.text(`Security Score: ${scanResult.securityScore}/100`, 14, 49);
    doc.text(`Risk Level: ${scanResult.riskLevel}`, 14, 56);
    
    // Summary section
    doc.setFontSize(14);
    doc.setFont("helvetica", "bold");
    doc.text("Summary of Findings", 14, 70);
    
    doc.setFontSize(10);
    doc.setFont("helvetica", "normal");
    const summary = [
      `Total vulnerabilities detected: ${scanResult.vulnerabilities.length}`,
      `${scanResult.totalFindings.critical} Critical | ${scanResult.totalFindings.high} High | ${scanResult.totalFindings.medium} Medium | ${scanResult.totalFindings.low} Low`,
      `SSL certificate valid until: ${scanResult.sslValid}`,
      `CMS detected: ${scanResult.cmsDetected}`
    ];
    
    let yPos = 78;
    summary.forEach(line => {
      doc.text(line, 14, yPos);
      yPos += 7;
    });
    
    // Vulnerability table
    doc.setFontSize(14);
    doc.setFont("helvetica", "bold");
    doc.text("Vulnerability Breakdown", 14, yPos + 8);
    
    const tableData = scanResult.vulnerabilities.map(v => [
      v.name,
      v.severity,
      v.description,
      v.recommendation
    ]);
    
    autoTable(doc, {
      startY: yPos + 15,
      head: [["Vulnerability", "Severity", "Description", "Recommendation"]],
      body: tableData,
      theme: "grid",
      headStyles: { fillColor: [71, 85, 105], fontSize: 9, fontStyle: "bold" },
      bodyStyles: { fontSize: 8 },
      columnStyles: {
        0: { cellWidth: 35 },
        1: { cellWidth: 20 },
        2: { cellWidth: 60 },
        3: { cellWidth: 60 }
      },
      margin: { left: 14, right: 14 }
    });
    
    // Risk matrix
    const finalY = (doc as any).lastAutoTable.finalY || yPos + 100;
    doc.setFontSize(14);
    doc.setFont("helvetica", "bold");
    doc.text("Risk Matrix", 14, finalY + 15);
    
    autoTable(doc, {
      startY: finalY + 20,
      head: [["Risk Level", "Count", "Impact"]],
      body: [
        ["Critical", scanResult.totalFindings.critical.toString(), "System Compromise"],
        ["High", scanResult.totalFindings.high.toString(), "Data Exposure"],
        ["Medium", scanResult.totalFindings.medium.toString(), "Moderate Risk"],
        ["Low", scanResult.totalFindings.low.toString(), "Informational"]
      ],
      theme: "striped",
      headStyles: { fillColor: [71, 85, 105] }
    });
    
    // Footer
    const finalPageY = (doc as any).lastAutoTable.finalY || finalY + 60;
    doc.setFontSize(10);
    doc.setFont("helvetica", "italic");
    doc.text("Generated by SentinelX Unified Cybersecurity Framework", pageWidth / 2, finalPageY + 15, { align: "center" });
    
    // Save PDF
    const filename = `${scanResult.target.replace(/https?:\/\//, "").replace(/\//g, "_")}_Vulnerability_Report_${new Date().toISOString().split("T")[0]}.pdf`;
    doc.save(filename);
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "Critical": return "destructive";
      case "High": return "default";
      case "Medium": return "secondary";
      case "Low": return "outline";
      default: return "outline";
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-background via-background to-muted/20">
      <div className="container mx-auto px-4 py-8 max-w-7xl">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <Link to="/">
            <Button variant="ghost" size="sm">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Home
            </Button>
          </Link>
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            <h1 className="text-2xl font-bold">Security Scanner Demo</h1>
          </div>
        </div>

        {/* Scan Input */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Globe className="h-5 w-5" />
              Website Vulnerability Scanner
            </CardTitle>
            <CardDescription>
              Enter a website URL to perform a comprehensive security analysis
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex gap-4">
              <div className="flex-1">
                <Input
                  type="url"
                  placeholder="https://example.com"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  disabled={isScanning}
                  className="text-base"
                />
              </div>
              <Button 
                onClick={handleScan} 
                disabled={isScanning || !targetUrl.trim()}
                size="lg"
              >
                {isScanning ? (
                  <>
                    <Scan className="mr-2 h-4 w-4 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Scan className="mr-2 h-4 w-4" />
                    Start Scan
                  </>
                )}
              </Button>
            </div>

            {/* Progress Bar */}
            {isScanning && (
              <div className="mt-6 space-y-2">
                <Progress value={scanProgress} className="h-2" />
                <p className="text-sm text-muted-foreground flex items-center gap-2">
                  <Server className="h-4 w-4 animate-pulse" />
                  {currentScanPhase}
                </p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Scan Results */}
        {scanResult && (
          <div className="space-y-6">
            {/* Success Alert */}
            <Alert className="border-green-500 bg-green-50 dark:bg-green-950">
              <CheckCircle className="h-4 w-4 text-green-600" />
              <AlertDescription className="text-green-800 dark:text-green-200">
                ✅ Scan Completed. Vulnerability report generated successfully.
              </AlertDescription>
            </Alert>

            {/* Overview Card */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  <span className="flex items-center gap-2">
                    <FileText className="h-5 w-5" />
                    Website Vulnerability Report
                  </span>
                  <Button onClick={generatePDF} variant="outline" size="sm">
                    <Download className="mr-2 h-4 w-4" />
                    Download PDF Report
                  </Button>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Report Header */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 bg-muted/50 rounded-lg">
                  <div>
                    <p className="text-sm text-muted-foreground">Target</p>
                    <p className="font-medium truncate">{scanResult.target}</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Scan Date</p>
                    <p className="font-medium">{scanResult.scanDate}</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Security Score</p>
                    <p className="font-bold text-2xl">{scanResult.securityScore}/100</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Risk Level</p>
                    <Badge variant={scanResult.riskLevel === "Critical" || scanResult.riskLevel === "High" ? "destructive" : "secondary"}>
                      {scanResult.riskLevel}
                    </Badge>
                  </div>
                </div>

                {/* Summary */}
                <div>
                  <h3 className="text-lg font-semibold mb-3 flex items-center gap-2">
                    <Shield className="h-5 w-5" />
                    Summary of Findings
                  </h3>
                  <div className="space-y-2 text-sm">
                    <p>Total vulnerabilities detected: <span className="font-bold">{scanResult.vulnerabilities.length}</span></p>
                    <div className="flex gap-4">
                      <span className="text-destructive font-semibold">{scanResult.totalFindings.critical} Critical</span>
                      <span className="text-orange-500 font-semibold">{scanResult.totalFindings.high} High</span>
                      <span className="text-yellow-500 font-semibold">{scanResult.totalFindings.medium} Medium</span>
                      <span className="text-blue-500 font-semibold">{scanResult.totalFindings.low} Low</span>
                    </div>
                    <p>SSL certificate valid until: <span className="font-medium">{scanResult.sslValid}</span></p>
                    <p>CMS detected: <span className="font-medium">{scanResult.cmsDetected}</span></p>
                  </div>
                </div>

                {/* Vulnerability Breakdown */}
                <div>
                  <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5" />
                    Vulnerability Breakdown
                  </h3>
                  <div className="overflow-x-auto">
                    <table className="w-full border-collapse">
                      <thead>
                        <tr className="border-b bg-muted/50">
                          <th className="text-left p-3 font-semibold">Vulnerability</th>
                          <th className="text-left p-3 font-semibold">Severity</th>
                          <th className="text-left p-3 font-semibold">Description</th>
                          <th className="text-left p-3 font-semibold">Recommendation</th>
                        </tr>
                      </thead>
                      <tbody>
                        {scanResult.vulnerabilities.map((vuln, idx) => (
                          <tr key={idx} className="border-b hover:bg-muted/30 transition-colors">
                            <td className="p-3 font-medium">{vuln.name}</td>
                            <td className="p-3">
                              <Badge variant={getSeverityBadge(vuln.severity) as any}>
                                {vuln.severity}
                              </Badge>
                            </td>
                            <td className="p-3 text-sm text-muted-foreground">{vuln.description}</td>
                            <td className="p-3 text-sm">{vuln.recommendation}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Risk Matrix */}
                <div>
                  <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                    <Lock className="h-5 w-5" />
                    Risk Matrix
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <Card className="border-destructive">
                      <CardContent className="p-4">
                        <p className="text-sm text-muted-foreground">Critical</p>
                        <p className="text-2xl font-bold text-destructive">{scanResult.totalFindings.critical}</p>
                        <p className="text-xs text-muted-foreground mt-1">System Compromise</p>
                      </CardContent>
                    </Card>
                    <Card className="border-orange-500">
                      <CardContent className="p-4">
                        <p className="text-sm text-muted-foreground">High</p>
                        <p className="text-2xl font-bold text-orange-500">{scanResult.totalFindings.high}</p>
                        <p className="text-xs text-muted-foreground mt-1">Data Exposure</p>
                      </CardContent>
                    </Card>
                    <Card className="border-yellow-500">
                      <CardContent className="p-4">
                        <p className="text-sm text-muted-foreground">Medium</p>
                        <p className="text-2xl font-bold text-yellow-500">{scanResult.totalFindings.medium}</p>
                        <p className="text-xs text-muted-foreground mt-1">Moderate Risk</p>
                      </CardContent>
                    </Card>
                    <Card className="border-blue-500">
                      <CardContent className="p-4">
                        <p className="text-sm text-muted-foreground">Low</p>
                        <p className="text-2xl font-bold text-blue-500">{scanResult.totalFindings.low}</p>
                        <p className="text-xs text-muted-foreground mt-1">Informational</p>
                      </CardContent>
                    </Card>
                  </div>
                </div>

                {/* Remediation Summary */}
                <div className="p-4 bg-muted/30 rounded-lg">
                  <h3 className="text-lg font-semibold mb-3">🩺 Remediation Summary</h3>
                  <ul className="space-y-2 text-sm">
                    <li>• Update outdated CMS and frameworks immediately</li>
                    <li>• Implement strict HTTPS enforcement with HSTS</li>
                    <li>• Disable public debug endpoints and directory listings</li>
                    <li>• Review and configure missing security headers</li>
                    <li>• Conduct periodic scans to maintain security posture</li>
                  </ul>
                </div>

                {/* Overall Verdict */}
                <Alert variant={scanResult.riskLevel === "Critical" || scanResult.riskLevel === "High" ? "destructive" : "default"}>
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    <strong>Overall Verdict:</strong> This domain has been assessed with a security score of {scanResult.securityScore}/100.
                    {scanResult.riskLevel === "Critical" || scanResult.riskLevel === "High" 
                      ? " Immediate patching and security hardening are strongly advised."
                      : " Continue monitoring and apply recommended security improvements."}
                  </AlertDescription>
                </Alert>
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  );
};

export default Demo;
