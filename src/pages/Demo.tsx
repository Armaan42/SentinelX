import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  ArrowLeft, 
  Scan,
  Eye,
  Brain,
  Zap
} from "lucide-react";
import { Link } from "react-router-dom";

const Demo = () => {
  const [request, setRequest] = useState("");
  const [analysis, setAnalysis] = useState<any>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Security patterns for detection
  const securityPatterns = {
    sqlInjection: [
      /('|"|`)(.*)(OR|AND)(.*)(=|LIKE)/i,
      /(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)/i,
      /('.*OR.*'=')/i,
      /(--|\*\/|\/\*)/,
      /(exec|execute|sp_|xp_)/i
    ],
    xss: [
      /<script[^>]*>.*?<\/script>/gi,
      /<iframe[^>]*>.*?<\/iframe>/gi,
      /javascript:/i,
      /on(click|load|error|focus|blur|change|submit)=/i,
      /<img[^>]*onerror/i,
      /eval\s*\(/i,
      /<svg[^>]*onload/i,
      /<details[^>]*ontoggle/i
    ],
    csrf: [
      /X-CSRF-Token/i,
      /csrf_token/i,
      /_token/i
    ],
    pathTraversal: [
      /\.\.\//,
      /\.\.\\/,
      /%2e%2e%2f/i,
      /%252e%252e%252f/i
    ],
    commandInjection: [
      /(\||&|;|`|\$\()/,
      /(nc|netcat|wget|curl)\s/i,
      /\/bin\/(sh|bash|zsh|csh)/i
    ]
  };

  const detectThreats = (requestText: string) => {
    const threats: any[] = [];
    const decodedRequest = decodeURIComponent(requestText);
    
    // SQL Injection Detection
    securityPatterns.sqlInjection.forEach((pattern, index) => {
      if (pattern.test(requestText) || pattern.test(decodedRequest)) {
        threats.push({
          type: "SQL Injection",
          severity: "high",
          pattern: pattern.toString(),
          description: "Potential SQL injection attempt detected",
          location: "Query parameters or request body"
        });
      }
    });

    // XSS Detection
    securityPatterns.xss.forEach((pattern, index) => {
      if (pattern.test(requestText) || pattern.test(decodedRequest)) {
        threats.push({
          type: "Cross-Site Scripting (XSS)",
          severity: "high", 
          pattern: pattern.toString(),
          description: "Potential XSS attack vector identified",
          location: "Request parameters or headers"
        });
      }
    });

    // CSRF Token Check
    const hasCsrfToken = securityPatterns.csrf.some(pattern => 
      pattern.test(requestText) || pattern.test(decodedRequest)
    );
    
    if (requestText.includes("POST") && !hasCsrfToken) {
      threats.push({
        type: "CSRF Vulnerability",
        severity: "medium",
        pattern: "Missing CSRF token",
        description: "POST request without CSRF protection",
        location: "Request headers or body"
      });
    }

    // Path Traversal Detection
    securityPatterns.pathTraversal.forEach((pattern, index) => {
      if (pattern.test(requestText) || pattern.test(decodedRequest)) {
        threats.push({
          type: "Path Traversal",
          severity: "high",
          pattern: pattern.toString(),
          description: "Directory traversal attempt detected",
          location: "URL path or parameters"
        });
      }
    });

    // Command Injection Detection
    securityPatterns.commandInjection.forEach((pattern, index) => {
      if (pattern.test(requestText) || pattern.test(decodedRequest)) {
        threats.push({
          type: "Command Injection",
          severity: "critical",
          pattern: pattern.toString(),
          description: "Potential command injection attempt",
          location: "Request parameters"
        });
      }
    });

    // Encoding Detection (ML-based anomaly detection simulation)
    const encodingPatterns = [/%[0-9a-f]{2}/gi, /\\x[0-9a-f]{2}/gi, /&#[0-9]+;/gi];
    const encodedMatches = encodingPatterns.some(pattern => {
      const matches = requestText.match(pattern);
      return matches && matches.length > 3; // High encoding density
    });

    if (encodedMatches) {
      threats.push({
        type: "Encoded Payload",
        severity: "medium",
        pattern: "Multiple encoding patterns",
        description: "Suspicious encoding detected - potential evasion attempt",
        location: "Request payload"
      });
    }

    return threats;
  };

  const analyzeRequest = () => {
    if (!request.trim()) return;
    
    setIsAnalyzing(true);
    
    // Simulate analysis delay
    setTimeout(() => {
      const threats = detectThreats(request);
      const riskScore = threats.length > 0 ? 
        Math.min(100, threats.length * 25 + (threats.filter(t => t.severity === "critical").length * 25)) : 0;
      
      setAnalysis({
        threats,
        riskScore,
        isClean: threats.length === 0,
        detectionMethod: threats.length > 0 ? "Signature & ML-based Detection" : "Clean Request"
      });
      setIsAnalyzing(false);
    }, 1500);
  };

  const exampleRequests = {
    // Valid Requests
    homepage: `GET / HTTP/1.1
Host: www.example.com`,
    
    productListing: `GET /products?category=electronics&page=2 HTTP/1.1
Host: www.ecommerce.com
Referer: https://www.ecommerce.com/products`,
    
    singleProduct: `GET /product/12345 HTTP/1.1
Host: www.ecommerce.com
Referer: https://www.ecommerce.com/products?category=electronics&page=2`,
    
    addToCart: `POST /cart/add HTTP/1.1
Host: www.ecommerce.com
Content-Type: application/json
Content-Length: 45

{"productId": "12345", "quantity": 1}`,

    // Signature-Based Detection (Malicious)
    sqlInjectionSearch: `GET /search?q=' OR '1'='1'; DROP TABLE users;-- HTTP/1.1
Host: www.example.com`,
    
    xssComment: `GET /comment?text=<script>alert('XSS')</script> HTTP/1.1
Host: www.example.com`,
    
    xssEval: `GET /comment?text=<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script> HTTP/1.1
Host: www.example.com`,
    
    sqlUnion: `GET /search?q=1' UNION SELECT username,password FROM users-- HTTP/1.1
Host: www.example.com`,

    // ML-based Anomaly Detection (Encoded)
    urlEncodedSqli: `GET /search?q=%27%20OR%20%271%27%3D%271 HTTP/1.1
Host: www.example.com`,
    
    hexEncodedSqli: `GET /search?q=\\x27\\x20OR\\x20\\x31\\x3D\\x31 HTTP/1.1
Host: www.example.com`,
    
    obscureHtml: `GET /comment?text=<details%20open%20ontoggle=Function('ale'+'rt(1)')()> HTTP/1.1
Host: www.example.com`,
    
    encodedXss: `GET /comment?text=%3Cscript%3Ealert%28%27XSS%27%29%3C%2Fscript%3E HTTP/1.1
Host: www.example.com`
  };

  return (
    <div className="min-h-screen bg-gradient-dark">
      {/* Navigation */}
      <nav className="fixed top-0 w-full bg-background/80 backdrop-blur-md border-b border-border z-50">
        <div className="container mx-auto px-4 h-16 flex items-center justify-between">
          <Link to="/" className="flex items-center space-x-2">
            <ArrowLeft className="h-5 w-5 text-muted-foreground" />
            <Shield className="h-8 w-8 text-primary" />
            <span className="text-xl font-bold gradient-text">SentinelX</span>
          </Link>
          
          <Badge variant="secondary" className="glow-cyber">
            <Scan className="h-4 w-4 mr-2" />
            Security Demo
          </Badge>
        </div>
      </nav>

      {/* Main Content */}
      <div className="pt-20 pb-12 px-4">
        <div className="container mx-auto max-w-6xl">
          <div className="text-center mb-12">
            <h1 className="text-4xl md:text-5xl font-bold mb-6">
              <span className="gradient-text">Security Request</span> Analyzer
            </h1>
            <p className="text-xl text-muted-foreground max-w-3xl mx-auto">
              Test HTTP requests for security vulnerabilities including SQL injection, XSS, CSRF, and other threats using both signature-based and ML-powered detection.
            </p>
          </div>

          <div className="grid lg:grid-cols-2 gap-8">
            {/* Input Section */}
            <Card className="bg-card/50 border-border/50">
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Eye className="h-5 w-5 mr-2 text-primary" />
                  HTTP Request Input
                </CardTitle>
                <CardDescription>
                  Paste your HTTP request below to analyze for security threats
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <Textarea
                  placeholder="Paste your HTTP request here..."
                  value={request}
                  onChange={(e) => setRequest(e.target.value)}
                  className="min-h-[300px] font-mono text-sm"
                />
                
                <div className="flex gap-2">
                  <Button 
                    onClick={analyzeRequest}
                    disabled={!request.trim() || isAnalyzing}
                    className="btn-hero"
                  >
                    {isAnalyzing ? (
                      <>
                        <Zap className="h-4 w-4 mr-2 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Scan className="h-4 w-4 mr-2" />
                        Analyze Request
                      </>
                    )}
                  </Button>
                </div>

                {/* Example Requests */}
                <div className="space-y-2">
                  <p className="text-sm font-medium">Quick Examples:</p>
                  <div className="grid grid-cols-2 gap-2">
                    {/* Valid Requests */}
                    <div className="space-y-1">
                      <p className="text-xs text-muted-foreground font-medium">✅ Valid Requests</p>
                      <div className="flex flex-col gap-1">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setRequest(exampleRequests.homepage)}
                          className="text-xs"
                        >
                          Homepage
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setRequest(exampleRequests.productListing)}
                          className="text-xs"
                        >
                          Product Listing
                        </Button>
                      </div>
                    </div>

                    {/* Malicious Requests */}
                    <div className="space-y-1">
                      <p className="text-xs text-muted-foreground font-medium">❌ Malicious Requests</p>
                      <div className="flex flex-col gap-1">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setRequest(exampleRequests.sqlInjectionSearch)}
                          className="text-xs"
                        >
                          SQL Injection
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setRequest(exampleRequests.xssComment)}
                          className="text-xs"
                        >
                          XSS Attack
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setRequest(exampleRequests.urlEncodedSqli)}
                          className="text-xs"
                        >
                          Encoded Attack
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setRequest(exampleRequests.obscureHtml)}
                          className="text-xs"
                        >
                          Advanced XSS
                        </Button>
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Analysis Results */}
            <Card className="bg-card/50 border-border/50">
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Brain className="h-5 w-5 mr-2 text-secondary" />
                  Security Analysis
                </CardTitle>
                <CardDescription>
                  Real-time threat detection and risk assessment
                </CardDescription>
              </CardHeader>
              <CardContent>
                {!analysis ? (
                  <div className="text-center py-12 text-muted-foreground">
                    <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>Submit a request to see security analysis</p>
                  </div>
                ) : (
                  <div className="space-y-6">
                    {/* Risk Score */}
                    <div className="flex items-center justify-between p-4 bg-muted/50 rounded-lg">
                      <div>
                        <p className="text-sm text-muted-foreground">Risk Score</p>
                        <p className="text-2xl font-bold">
                          <span className={analysis.riskScore === 0 ? "text-secondary" : 
                                         analysis.riskScore < 50 ? "text-yellow-500" : "text-destructive"}>
                            {analysis.riskScore}/100
                          </span>
                        </p>
                      </div>
                      <div className="text-right">
                        <Badge variant={analysis.isClean ? "secondary" : "destructive"}>
                          {analysis.isClean ? "Clean" : "Threats Detected"}
                        </Badge>
                        <p className="text-xs text-muted-foreground mt-1">
                          {analysis.detectionMethod}
                        </p>
                      </div>
                    </div>

                    {/* Threats List */}
                    {analysis.threats.length === 0 ? (
                      <Alert>
                        <CheckCircle className="h-4 w-4" />
                        <AlertDescription>
                          No security threats detected. This request appears to be safe.
                        </AlertDescription>
                      </Alert>
                    ) : (
                      <div className="space-y-3">
                        <p className="font-medium text-destructive">
                          {analysis.threats.length} threat(s) detected:
                        </p>
                        {analysis.threats.map((threat, index) => (
                          <Alert key={index} variant="destructive">
                            <AlertTriangle className="h-4 w-4" />
                            <AlertDescription>
                              <div className="space-y-1">
                                <div className="flex items-center justify-between">
                                  <span className="font-medium">{threat.type}</span>
                                  <Badge variant={
                                    threat.severity === "critical" ? "destructive" :
                                    threat.severity === "high" ? "destructive" :
                                    threat.severity === "medium" ? "secondary" : "outline"
                                  }>
                                    {threat.severity.toUpperCase()}
                                  </Badge>
                                </div>
                                <p className="text-sm">{threat.description}</p>
                                <p className="text-xs text-muted-foreground">
                                  Location: {threat.location}
                                </p>
                              </div>
                            </AlertDescription>
                          </Alert>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Detection Methods */}
          <div className="mt-12 grid md:grid-cols-3 gap-6">
            <Card className="bg-gradient-card border-border">
              <CardHeader className="text-center">
                <Shield className="h-8 w-8 text-primary mx-auto mb-2" />
                <CardTitle className="text-lg">Signature Detection</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground text-center">
                  Pattern-based detection for known attack vectors like SQL injection, XSS, and command injection
                </p>
              </CardContent>
            </Card>

            <Card className="bg-gradient-card border-border">
              <CardHeader className="text-center">
                <Brain className="h-8 w-8 text-secondary mx-auto mb-2" />
                <CardTitle className="text-lg">ML-Based Detection</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground text-center">
                  Advanced anomaly detection for encoded payloads and evasion techniques
                </p>
              </CardContent>
            </Card>

            <Card className="bg-gradient-card border-border">
              <CardHeader className="text-center">
                <Zap className="h-8 w-8 text-accent mx-auto mb-2" />
                <CardTitle className="text-lg">Real-Time Analysis</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-sm text-muted-foreground text-center">
                  Instant threat assessment with detailed risk scoring and remediation guidance
                </p>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Demo;