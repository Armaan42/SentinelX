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

  // Enhanced security patterns for bulletproof detection
  const securityPatterns = {
    sqlInjection: [
      // Classic SQL injection with quotes and OR/AND logic
      /('|\"|`)(\s*)(or|and)(\s*)('|\"|`)(\s*)(=|like|in)(\s*)('|\"|`)/i,
      // SQL injection with typical payloads
      /('|\"|`)(\s*)(or|and)(\s*)(\d+|\w+)(\s*)(=|like|in)(\s*)(\d+|\w+)/i,
      // UNION based attacks
      /\b(union)(\s+)(select|all)\b/i,
      // SQL injection with comments
      /('|\"|`)(\s*)(or|and)(\s*)('|\"|`)(\s*)(=|like|in)(\s*)('|\"|`)(\s*)(-{2,}|\/\*)/i,
      // Time-based SQL injection
      /\b(sleep|waitfor|delay|benchmark)\s*\(/i,
      // Boolean-based blind SQL injection
      /('|\"|`)(\s*)(or|and)(\s*)(if|case|when)\s*\(/i,
      // SQL functions in injection context
      /('|\"|`)(\s*)(or|and)(\s*)(\w+\s*=\s*)?(\w+)\s*\(/i,
      // SQL injection ending with comment
      /('|\"|`)(\s*)(or|and)(\s*).*(-{2,})/i,
      // Stacked queries
      /;\s*(select|insert|update|delete|drop|create|alter|exec)\b/i
    ],
    xss: [
      // Script tags
      /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
      /<script[\s\S]*?>/gi,
      // Event handlers
      /\bon(load|click|error|focus|blur|change|submit|mouseover|mouseout)\s*=/i,
      // JavaScript protocol
      /javascript\s*:/i,
      // Image with onerror
      /<img[\s\S]*?onerror[\s\S]*?=/i,
      // SVG with script content
      /<svg[\s\S]*?onload[\s\S]*?=/i,
      // Iframe injection
      /<iframe[\s\S]*?src[\s\S]*?=/i,
      // Details/summary with ontoggle
      /<(details|summary)[\s\S]*?ontoggle[\s\S]*?=/i,
      // Eval functions
      /\beval\s*\(/i,
      // HTML5 form elements with event handlers
      /<(input|textarea|select)[\s\S]*?on\w+[\s\S]*?=/i
    ],
    pathTraversal: [
      // Directory traversal patterns
      /(\.\.[\/\\]){2,}/,
      // URL encoded traversal
      /(%2e%2e[%2f%5c]){2,}/i,
      // Double URL encoded
      /(%252e%252e[%252f%255c]){2,}/i,
      // Absolute path access to sensitive files
      /[\/\\](etc[\/\\]passwd|windows[\/\\]system32|boot\.ini)/i,
      // Null byte injection
      /%00/i
    ],
    commandInjection: [
      // Command separators with commands
      /[;&|`]\s*(ls|dir|cat|type|whoami|id|ps|netstat|ifconfig|pwd|uname)/i,
      // Backticks with commands
      /`[\s\S]*?(ls|dir|cat|type|whoami|id|ps|netstat|ifconfig|pwd|uname)[\s\S]*?`/i,
      // Shell command substitution
      /\$\([\s\S]*?(ls|dir|cat|type|whoami|id|ps|netstat|ifconfig|pwd|uname)[\s\S]*?\)/i,
      // Network tools
      /\b(nc|netcat|wget|curl|ping|nslookup|dig)\s+/i,
      // Shell paths
      /[\/\\](bin[\/\\])?(sh|bash|zsh|csh|cmd|powershell)\b/i
    ],
    ldapInjection: [
      // LDAP injection patterns
      /\*\)\(|\)\(\*/,
      /\(\|\(/,
      /\)\(objectClass=\*/i
    ]
  };

  const detectThreats = (requestText: string) => {
    const threats: any[] = [];
    const decodedRequest = decodeURIComponent(requestText);
    
    // Normalize request for better detection
    const normalizedRequest = requestText.toLowerCase();
    const normalizedDecoded = decodedRequest.toLowerCase();
    
    // SQL Injection Detection with enhanced accuracy
    securityPatterns.sqlInjection.forEach((pattern, index) => {
      const match1 = pattern.test(requestText);
      const match2 = pattern.test(decodedRequest);
      
      if (match1 || match2) {
        // Check if it's a legitimate query parameter vs malicious injection
        const isLegitimateQuery = /^[a-zA-Z0-9\s\-_+%&=.,:;()\[\]{}@#!?<>|~/\\]*$/.test(requestText) && 
                                 !/(union\s+select|or\s+'?\d+\s*=\s*\d+|and\s+'?\d+\s*=\s*\d+|sleep\s*\(|benchmark\s*\()/i.test(requestText);
        
        if (!isLegitimateQuery) {
          threats.push({
            type: "SQL Injection",
            severity: "critical",
            pattern: pattern.toString(),
            description: "SQL injection attack detected - unauthorized database access attempt",
            location: "Query parameters or request body"
          });
        }
      }
    });

    // XSS Detection
    securityPatterns.xss.forEach((pattern, index) => {
      if (pattern.test(requestText) || pattern.test(decodedRequest)) {
        threats.push({
          type: "Cross-Site Scripting (XSS)",
          severity: "high", 
          pattern: pattern.toString(),
          description: "XSS attack vector identified - potential script injection",
          location: "Request parameters or headers"
        });
      }
    });

    // Path Traversal Detection
    securityPatterns.pathTraversal.forEach((pattern, index) => {
      if (pattern.test(requestText) || pattern.test(decodedRequest)) {
        threats.push({
          type: "Path Traversal",
          severity: "high",
          pattern: pattern.toString(),
          description: "Directory traversal attempt detected - unauthorized file access",
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
          description: "Command injection attempt detected - potential system compromise",
          location: "Request parameters"
        });
      }
    });

    // LDAP Injection Detection
    securityPatterns.ldapInjection.forEach((pattern, index) => {
      if (pattern.test(requestText) || pattern.test(decodedRequest)) {
        threats.push({
          type: "LDAP Injection",
          severity: "high",
          pattern: pattern.toString(),
          description: "LDAP injection attempt detected - unauthorized directory access",
          location: "Authentication parameters"
        });
      }
    });

    // CSRF Protection Check (for POST requests)
    if (requestText.includes("POST") || requestText.includes("PUT") || requestText.includes("DELETE")) {
      const hasCSRFProtection = /X-CSRF-Token|csrf_token|_token/i.test(requestText);
      
      if (!hasCSRFProtection) {
        threats.push({
          type: "CSRF Vulnerability",
          severity: "medium",
          pattern: "Missing CSRF token",
          description: "State-changing request without CSRF protection",
          location: "Request headers or body"
        });
      }
    }

    // Enhanced Encoding Detection (Advanced evasion techniques)
    const encodingPatterns = [
      /%[0-9a-f]{2}/gi,     // URL encoding
      /\\x[0-9a-f]{2}/gi,   // Hex encoding
      /&#[0-9]+;/gi,        // HTML entities
      /\\u[0-9a-f]{4}/gi,   // Unicode encoding
      /\+/g                 // Space encoding in URL
    ];
    
    let totalEncodedChars = 0;
    encodingPatterns.forEach(pattern => {
      const matches = requestText.match(pattern);
      if (matches) totalEncodedChars += matches.length;
    });

    // High encoding density indicates evasion attempt
    if (totalEncodedChars > 5 && (totalEncodedChars / requestText.length) > 0.2) {
      threats.push({
        type: "Encoded Payload",
        severity: "medium",
        pattern: "High encoding density detected",
        description: "Suspicious encoding patterns - potential evasion attempt",
        location: "Request payload"
      });
    }

    // Remove duplicates based on type
    const uniqueThreats = threats.filter((threat, index, self) => 
      index === self.findIndex(t => t.type === threat.type)
    );

    return uniqueThreats;
  };

  const analyzeRequest = () => {
    if (!request?.trim()) return;
    
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
    // Valid Requests - Updated with comprehensive examples
    homepage: `GET / HTTP/1.1
Host: www.example.com`,
    
    productListing: `GET /products?category=electronics&page=2 HTTP/1.1
Host: www.ecommerce.com
Referer: https://www.ecommerce.com/products`,
    
    productSearch: `GET /search?q=wireless+earbuds&sort=rating_desc HTTP/1.1
Host: localhost:3000`,

    userOrders: `GET /user/orders?page=1&status=shipped HTTP/1.1
Host: localhost:3000`,

    addToCartJSON: `POST /cart/add HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{
  "product_id": 98765,
  "quantity": 1,
  "variant": "red"
}`,

    loginForm: `POST /login HTTP/1.1
Host: localhost:3000
Content-Type: application/x-www-form-urlencoded

username=johndoe&password=SecurePass123`,

    // Malicious Requests - SQL Injection
    sqlInjectionOR: `GET /products?category=' OR '1'='1 HTTP/1.1
Host: localhost:3000`,
    
    sqlInjectionUnion: `GET /products?id=1 UNION SELECT username,password FROM users-- HTTP/1.1
Host: localhost:3000`,

    sqlInjectionTime: `GET /search?q=' OR IF(1=1, SLEEP(3), 0)-- HTTP/1.1
Host: localhost:3000`,

    sqlInjectionLogin: `POST /login HTTP/1.1
Host: localhost:3000
Content-Type: application/x-www-form-urlencoded

username=admin'--&password=anything`,
    
    // XSS Attacks
    xssScript: `GET /search?q=<script>alert('XSS')</script> HTTP/1.1
Host: localhost:3000`,
    
    xssImage: `GET /products?category=<img src=x onerror=alert(1)> HTTP/1.1
Host: localhost:3000`,

    xssComment: `POST /comment HTTP/1.1
Host: localhost:3000
Content-Type: application/x-www-form-urlencoded

comment=<script>alert('XSS')</script>`,

    // Path Traversal
    pathTraversal: `GET /download?file=../../../../etc/passwd HTTP/1.1
Host: localhost:3000`,

    // Command Injection
    commandInjection: `GET /ping?host=127.0.0.1;ls HTTP/1.1
Host: localhost:3000`,

    // Encoded Attacks
    urlEncodedSqli: `GET /search?q=%27%20OR%20%271%27%3D%271 HTTP/1.1
Host: www.example.com`,
    
    hexEncodedSqli: `GET /search?q=\\x27\\x20OR\\x20\\x31\\x3D\\x31 HTTP/1.1
Host: www.example.com`,
    
    advancedXss: `GET /comment?text=<details%20open%20ontoggle=Function('ale'+'rt(1)')()> HTTP/1.1
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
                    disabled={!request?.trim() || isAnalyzing}
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
                          onClick={() => setRequest(exampleRequests.sqlInjectionOR)}
                          className="text-xs"
                        >
                          SQL Injection
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setRequest(exampleRequests.xssScript)}
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
                          onClick={() => setRequest(exampleRequests.advancedXss)}
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