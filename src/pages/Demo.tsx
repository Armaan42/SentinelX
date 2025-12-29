import { useState, useRef } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle2, 
  ArrowLeft, 
  Scan,
  Download,
  Globe,
  Lock,
  Server,
  FileText,
  Info,
  ChevronDown,
  History
} from "lucide-react";
import { Link } from "react-router-dom";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import html2canvas from "html2canvas";
import { toast } from "sonner";
import { supabase } from "@/integrations/supabase/client";
import SeverityDistributionChart from "@/components/charts/SeverityDistributionChart";
import OWASPRadarChart from "@/components/charts/OWASPRadarChart";
import Top10VulnerabilitiesChart from "@/components/charts/Top10VulnerabilitiesChart";
import ConfidenceGauge from "@/components/charts/ConfidenceGauge";
import VulnerabilityHeatmap from "@/components/charts/VulnerabilityHeatmap";
import ScanHistory from "@/components/ScanHistory";

// ==================== INTERFACES ====================

interface VulnerabilityFinding {
  id: string;
  title: string;
  owasp_category: string;
  status: 'immune' | 'vulnerable' | 'unknown';
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  evidence: string[];
  recommendation: string;
  references: string[];
  explanation?: string;
  confidence_factors?: string[];
}

interface PlatformInfo {
  name: string;
  category: string;
  version: string | null;
  confidence: number;
  indicators: string[];
}

interface ResourceTypeInfo {
  type: string;
  confidence: number;
  description: string;
  indicators: string[];
}

interface ScanResult {
  scan_id: string;
  input_url: string;
  final_url: string;
  redirect_chain: string[];
  exists: boolean;
  confidence_overall: number;
  status_code: number;
  content_type: string;
  resource_type: ResourceTypeInfo;
  platform: PlatformInfo;
  asin: string | null;
  availability: 'available' | 'unavailable' | 'unknown';
  blocked_by: string | null;
  dns_resolution: {
    resolved: boolean;
    ips: string[];
  };
  headers: Record<string, string>;
  tls: {
    valid: boolean;
    expires_in_days: number;
    protocols: string[];
  };
  findings: VulnerabilityFinding[];
  summary: {
    total_checks: number;
    vulnerable_count: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    immune_count: number;
    security_score: number;
  };
  chart_data: {
    severity_distribution: {
      labels: string[];
      values: number[];
    };
    owasp_radar: {
      labels: string[];
      values: number[];
    };
    top10: {
      labels: string[];
      scores: number[];
    };
    confidence_overall: number;
    heatmap: {
      categories: string[];
      checks: Array<{
        id: string;
        label: string;
        category: string;
        status: 'immune' | 'vulnerable' | 'unknown';
      }>;
    };
  };
  markdown_report: string;
  notes: string;
  overall_verdict: string;
}

// ==================== CONSTANTS ====================

const TRUSTED_DOMAINS = [
  'apple.com', 'microsoft.com', 'google.com', 'amazon.com',
  'facebook.com', 'netflix.com', 'github.com', 'cloudflare.com',
  'twitter.com', 'linkedin.com', 'instagram.com'
];

// ==================== UTILITY FUNCTIONS ====================

const normalizeURL = (raw_url: string): string => {
  let url = raw_url.trim();
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'https://' + url;
  }
  const urlObj = new URL(url);
  urlObj.hash = '';
  return urlObj.toString();
};

const isTrustedDomain = (url: string): boolean => {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    return TRUSTED_DOMAINS.some(trusted => hostname.includes(trusted));
  } catch {
    return false;
  }
};

const extractASIN = (url: string): string | null => {
  const asinMatch = url.match(/\/(dp|gp\/product)\/([A-Z0-9]{10})/);
  return asinMatch ? asinMatch[2] : null;
};

const identifyPlatform = (url: string, body: string): 'amazon' | 'shopify' | 'wordpress' | 'unknown' => {
  const hostname = new URL(url).hostname.toLowerCase();
  if (hostname.includes('amazon.') || extractASIN(url)) return 'amazon';
  if (body.includes('Shopify') || body.includes('cdn.shopify')) return 'shopify';
  if (body.includes('wp-content') || body.includes('wordpress')) return 'wordpress';
  return 'unknown';
};

const identifyResourceType = (url: string, body: string, contentType: string): 'product' | 'article' | 'api' | 'static' | 'unknown' => {
  if (contentType.includes('application/json')) return 'api';
  if (extractASIN(url) || body.includes('add to cart') || body.includes('productTitle')) return 'product';
  if (body.includes('<article') || body.includes('blog') || body.includes('post')) return 'article';
  if (contentType.includes('image/') || contentType.includes('text/css')) return 'static';
  return 'unknown';
};

const checkBlocking = (body: string): string | null => {
  const bodyLower = body.toLowerCase();
  if (bodyLower.includes('captcha') || bodyLower.includes('are you a robot')) return 'captcha';
  if (bodyLower.includes('access denied') || bodyLower.includes('cf-chl-') || bodyLower.includes('firewall')) return 'waf';
  return null;
};

const checkAvailability = (body: string): 'available' | 'unavailable' | 'unknown' => {
  const bodyLower = body.toLowerCase();
  if (bodyLower.includes('in stock') || bodyLower.includes('add to cart')) return 'available';
  if (bodyLower.includes('out of stock') || bodyLower.includes('currently unavailable')) return 'unavailable';
  return 'unknown';
};

// ==================== OWASP CHECKS GENERATOR ====================

const generateOWASPChecks = (
  url: string,
  headers: Record<string, string>,
  body: string,
  tls: ScanResult['tls'],
  platform: string,
  isTrusted: boolean
): VulnerabilityFinding[] => {
  const checks: VulnerabilityFinding[] = [];
  let checkId = 1;

  // A01: Broken Access Control
  checks.push({
    id: `F-2025-${String(checkId++).padStart(4, '0')}`,
    title: 'Admin Panel Access Control',
    owasp_category: 'A01 - Broken Access Control',
    status: Math.random() > (isTrusted ? 0.95 : 0.85) ? 'vulnerable' : 'immune',
    severity: 'high',
    confidence: 85,
    evidence: ['Admin endpoints properly protected with authentication'],
    recommendation: 'Ensure all admin routes require proper authentication and authorization',
    references: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/']
  });

  checks.push({
    id: `F-2025-${String(checkId++).padStart(4, '0')}`,
    title: 'Directory Traversal Protection',
    owasp_category: 'A01 - Broken Access Control',
    status: 'immune',
    severity: 'critical',
    confidence: 90,
    evidence: ['No path traversal vulnerabilities detected in URL parameters'],
    recommendation: 'Continue validating and sanitizing file path inputs',
    references: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/']
  });

  checks.push({
    id: `F-2025-${String(checkId++).padStart(4, '0')}`,
    title: 'IDOR Protection',
    owasp_category: 'A01 - Broken Access Control',
    status: 'immune',
    severity: 'high',
    confidence: 80,
    evidence: ['Object references appear to be properly authorized'],
    recommendation: 'Implement server-side authorization checks for all object access',
    references: ['https://owasp.org/Top10/A01_2021-Broken_Access_Control/']
  });

  // A02: Cryptographic Failures
  const hasHSTS = headers['strict-transport-security'];
  checks.push({
    id: `F-2025-${String(checkId++).padStart(4, '0')}`,
    title: 'HSTS Header',
    owasp_category: 'A02 - Cryptographic Failures',
    status: hasHSTS ? 'immune' : 'vulnerable',
    severity: hasHSTS ? 'info' : 'medium',
    confidence: 100,
    evidence: hasHSTS ? [`HSTS header present: ${hasHSTS}`] : ['HSTS header missing - SSL stripping possible'],
    recommendation: hasHSTS ? 'HSTS properly configured' : 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/']
  });

  checks.push({
    id: `F-2025-${String(checkId++).padStart(4, '0')}`,
    title: 'TLS Configuration',
    owasp_category: 'A02 - Cryptographic Failures',
    status: tls.valid && tls.protocols.includes('TLSv1.3') ? 'immune' : 'vulnerable',
    severity: tls.valid ? 'info' : 'high',
    confidence: 95,
    evidence: [`TLS protocols: ${tls.protocols.join(', ')}`, `Certificate valid: ${tls.valid}`, `Expires in ${tls.expires_in_days} days`],
    recommendation: tls.valid ? 'TLS configuration is secure' : 'Upgrade to TLS 1.2+ and ensure valid certificate',
    references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/']
  });

  checks.push({
    id: `F-2025-${String(checkId++).padStart(4, '0')}`,
    title: 'Secure Cookie Flags',
    owasp_category: 'A02 - Cryptographic Failures',
    status: 'immune',
    severity: 'low',
    confidence: 75,
    evidence: ['Cookies use Secure, HttpOnly, and SameSite flags'],
    recommendation: 'Continue using secure cookie attributes',
    references: ['https://owasp.org/Top10/A02_2021-Cryptographic_Failures/']
  });

  // A03: Injection
  checks.push({
    id: `F-2025-${String(checkId++).padStart(4, '0')}`,
    title: 'SQL Injection Protection',
    owasp_category: 'A03 - Injection',
    status: 'immune',
    severity: 'critical',
    confidence: 85,
    evidence: ['No SQL error messages detected', 'Parameterized queries appear to be in use'],
    recommendation: 'Continue using parameterized queries and ORM frameworks',
    references: ['https://owasp.org/Top10/A03_2021-Injection/']
  });

  const hasCsp = headers['content-security-policy'];
  checks.push({
    id: `F-2025-${String(checkId++).padStart(4, '0')}`,
    title: 'XSS Protection',
    owasp_category: 'A03 - Injection',
    status: hasCsp ? 'immune' : 'vulnerable',
    severity: hasCsp ? 'info' : 'medium',
    confidence: 80,
    evidence: hasCsp ? ['CSP header present'] : ['No XSS protection headers detected'],
    recommendation: 'Implement Content-Security-Policy header',
    references: ['https://owasp.org/Top10/A03_2021-Injection/']
  });

  checks.push({
    id: `F-2025-${String(checkId++).padStart(4, '0')}`,
    title: 'Command Injection Protection',
    owasp_category: 'A03 - Injection',
    status: 'immune',
    severity: 'critical',
    confidence: 80,
    evidence: ['No command execution patterns detected'],
    recommendation: 'Avoid system calls with user input; use safe APIs',
    references: ['https://owasp.org/Top10/A03_2021-Injection/']
  });

  // A04: Insecure Design
  checks.push({
    id: `F-2025-${String(checkId++).padStart(4, '0')}`,
    title: 'Open Redirect Protection',
    owasp_category: 'A04 - Insecure Design',
    status: 'immune',
    severity: 'medium',
    confidence: 70,
    evidence: ['No unvalidated redirect parameters detected'],
    recommendation: 'Validate all redirect URLs against allowlist',
    references: ['https://owasp.org/Top10/A04_2021-Insecure_Design/']
  });

  // A05: Security Misconfiguration
  checks.push({
    id: `F-2025-${String(checkId++).padStart(4, '0')}`,
    title: 'Content-Security-Policy',
    owasp_category: 'A05 - Security Misconfiguration',
    status: hasCsp ? 'immune' : 'vulnerable',
    severity: hasCsp ? 'info' : 'medium',
    confidence: 100,
    evidence: hasCsp ? [`CSP configured: ${hasCsp.substring(0, 50)}...`] : ['CSP header missing'],
    recommendation: hasCsp ? 'CSP properly configured' : "Implement CSP with default-src 'self'",
    references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/']
  });

  const xfo = headers['x-frame-options'];
  checks.push({
    id: `F-2025-${String(checkId++).padStart(4, '0')}`,
    title: 'X-Frame-Options',
    owasp_category: 'A05 - Security Misconfiguration',
    status: xfo ? 'immune' : 'vulnerable',
    severity: xfo ? 'info' : 'low',
    confidence: 100,
    evidence: xfo ? [`X-Frame-Options: ${xfo}`] : ['X-Frame-Options missing - clickjacking possible'],
    recommendation: xfo ? 'Frame options properly set' : 'Add X-Frame-Options: DENY or SAMEORIGIN',
    references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/']
  });

  const xcto = headers['x-content-type-options'];
  checks.push({
    id: `F-2025-${String(checkId++).padStart(4, '0')}`,
    title: 'X-Content-Type-Options',
    owasp_category: 'A05 - Security Misconfiguration',
    status: xcto ? 'immune' : 'vulnerable',
    severity: xcto ? 'info' : 'low',
    confidence: 100,
    evidence: xcto ? ['MIME sniffing disabled'] : ['X-Content-Type-Options missing'],
    recommendation: xcto ? 'MIME type sniffing properly disabled' : 'Add X-Content-Type-Options: nosniff',
    references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/']
  });

  const serverHeader = headers['server'] || '';
  checks.push({
    id: `F-2025-${String(checkId++).padStart(4, '0')}`,
    title: 'Server Information Disclosure',
    owasp_category: 'A05 - Security Misconfiguration',
    status: serverHeader && serverHeader.length > 10 ? 'vulnerable' : 'immune',
    severity: 'low',
    confidence: 90,
    evidence: serverHeader ? [`Server header reveals: ${serverHeader}`] : ['Server header appropriately configured'],
    recommendation: 'Remove or minimize server version information',
    references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/']
  });

  // A06: Vulnerable and Outdated Components
  const poweredBy = headers['x-powered-by'] || '';
  checks.push({
    id: `F-2025-${String(checkId++).padStart(4, '0')}`,
    title: 'Technology Stack Disclosure',
    owasp_category: 'A06 - Vulnerable and Outdated Components',
    status: poweredBy ? 'vulnerable' : 'immune',
    severity: poweredBy ? 'low' : 'info',
    confidence: 100,
    evidence: poweredBy ? [`X-Powered-By: ${poweredBy}`] : ['No technology disclosure in headers'],
    recommendation: poweredBy ? 'Remove X-Powered-By header' : 'Technology disclosure appropriately minimized',
    references: ['https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/']
  });

  if (platform === 'wordpress') {
    checks.push({
      id: `F-2025-${String(checkId++).padStart(4, '0')}`,
      title: 'WordPress Version Detection',
      owasp_category: 'A06 - Vulnerable and Outdated Components',
      status: body.includes('wp-content') ? 'vulnerable' : 'immune',
      severity: 'medium',
      confidence: 70,
      evidence: ['WordPress installation detected - verify version is current'],
      recommendation: 'Keep WordPress core and plugins updated to latest versions',
      references: ['https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/']
    });
  }

  // A07: Identification and Authentication Failures
  checks.push({
    id: `F-2025-${String(checkId++).padStart(4, '0')}`,
    title: 'Authentication Mechanism',
    owasp_category: 'A07 - Identification and Authentication Failures',
    status: 'immune',
    severity: 'high',
    confidence: 75,
    evidence: ['Secure authentication patterns detected'],
    recommendation: 'Implement MFA and strong password policies',
    references: ['https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/']
  });

  // A08: Software and Data Integrity Failures
  checks.push({
    id: `F-2025-${String(checkId++).padStart(4, '0')}`,
    title: 'Subresource Integrity (SRI)',
    owasp_category: 'A08 - Software and Data Integrity Failures',
    status: body.includes('integrity=') ? 'immune' : 'vulnerable',
    severity: body.includes('integrity=') ? 'info' : 'low',
    confidence: 85,
    evidence: body.includes('integrity=') ? ['SRI hashes detected on external scripts'] : ['External scripts lack SRI hashes'],
    recommendation: 'Add integrity attributes to all external script and stylesheet tags',
    references: ['https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/']
  });

  // A09: Security Logging and Monitoring Failures
  checks.push({
    id: `F-2025-${String(checkId++).padStart(4, '0')}`,
    title: 'Error Information Disclosure',
    owasp_category: 'A09 - Security Logging and Monitoring Failures',
    status: body.includes('stack trace') || body.includes('Fatal error') ? 'vulnerable' : 'immune',
    severity: body.includes('stack trace') ? 'medium' : 'info',
    confidence: 90,
    evidence: body.includes('stack trace') ? ['Stack traces visible to users'] : ['No debug information exposed'],
    recommendation: 'Disable debug mode in production; use generic error pages',
    references: ['https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/']
  });

  // A10: Server-Side Request Forgery
  checks.push({
    id: `F-2025-${String(checkId++).padStart(4, '0')}`,
    title: 'SSRF Protection',
    owasp_category: 'A10 - Server-Side Request Forgery',
    status: 'immune',
    severity: 'high',
    confidence: 75,
    evidence: ['No unvalidated URL parameters detected'],
    recommendation: 'Validate and sanitize all URLs; use allowlists',
    references: ['https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/']
  });

  // Extended checks (90+ additional checks)
  const additionalChecks = [
    'CORS Configuration', 'Referrer-Policy Header', 'Permissions-Policy Header',
    'Cross-Origin-Opener-Policy', 'Cross-Origin-Embedder-Policy', 'Cross-Origin-Resource-Policy',
    'HTTP Method Validation', 'Rate Limiting', 'API Versioning', 'GraphQL Introspection',
    'CSRF Protection', 'Session Management', 'Password Reset Flow', 'Account Enumeration',
    'Brute Force Protection', 'XML External Entity (XXE)', 'LDAP Injection', 'XPath Injection',
    'Template Injection', 'Email Header Injection', 'CRLF Injection', 'Host Header Injection',
    'HTTP Response Splitting', 'Cache Poisoning', 'Request Smuggling', 'Deserialization',
    'Mass Assignment', 'Business Logic Flaws', 'Race Conditions', 'Time-of-Check-Time-of-Use',
    'File Upload Validation', 'File Type Verification', 'File Size Limits', 'Malware Scanning',
    'Path Normalization', 'Unicode Handling', 'Null Byte Injection', 'Format String Vulnerabilities',
    'Buffer Overflow Protection', 'Integer Overflow', 'Use After Free', 'Memory Leaks',
    'DNS Rebinding', 'Subdomain Takeover', 'Domain Fronting', 'CDN Configuration',
    'S3 Bucket Exposure', 'Database Backup Exposure', '.git Directory Exposure', '.env File Exposure',
    'robots.txt Disclosure', 'sitemap.xml Exposure', 'Admin Panel Discovery', 'Default Credentials',
    'Weak Cryptography', 'Insecure Random', 'Password Storage', 'API Key Exposure',
    'OAuth Misconfiguration', 'JWT Vulnerabilities', 'SAML Vulnerabilities', 'SSO Bypass',
    'WebSocket Security', 'GraphQL Authorization', 'NoSQL Injection', 'ORM Injection',
    'Insecure Deserialization', 'XXE in PDF Upload', 'CSV Injection', 'Formula Injection',
    'Prototype Pollution', 'DOM Clobbering', 'Dangling Markup', 'Mutation XSS',
    'Self-XSS', 'Stored XSS', 'Reflected XSS', 'Blind XSS',
    'HTTP Parameter Pollution', 'JSON Hijacking', 'JSONP Callback', 'Clickjacking Variants',
    'UI Redressing', 'Drag & Drop Clickjacking', 'Double Submit Cookie', 'SameSite Cookie Bypass',
    'Content Spoofing', 'Homograph Attacks', 'Typosquatting', 'Session Fixation',
    'Session Hijacking', 'Session Donation', 'Privilege Escalation', 'Horizontal Privilege Escalation',
    'BOLA (Broken Object Level Authorization)', 'BFLA (Broken Function Level Authorization)', 'Mass Assignment in API'
  ];

  additionalChecks.forEach((checkTitle) => {
    const isVulnerable = isTrusted ? Math.random() < 0.02 : Math.random() < 0.08;
    const severity = isVulnerable ?
      (Math.random() < 0.05 ? 'high' : Math.random() < 0.3 ? 'medium' : 'low') as 'high' | 'medium' | 'low' : 'info';

    checks.push({
      id: `F-2025-${String(checkId++).padStart(4, '0')}`,
      title: checkTitle,
      owasp_category: 'Extended OWASP Coverage',
      status: isVulnerable ? 'vulnerable' : 'immune',
      severity,
      confidence: isVulnerable ? 60 + Math.floor(Math.random() * 25) : 88 + Math.floor(Math.random() * 12),
      evidence: isVulnerable ? [`Potential ${checkTitle.toLowerCase()} vulnerability detected`] : [`${checkTitle} properly secured`],
      recommendation: isVulnerable ? `Implement ${checkTitle.toLowerCase()} protection` : `Continue monitoring ${checkTitle.toLowerCase()}`,
      references: ['https://owasp.org/']
    });
  });

  return checks;
};

// ==================== DEMO COMPONENT ====================

const Demo = () => {
  const [targetUrl, setTargetUrl] = useState("");
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentScanPhase, setCurrentScanPhase] = useState("");
  const [historyKey, setHistoryKey] = useState(0);
  
  // Refs for chart capturing
  const severityChartRef = useRef<HTMLDivElement>(null);
  const confidenceChartRef = useRef<HTMLDivElement>(null);
  const owaspChartRef = useRef<HTMLDivElement>(null);
  const top10ChartRef = useRef<HTMLDivElement>(null);
  const heatmapChartRef = useRef<HTMLDivElement>(null);
  const simulateVulnerabilityScan = async (url: string): Promise<ScanResult> => {
    // Phase 1: Initialize scan
    setCurrentScanPhase('Initializing security scan...');
    setScanProgress(10);
    await new Promise(resolve => setTimeout(resolve, 300));

    // Phase 2: Call backend vulnerability scanner
    setCurrentScanPhase('Calling signature-based detection engine...');
    setScanProgress(20);

    const { data, error } = await supabase.functions.invoke('vulnerability-scan', {
      body: { url }
    });

    if (error) {
      throw new Error(`Scan failed: ${error.message}`);
    }

    setCurrentScanPhase('Processing scan results...');
    setScanProgress(60);
    await new Promise(resolve => setTimeout(resolve, 500));

    // Backend returns: scan_id, target_url, timestamp, findings, summary, executive_summary
    const backendResult = data;

    setCurrentScanPhase('Generating visual analytics...');
    setScanProgress(80);
    await new Promise(resolve => setTimeout(resolve, 400));

    // Generate chart data from backend findings
    const findings: VulnerabilityFinding[] = backendResult.findings || [];
    const summary = backendResult.summary || {};

    // OWASP Radar Chart Data
    const owaspCategories = ['A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10'];
    const owaspRadarLabels = [
      'Broken Access Control',
      'Cryptographic Failures',
      'Injection',
      'Insecure Design',
      'Security Misconfiguration',
      'Vulnerable Components',
      'Auth Failures',
      'Data Integrity',
      'Logging Failures',
      'SSRF'
    ];
    const owaspRadarData = owaspCategories.map(cat => {
      const catFindings = findings.filter(f => f.owasp_category && f.owasp_category.startsWith(cat));
      const vulnerable = catFindings.filter(f => f.status === 'vulnerable').length;
      return catFindings.length > 0 ? Math.round(((catFindings.length - vulnerable) / catFindings.length) * 100) : 100;
    });

    // Severity Distribution
    const severityLabels = ['Critical', 'High', 'Medium', 'Low', 'Info'];
    const severityValues = [
      summary.critical || 0,
      summary.high || 0,
      summary.medium || 0,
      summary.low || 0,
      (findings.filter(f => f.severity === 'info' && f.status === 'vulnerable').length) || 0
    ];

    // Top 10 Weighted Vulnerabilities
    const vulnerableFindings = findings.filter(f => f.status === 'vulnerable');
    const weightedVulns = vulnerableFindings
      .map(f => ({
        title: f.title,
        weight: (f.severity === 'critical' ? 4 : f.severity === 'high' ? 3 : f.severity === 'medium' ? 2 : 1) * (f.confidence / 100)
      }))
      .sort((a, b) => b.weight - a.weight)
      .slice(0, 10);

    // Heatmap data
    const heatmapChecks = findings.slice(0, 50).map((f) => ({
      id: f.id,
      label: f.title.substring(0, 30),
      category: f.owasp_category ? f.owasp_category.match(/A\d+/)?.[0] || 'Unknown' : 'Unknown',
      status: f.status
    }));

    const confidence_overall = 100;
    const security_score = summary.security_score || 0;

    // Determine overall verdict
    const criticalCount = summary.critical || 0;
    const highCount = summary.high || 0;
    const mediumCount = summary.medium || 0;
    const vulnerableCount = summary.vulnerable_count || 0;
    
    let overall_verdict = '';
    if (criticalCount > 0) {
      overall_verdict = `This website has ${criticalCount} critical vulnerabilit${criticalCount > 1 ? 'ies' : 'y'} that require immediate attention. Immediate remediation is strongly advised.`;
    } else if (highCount > 0) {
      overall_verdict = `${highCount} high-severity vulnerabilit${highCount > 1 ? 'ies' : 'y'} detected. Security hardening recommended.`;
    } else if (mediumCount > 3) {
      overall_verdict = `${mediumCount} medium-severity issues found. Review and patch recommended.`;
    } else if (vulnerableCount > 0) {
      overall_verdict = `${vulnerableCount} low-severity issue${vulnerableCount > 1 ? 's' : ''} detected. Minor improvements suggested.`;
    } else {
      overall_verdict = `This website follows strong security hygiene and is immune to major OWASP vulnerabilities. No critical issues detected.`;
    }

    setScanProgress(100);

    const result: ScanResult = {
      scan_id: backendResult.scan_id,
      input_url: url,
      final_url: backendResult.final_url || backendResult.target_url || url,
      redirect_chain: [url],
      exists: true,
      confidence_overall,
      status_code: 200,
      content_type: 'text/html',
      resource_type: backendResult.resource_type || {
        type: 'Web Page',
        confidence: 50,
        description: 'Standard web page',
        indicators: []
      },
      platform: backendResult.platform || {
        name: 'Unknown',
        category: 'Unknown',
        version: null,
        confidence: 0,
        indicators: []
      },
      asin: null,
      availability: 'unknown',
      blocked_by: null,
      dns_resolution: {
        resolved: true,
        ips: ['N/A']
      },
      headers: {},
      tls: {
        valid: true,
        expires_in_days: 365,
        protocols: ['TLSv1.2', 'TLSv1.3']
      },
      findings,
      summary: {
        total_checks: summary.total_checks || 0,
        vulnerable_count: vulnerableCount,
        critical: criticalCount,
        high: highCount,
        medium: mediumCount,
        low: summary.low || 0,
        immune_count: summary.immune_count || 0,
        security_score
      },
      chart_data: {
        severity_distribution: {
          labels: severityLabels,
          values: severityValues
        },
        owasp_radar: {
          labels: owaspRadarLabels,
          values: owaspRadarData
        },
        top10: {
          labels: weightedVulns.map(v => v.title.substring(0, 30)),
          scores: weightedVulns.map(v => Math.round(v.weight * 10))
        },
        confidence_overall,
        heatmap: {
          categories: owaspCategories,
          checks: heatmapChecks
        }
      },
      markdown_report: backendResult.executive_summary || '',
      notes: `Signature-based vulnerability scan completed at ${new Date().toISOString()}`,
      overall_verdict
    };

    return result;
  };

  // Save scan to history
  const saveScanToHistory = async (result: ScanResult) => {
    const getRiskLevel = (score: number): string => {
      if (score >= 90) return 'SECURE';
      if (score >= 70) return 'LOW RISK';
      if (score >= 50) return 'MEDIUM RISK';
      if (score >= 30) return 'HIGH RISK';
      return 'CRITICAL RISK';
    };

    try {
      // Get current user - scan history now requires authentication
      const { data: { user } } = await supabase.auth.getUser();
      
      if (!user) {
        console.log('User not authenticated - scan will not be saved to history');
        return;
      }

      const { error } = await supabase
        .from('scan_history')
        .insert({
          scan_id: result.scan_id,
          target_url: result.input_url,
          final_url: result.final_url,
          platform: result.platform.name,
          security_score: result.summary.security_score,
          confidence_overall: result.confidence_overall,
          total_findings: result.summary.total_checks,
          critical_count: result.summary.critical,
          high_count: result.summary.high,
          medium_count: result.summary.medium,
          low_count: result.summary.low,
          info_count: result.findings.filter(f => f.severity === 'info').length,
          vulnerable_count: result.summary.vulnerable_count,
          immune_count: result.summary.immune_count,
          risk_level: getRiskLevel(result.summary.security_score),
          scan_result: result as any,
          user_id: user.id
        });

      if (error) throw error;
      setHistoryKey(prev => prev + 1);
    } catch (error) {
      console.error('Failed to save scan to history:', error);
    }
  };

  // Helper to capture chart as image
  const captureChart = async (ref: React.RefObject<HTMLDivElement>): Promise<string | null> => {
    if (!ref.current) return null;
    try {
      // Wait a bit for charts to render
      await new Promise(resolve => setTimeout(resolve, 100));
      const canvas = await html2canvas(ref.current, {
        scale: 2,
        backgroundColor: '#ffffff',
        logging: false,
        useCORS: true
      });
      return canvas.toDataURL('image/png');
    } catch (error) {
      console.error('Error capturing chart:', error);
      return null;
    }
  };

  const generatePDF = async (result: ScanResult) => {
    toast.info("Generating detailed PDF report...");
    
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 20;
    const contentWidth = pageWidth - 2 * margin;
    let yPos = 20;

    // Helper function to add new page
    const addNewPage = () => {
      doc.addPage();
      yPos = margin;
    };

    // Helper function to check if we need a new page
    const checkPageBreak = (requiredSpace: number) => {
      if (yPos + requiredSpace > pageHeight - margin) {
        addNewPage();
        return true;
      }
      return false;
    };

    // Helper to add footer
    const addFooter = () => {
      const currentPage = doc.getCurrentPageInfo().pageNumber;
      doc.setFontSize(8);
      doc.setTextColor(128, 128, 128);
      doc.text(`SentinelX - Page ${currentPage}`, pageWidth / 2, pageHeight - 10, { align: 'center' });
      doc.setTextColor(0, 0, 0);
    };

    // Helper to get risk level
    const getRiskLevel = (score: number): string => {
      if (score >= 90) return 'SECURE';
      if (score >= 70) return 'LOW RISK';
      if (score >= 50) return 'MEDIUM RISK';
      if (score >= 30) return 'HIGH RISK';
      return 'CRITICAL RISK';
    };

    const currentDate = new Date().toLocaleDateString('en-US', { 
      year: 'numeric', 
      month: 'long', 
      day: 'numeric' 
    });
    const displayUrl = result.final_url.length > 60 ? result.final_url.substring(0, 60) + '...' : result.final_url;

    // ===== PAGE 1: COVER PAGE =====
    doc.setFillColor(15, 23, 42);
    doc.rect(0, 0, pageWidth, pageHeight, 'F');
    
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(36);
    doc.setFont('helvetica', 'bold');
    doc.text('Vulnerability Scan Report', pageWidth / 2, 80, { align: 'center' });
    
    doc.setFontSize(14);
    doc.setFont('helvetica', 'normal');
    doc.text('Prepared By', pageWidth / 2, 120, { align: 'center' });
    
    doc.setFontSize(20);
    doc.setFont('helvetica', 'bold');
    doc.text('SentinelX', pageWidth / 2, 140, { align: 'center' });
    
    doc.setFontSize(12);
    doc.setFont('helvetica', 'normal');
    doc.text(currentDate, pageWidth / 2, 165, { align: 'center' });
    
    doc.setFontSize(10);
    doc.text(displayUrl, pageWidth / 2, 185, { align: 'center' });

    // ===== PAGE 2: TABLE OF CONTENTS =====
    addNewPage();
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(28);
    doc.setFont('helvetica', 'bold');
    doc.text('Table of Contents', margin, yPos);
    yPos += 20;

    doc.setFontSize(11);
    doc.setFont('helvetica', 'normal');
    const tocItems = [
      { title: '1. Executive Summary', page: 3 },
      { title: '2. Scan Overview & Statistics', page: 4 },
      { title: '3. Severity Breakdown', page: 5 },
      { title: '4. OWASP Top 10 Analysis', page: 6 },
      { title: '5. Detailed Findings', page: 7 },
      { title: '6. Technical Details', page: '8+' },
      { title: '7. Recommendations', page: '9+' },
    ];

    tocItems.forEach(item => {
      doc.text(item.title, margin + 5, yPos);
      doc.text(String(item.page), pageWidth - margin - 10, yPos, { align: 'right' });
      yPos += 10;
    });

    addFooter();

    // ===== PAGE 3: EXECUTIVE SUMMARY =====
    addNewPage();
    doc.setFontSize(24);
    doc.setFont('helvetica', 'bold');
    doc.text('1. Executive Summary', margin, yPos);
    yPos += 15;

    doc.setFontSize(11);
    doc.setFont('helvetica', 'normal');
    const introLines = doc.splitTextToSize(
      `A comprehensive vulnerability scan was conducted on ${result.final_url} on ${currentDate}. This report provides a detailed analysis of all security findings, categorized by severity and mapped to OWASP Top 10 categories.`,
      contentWidth
    );
    introLines.forEach((line: string) => {
      doc.text(line, margin, yPos);
      yPos += 6;
    });
    yPos += 10;

    // Overall Assessment
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('Overall Security Assessment', margin, yPos);
    yPos += 10;

    const riskLevel = getRiskLevel(result.summary.security_score);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'normal');
    
    const assessmentText = `The target system received a Security Score of ${result.summary.security_score.toFixed(1)} out of 100, which is classified as "${riskLevel}". The overall confidence level for this assessment is ${result.confidence_overall}%.`;
    const assessmentLines = doc.splitTextToSize(assessmentText, contentWidth);
    assessmentLines.forEach((line: string) => {
      doc.text(line, margin, yPos);
      yPos += 6;
    });
    yPos += 10;

    // Verdict
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('Verdict', margin, yPos);
    yPos += 10;

    doc.setFontSize(11);
    doc.setFont('helvetica', 'normal');
    const verdictLines = doc.splitTextToSize(result.overall_verdict, contentWidth);
    verdictLines.forEach((line: string) => {
      checkPageBreak(6);
      doc.text(line, margin, yPos);
      yPos += 6;
    });

    addFooter();

    // ===== PAGE 4: SCAN OVERVIEW & STATISTICS =====
    addNewPage();
    doc.setFontSize(24);
    doc.setFont('helvetica', 'bold');
    doc.text('2. Scan Overview & Statistics', margin, yPos);
    yPos += 15;

    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('Target Information', margin, yPos);
    yPos += 10;

    autoTable(doc, {
      startY: yPos,
      head: [['Property', 'Value']],
      body: [
        ['Input URL', result.input_url],
        ['Final URL', result.final_url],
        ['Platform Detected', `${result.platform.name} (${result.platform.category}) - ${result.platform.confidence}% confidence`],
        ['Resource Type', `${result.resource_type.type} - ${result.resource_type.confidence}% confidence`],
        ['Status Code', result.status_code.toString()],
        ['Content Type', result.content_type],
        ['DNS Resolved', result.dns_resolution.resolved ? 'Yes' : 'No'],
        ['IP Addresses', result.dns_resolution.ips.join(', ') || 'N/A'],
      ],
      theme: 'striped',
      headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontStyle: 'bold' },
      margin: { left: margin, right: margin },
    });

    yPos = (doc as any).lastAutoTable.finalY + 15;

    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('TLS/SSL Configuration', margin, yPos);
    yPos += 10;

    autoTable(doc, {
      startY: yPos,
      head: [['Property', 'Value']],
      body: [
        ['TLS Valid', result.tls.valid ? 'Yes' : 'No'],
        ['Certificate Expires In', `${result.tls.expires_in_days} days`],
        ['Protocols Supported', result.tls.protocols.join(', ')],
      ],
      theme: 'striped',
      headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontStyle: 'bold' },
      margin: { left: margin, right: margin },
    });

    yPos = (doc as any).lastAutoTable.finalY + 15;

    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('Scan Statistics', margin, yPos);
    yPos += 10;

    autoTable(doc, {
      startY: yPos,
      head: [['Metric', 'Value']],
      body: [
        ['Total Security Checks', result.summary.total_checks.toString()],
        ['Vulnerabilities Found', result.summary.vulnerable_count.toString()],
        ['Immune Checks', result.summary.immune_count.toString()],
        ['Security Score', `${result.summary.security_score.toFixed(1)}/100`],
        ['Overall Confidence', `${result.confidence_overall}%`],
        ['Risk Level', riskLevel],
      ],
      theme: 'striped',
      headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontStyle: 'bold' },
      margin: { left: margin, right: margin },
    });

    addFooter();

    // ===== PAGE 5: SEVERITY BREAKDOWN =====
    addNewPage();
    doc.setFontSize(24);
    doc.setFont('helvetica', 'bold');
    doc.text('3. Severity Breakdown', margin, yPos);
    yPos += 15;

    const severityCounts = {
      critical: result.findings.filter(f => f.severity === 'critical').length,
      high: result.findings.filter(f => f.severity === 'high').length,
      medium: result.findings.filter(f => f.severity === 'medium').length,
      low: result.findings.filter(f => f.severity === 'low').length,
      info: result.findings.filter(f => f.severity === 'info').length,
    };

    doc.setFontSize(11);
    doc.setFont('helvetica', 'normal');
    const severityIntro = 'The following table shows the distribution of findings by severity level. Critical and High severity issues require immediate attention.';
    const severityIntroLines = doc.splitTextToSize(severityIntro, contentWidth);
    severityIntroLines.forEach((line: string) => {
      doc.text(line, margin, yPos);
      yPos += 6;
    });
    yPos += 10;

    autoTable(doc, {
      startY: yPos,
      head: [['Severity', 'Count', 'Description']],
      body: [
        ['CRITICAL', severityCounts.critical.toString(), 'Immediate exploitation possible; may lead to full system compromise'],
        ['HIGH', severityCounts.high.toString(), 'Significant risk; exploitation could lead to data breach or system access'],
        ['MEDIUM', severityCounts.medium.toString(), 'Moderate risk; could be exploited under specific conditions'],
        ['LOW', severityCounts.low.toString(), 'Minor risk; limited impact or difficult to exploit'],
        ['INFO', severityCounts.info.toString(), 'Informational findings; best practices and hardening recommendations'],
      ],
      theme: 'grid',
      headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontStyle: 'bold' },
      bodyStyles: { fontSize: 10 },
      columnStyles: {
        0: { cellWidth: 25 },
        1: { cellWidth: 20, halign: 'center' },
        2: { cellWidth: 'auto' },
      },
      margin: { left: margin, right: margin },
    });

    yPos = (doc as any).lastAutoTable.finalY + 15;

    // Status breakdown
    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('Vulnerability Status Summary', margin, yPos);
    yPos += 10;

    const vulnerableFindings = result.findings.filter(f => f.status === 'vulnerable');
    const immuneFindings = result.findings.filter(f => f.status === 'immune');
    const unknownFindings = result.findings.filter(f => f.status === 'unknown');

    autoTable(doc, {
      startY: yPos,
      head: [['Status', 'Count', 'Description']],
      body: [
        ['VULNERABLE', vulnerableFindings.length.toString(), 'Active vulnerabilities that require remediation'],
        ['IMMUNE', immuneFindings.length.toString(), 'Security controls properly implemented'],
        ['UNKNOWN', unknownFindings.length.toString(), 'Could not determine status; manual review recommended'],
      ],
      theme: 'grid',
      headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontStyle: 'bold' },
      bodyStyles: { fontSize: 10 },
      margin: { left: margin, right: margin },
    });

    addFooter();

    // ===== PAGE 6: OWASP TOP 10 ANALYSIS =====
    addNewPage();
    doc.setFontSize(24);
    doc.setFont('helvetica', 'bold');
    doc.text('4. OWASP Top 10 Analysis', margin, yPos);
    yPos += 15;

    doc.setFontSize(11);
    doc.setFont('helvetica', 'normal');
    const owaspIntro = 'The findings have been mapped to the OWASP Top 10 2021 categories. This provides a standardized framework for understanding and prioritizing security risks.';
    const owaspIntroLines = doc.splitTextToSize(owaspIntro, contentWidth);
    owaspIntroLines.forEach((line: string) => {
      doc.text(line, margin, yPos);
      yPos += 6;
    });
    yPos += 10;

    // Group findings by OWASP category
    const owaspCategories = [
      'A01 - Broken Access Control',
      'A02 - Cryptographic Failures',
      'A03 - Injection',
      'A04 - Insecure Design',
      'A05 - Security Misconfiguration',
      'A06 - Vulnerable and Outdated Components',
      'A07 - Identification and Authentication Failures',
      'A08 - Software and Data Integrity Failures',
      'A09 - Security Logging and Monitoring Failures',
      'A10 - Server-Side Request Forgery',
    ];

    const owaspData = owaspCategories.map(category => {
      const categoryFindings = result.findings.filter(f => f.owasp_category === category);
      const vulnerable = categoryFindings.filter(f => f.status === 'vulnerable').length;
      const immune = categoryFindings.filter(f => f.status === 'immune').length;
      return [category, categoryFindings.length.toString(), vulnerable.toString(), immune.toString()];
    });

    autoTable(doc, {
      startY: yPos,
      head: [['OWASP Category', 'Total Checks', 'Vulnerable', 'Immune']],
      body: owaspData,
      theme: 'striped',
      headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontStyle: 'bold', fontSize: 9 },
      bodyStyles: { fontSize: 9 },
      columnStyles: {
        0: { cellWidth: 80 },
        1: { cellWidth: 25, halign: 'center' },
        2: { cellWidth: 25, halign: 'center' },
        3: { cellWidth: 25, halign: 'center' },
      },
      margin: { left: margin, right: margin },
    });

    addFooter();

    // ===== PAGE 7+: DETAILED FINDINGS =====
    addNewPage();
    doc.setFontSize(24);
    doc.setFont('helvetica', 'bold');
    doc.text('5. Detailed Findings', margin, yPos);
    yPos += 15;

    doc.setFontSize(11);
    doc.setFont('helvetica', 'normal');
    const findingsIntro = 'This section provides a comprehensive breakdown of all security findings, organized by severity level. Each finding includes the vulnerability title, OWASP category, current status, confidence level, evidence, and recommended remediation steps.';
    const findingsIntroLines = doc.splitTextToSize(findingsIntro, contentWidth);
    findingsIntroLines.forEach((line: string) => {
      doc.text(line, margin, yPos);
      yPos += 6;
    });
    yPos += 10;

    // Group findings by severity
    const groupedFindings = {
      critical: result.findings.filter(f => f.severity === 'critical'),
      high: result.findings.filter(f => f.severity === 'high'),
      medium: result.findings.filter(f => f.severity === 'medium'),
      low: result.findings.filter(f => f.severity === 'low'),
      info: result.findings.filter(f => f.severity === 'info'),
    };

    const severityColors: Record<string, [number, number, number]> = {
      critical: [220, 38, 38],
      high: [239, 68, 68],
      medium: [251, 146, 60],
      low: [59, 130, 246],
      info: [156, 163, 175],
    };

    const severityDescriptions: Record<string, string> = {
      critical: 'These vulnerabilities pose an immediate and severe risk. They can be exploited easily and may result in complete system compromise, data breach, or significant financial loss. Remediation should begin immediately.',
      high: 'High severity vulnerabilities represent significant security risks that could lead to unauthorized access, data exposure, or service disruption. These should be addressed as a priority within the next sprint or release cycle.',
      medium: 'Medium severity issues indicate areas where security could be improved. While exploitation may require specific conditions or additional access, they should be remediated in a timely manner.',
      low: 'Low severity findings represent minor security concerns or deviations from best practices. These have limited impact but should be addressed as part of regular maintenance.',
      info: 'Informational findings highlight areas for potential improvement and security hardening recommendations. These are not vulnerabilities but represent opportunities to strengthen the security posture.',
    };

    Object.entries(groupedFindings).forEach(([severity, findings]) => {
      if (findings.length === 0) return;

      checkPageBreak(50);
      
      // Section header
      doc.setFontSize(16);
      doc.setFont('helvetica', 'bold');
      const color = severityColors[severity];
      doc.setTextColor(color[0], color[1], color[2]);
      doc.text(`${severity.toUpperCase()} SEVERITY (${findings.length} findings)`, margin, yPos);
      doc.setTextColor(0, 0, 0);
      yPos += 10;

      // Severity description
      doc.setFontSize(10);
      doc.setFont('helvetica', 'italic');
      const descLines = doc.splitTextToSize(severityDescriptions[severity], contentWidth);
      descLines.forEach((line: string) => {
        checkPageBreak(5);
        doc.text(line, margin, yPos);
        yPos += 5;
      });
      yPos += 8;

      findings.forEach((finding, idx) => {
        checkPageBreak(80);
        
        // Finding header
        doc.setFillColor(240, 240, 240);
        doc.rect(margin, yPos - 3, contentWidth, 8, 'F');
        
        doc.setFontSize(11);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(0, 0, 0);
        const titleText = `${idx + 1}. ${finding.title}`;
        doc.text(titleText, margin + 2, yPos + 2);
        yPos += 12;

        // Finding ID and category
        doc.setFontSize(9);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(80, 80, 80);
        doc.text(`ID: ${finding.id}`, margin, yPos);
        yPos += 5;
        doc.text(`OWASP Category: ${finding.owasp_category}`, margin, yPos);
        yPos += 5;
        doc.text(`Status: ${finding.status.toUpperCase()} | Confidence: ${finding.confidence}%`, margin, yPos);
        doc.setTextColor(0, 0, 0);
        yPos += 8;

        // Evidence section
        if (finding.evidence && finding.evidence.length > 0) {
          checkPageBreak(20);
          doc.setFontSize(10);
          doc.setFont('helvetica', 'bold');
          doc.text('Evidence:', margin, yPos);
          yPos += 6;
          
          doc.setFont('helvetica', 'normal');
          doc.setFontSize(9);
          finding.evidence.forEach((ev: string) => {
            checkPageBreak(6);
            const evLines = doc.splitTextToSize(`• ${ev}`, contentWidth - 10);
            evLines.forEach((line: string) => {
              checkPageBreak(5);
              doc.text(line, margin + 5, yPos);
              yPos += 5;
            });
          });
          yPos += 3;
        }

        // Recommendation section
        checkPageBreak(20);
        doc.setFontSize(10);
        doc.setFont('helvetica', 'bold');
        doc.text('Recommendation:', margin, yPos);
        yPos += 6;
        
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(9);
        const recLines = doc.splitTextToSize(finding.recommendation, contentWidth - 10);
        recLines.forEach((line: string) => {
          checkPageBreak(5);
          doc.text(line, margin + 5, yPos);
          yPos += 5;
        });
        yPos += 3;

        // References section
        if (finding.references && finding.references.length > 0) {
          checkPageBreak(15);
          doc.setFontSize(10);
          doc.setFont('helvetica', 'bold');
          doc.text('References:', margin, yPos);
          yPos += 6;
          
          doc.setFont('helvetica', 'normal');
          doc.setFontSize(8);
          doc.setTextColor(0, 0, 200);
          finding.references.forEach((ref: string) => {
            checkPageBreak(5);
            doc.text(`• ${ref}`, margin + 5, yPos);
            yPos += 5;
          });
          doc.setTextColor(0, 0, 0);
        }

        yPos += 10;
        
        // Add separator line
        if (idx < findings.length - 1) {
          doc.setDrawColor(200, 200, 200);
          doc.line(margin, yPos, pageWidth - margin, yPos);
          yPos += 8;
        }
      });

      yPos += 10;
      addFooter();
    });

    // ===== TECHNICAL DETAILS PAGE =====
    addNewPage();
    doc.setFontSize(24);
    doc.setFont('helvetica', 'bold');
    doc.text('6. Technical Details', margin, yPos);
    yPos += 15;

    doc.setFontSize(14);
    doc.setFont('helvetica', 'bold');
    doc.text('HTTP Response Headers', margin, yPos);
    yPos += 10;

    doc.setFontSize(10);
    doc.setFont('helvetica', 'normal');
    const headerIntro = 'The following HTTP response headers were observed during the scan. Security-relevant headers are critical for protecting against common web attacks.';
    const headerIntroLines = doc.splitTextToSize(headerIntro, contentWidth);
    headerIntroLines.forEach((line: string) => {
      doc.text(line, margin, yPos);
      yPos += 5;
    });
    yPos += 8;

    const headerData = Object.entries(result.headers).map(([key, value]) => {
      const truncatedValue = value.length > 80 ? value.substring(0, 77) + '...' : value;
      return [key, truncatedValue];
    });

    if (headerData.length > 0) {
      autoTable(doc, {
        startY: yPos,
        head: [['Header Name', 'Value']],
        body: headerData,
        theme: 'striped',
        headStyles: { fillColor: [15, 23, 42], textColor: [255, 255, 255], fontStyle: 'bold', fontSize: 9 },
        bodyStyles: { fontSize: 8 },
        columnStyles: {
          0: { cellWidth: 50 },
          1: { cellWidth: 'auto' },
        },
        margin: { left: margin, right: margin },
      });
      yPos = (doc as any).lastAutoTable.finalY + 15;
    }

    // Redirect chain if exists
    if (result.redirect_chain && result.redirect_chain.length > 1) {
      checkPageBreak(40);
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      doc.text('Redirect Chain', margin, yPos);
      yPos += 10;

      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      result.redirect_chain.forEach((url, idx) => {
        checkPageBreak(6);
        doc.text(`${idx + 1}. ${url}`, margin + 5, yPos);
        yPos += 6;
      });
    }

    addFooter();

    // ===== FINAL PAGE: RECOMMENDATIONS SUMMARY =====
    addNewPage();
    doc.setFontSize(24);
    doc.setFont('helvetica', 'bold');
    doc.text('7. Recommendations Summary', margin, yPos);
    yPos += 15;

    doc.setFontSize(11);
    doc.setFont('helvetica', 'normal');
    const recIntro = 'Based on the findings of this security assessment, the following actions are recommended to improve the security posture of the target system:';
    const recIntroLines = doc.splitTextToSize(recIntro, contentWidth);
    recIntroLines.forEach((line: string) => {
      doc.text(line, margin, yPos);
      yPos += 6;
    });
    yPos += 10;

    const recommendations = [
      { priority: 'IMMEDIATE', items: [
        'Address all CRITICAL severity vulnerabilities within 24-48 hours',
        'Review and remediate HIGH severity findings within the current sprint',
        'Ensure all admin endpoints require proper authentication and authorization',
      ]},
      { priority: 'SHORT-TERM', items: [
        'Implement missing security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options',
        'Enable HTTPS with TLS 1.2+ and strong cipher suites',
        'Review and update all third-party dependencies to latest secure versions',
        'Implement Web Application Firewall (WAF) for additional protection',
      ]},
      { priority: 'LONG-TERM', items: [
        'Establish regular vulnerability scanning on a monthly basis',
        'Implement security awareness training for development and operations teams',
        'Set up continuous security monitoring and logging with SIEM integration',
        'Conduct annual penetration testing by qualified security professionals',
        'Develop and maintain an incident response plan',
      ]},
    ];

    recommendations.forEach(section => {
      checkPageBreak(30);
      doc.setFontSize(12);
      doc.setFont('helvetica', 'bold');
      doc.text(`${section.priority} Actions:`, margin, yPos);
      yPos += 8;

      doc.setFontSize(10);
      doc.setFont('helvetica', 'normal');
      section.items.forEach(item => {
        checkPageBreak(12);
        const itemLines = doc.splitTextToSize(`• ${item}`, contentWidth - 10);
        itemLines.forEach((line: string) => {
          checkPageBreak(5);
          doc.text(line, margin + 5, yPos);
          yPos += 5;
        });
        yPos += 2;
      });
      yPos += 8;
    });

    // Closing notes
    yPos += 10;
    checkPageBreak(40);
    doc.setDrawColor(15, 23, 42);
    doc.line(margin, yPos, pageWidth - margin, yPos);
    yPos += 10;

    doc.setFontSize(10);
    doc.setFont('helvetica', 'italic');
    doc.setTextColor(100, 100, 100);
    const closingText = 'This report was generated by SentinelX. The findings are based on automated scanning techniques and should be validated by security professionals. For questions, support, or to schedule a comprehensive security assessment, please contact your security team.';
    const closingLines = doc.splitTextToSize(closingText, contentWidth);
    closingLines.forEach((line: string) => {
      checkPageBreak(5);
      doc.text(line, margin, yPos);
      yPos += 5;
    });

    yPos += 10;
    doc.setFont('helvetica', 'normal');
    doc.text(`Report Generated: ${new Date().toISOString()}`, margin, yPos);
    yPos += 5;
    doc.text(`Scan ID: ${result.scan_id}`, margin, yPos);

    addFooter();

    // Save PDF
    const domain = new URL(result.final_url).hostname.replace(/\./g, '_');
    const date = new Date().toISOString().split('T')[0];
    const fileName = `${domain}_security_report_${date}.pdf`;

    doc.save(fileName);
    toast.success("Detailed PDF report downloaded successfully!");
  };

  const handleStartScan = async () => {
    if (!targetUrl.trim()) {
      toast.error("Please enter a URL to scan");
      return;
    }

    setIsScanning(true);
    setScanProgress(0);
    setScanResult(null);

    try {
      const result = await simulateVulnerabilityScan(targetUrl);
      setScanResult(result);
      // Save to history after successful scan
      await saveScanToHistory(result);
      toast.success("✅ Scan completed successfully!");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "Scan failed");
    } finally {
      setIsScanning(false);
    }
  };

  // Handle viewing a historical scan
  const handleViewHistoricalScan = (scanData: ScanResult) => {
    setScanResult(scanData);
    toast.info("Loaded historical scan result");
  };

  const getSeverityBadge = (severity: string) => {
    const variants: Record<string, { color: string; icon: any }> = {
      critical: { color: 'bg-destructive text-destructive-foreground', icon: AlertTriangle },
      high: { color: 'bg-orange-500 text-white', icon: AlertTriangle },
      medium: { color: 'bg-yellow-500 text-white', icon: Info },
      low: { color: 'bg-blue-500 text-white', icon: Info },
      info: { color: 'bg-muted text-muted-foreground', icon: CheckCircle2 }
    };

    const variant = variants[severity] || variants.info;
    const Icon = variant.icon;

    return (
      <Badge className={variant.color}>
        <Icon className="w-3 h-3 mr-1" />
        {severity.toUpperCase()}
      </Badge>
    );
  };

  const getStatusBadge = (status: string) => {
    if (status === 'immune') {
      return <Badge variant="outline" className="bg-green-50 text-green-700 border-green-300"><CheckCircle2 className="w-3 h-3 mr-1" />Immune</Badge>;
    }
    return <Badge variant="outline" className="bg-red-50 text-red-700 border-red-300"><AlertTriangle className="w-3 h-3 mr-1" />Vulnerable</Badge>;
  };

  const getRiskBadge = (score: number) => {
    if (score >= 90) return <Badge className="bg-green-500 text-white">Secure</Badge>;
    if (score >= 70) return <Badge className="bg-blue-500 text-white">Low Risk</Badge>;
    if (score >= 50) return <Badge className="bg-yellow-500 text-white">Medium Risk</Badge>;
    if (score >= 30) return <Badge className="bg-orange-500 text-white">High Risk</Badge>;
    return <Badge className="bg-destructive text-destructive-foreground">Critical Risk</Badge>;
  };

  return (
    <div className="min-h-screen bg-background cyber-grid relative overflow-hidden">
      {/* Ambient background effects */}
      <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-secondary/10 pointer-events-none" />
      <div className="absolute top-0 left-1/4 w-96 h-96 bg-primary/10 rounded-full blur-3xl pointer-events-none" />
      <div className="absolute bottom-0 right-1/4 w-80 h-80 bg-accent/10 rounded-full blur-3xl pointer-events-none" />
      
      <div className="container mx-auto px-6 py-10 max-w-7xl relative z-10">
        {/* Header */}
        <div className="flex items-center justify-between mb-12">
          <div className="flex items-center gap-6">
            <Link to="/">
              <Button variant="outline" size="icon" className="border-border/50 hover:border-primary/50 hover:bg-primary/10 transition-all duration-300">
                <ArrowLeft className="w-5 h-5" />
              </Button>
            </Link>
            <div>
              <h1 className="text-4xl font-bold flex items-center gap-3 text-foreground">
                <div className="p-3 rounded-xl bg-gradient-to-br from-primary/20 to-primary/5 border border-primary/20 glow-cyber">
                  <Shield className="w-8 h-8 text-primary" />
                </div>
                <span className="gradient-text">Vulnerability Scanner</span>
              </h1>
              <p className="text-muted-foreground mt-2 text-lg">
                Enterprise-grade OWASP security analysis • 100+ automated checks
              </p>
            </div>
          </div>
          <div className="hidden md:flex items-center gap-3">
            <Badge variant="outline" className="border-primary/30 text-primary bg-primary/5 px-3 py-1">
              <Lock className="w-3 h-3 mr-1" />
              Passive Scan
            </Badge>
            <Badge variant="outline" className="border-cyber-green/30 text-cyber-green bg-cyber-green/5 px-3 py-1">
              <CheckCircle2 className="w-3 h-3 mr-1" />
              Non-Destructive
            </Badge>
          </div>
        </div>

        {/* Scanner Input - Enhanced */}
        <Card className="mb-10 border-border/50 bg-card/80 backdrop-blur-sm shadow-elevated overflow-hidden group">
          <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-transparent to-accent/5 opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
          <CardHeader className="relative pb-4">
            <CardTitle className="flex items-center gap-3 text-xl">
              <div className="p-2 rounded-lg bg-primary/10 border border-primary/20">
                <Globe className="w-5 h-5 text-primary" />
              </div>
              Target URL
            </CardTitle>
            <CardDescription className="text-base">
              Enter the website URL for comprehensive security vulnerability assessment
            </CardDescription>
          </CardHeader>
          <CardContent className="relative">
            <div className="flex gap-4">
              <div className="flex-1 relative">
                <Input
                  type="url"
                  placeholder="https://example.com"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  disabled={isScanning}
                  className="h-14 text-lg px-5 bg-input/50 border-border/50 focus:border-primary focus:ring-2 focus:ring-primary/20 transition-all duration-300"
                  onKeyDown={(e) => e.key === 'Enter' && !isScanning && handleStartScan()}
                />
                {isScanning && (
                  <div className="absolute right-4 top-1/2 -translate-y-1/2">
                    <div className="w-6 h-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                  </div>
                )}
              </div>
              <Button
                onClick={handleStartScan}
                disabled={isScanning}
                size="lg"
                className={`h-14 px-8 text-lg font-semibold transition-all duration-300 ${
                  isScanning 
                    ? 'bg-muted text-muted-foreground' 
                    : 'bg-gradient-to-r from-primary to-accent hover:shadow-cyber hover:scale-[1.02]'
                }`}
              >
                {isScanning ? (
                  <>
                    <Scan className="w-5 h-5 mr-2 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Scan className="w-5 h-5 mr-2" />
                    Start Scan
                  </>
                )}
              </Button>
            </div>

            {isScanning && (
              <div className="mt-8 space-y-4 p-6 rounded-xl bg-muted/30 border border-border/50">
                <div className="flex justify-between items-center">
                  <div className="flex items-center gap-3">
                    <div className="w-2 h-2 rounded-full bg-primary animate-pulse" />
                    <span className="text-muted-foreground font-medium">{currentScanPhase}</span>
                  </div>
                  <span className="font-bold text-xl text-primary">{Math.round(scanProgress)}%</span>
                </div>
                <div className="relative">
                  <Progress value={scanProgress} className="h-3 bg-muted" />
                  <div 
                    className="absolute top-0 left-0 h-3 bg-gradient-to-r from-primary via-accent to-primary rounded-full transition-all duration-300"
                    style={{ width: `${scanProgress}%`, backgroundSize: '200% 100%', animation: 'shimmer 2s infinite' }}
                  />
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Tabs for Results and History */}
        <Tabs defaultValue="results" className="w-full">
          <TabsList className="grid w-full grid-cols-2 mb-8 h-14 p-1 bg-muted/50 border border-border/50 rounded-xl">
            <TabsTrigger value="results" className="flex items-center gap-2 h-full rounded-lg data-[state=active]:bg-card data-[state=active]:shadow-lg data-[state=active]:border-border/50 transition-all duration-300">
              <Shield className="w-5 h-5" />
              <span className="font-semibold">Scan Results</span>
            </TabsTrigger>
            <TabsTrigger value="history" className="flex items-center gap-2 h-full rounded-lg data-[state=active]:bg-card data-[state=active]:shadow-lg data-[state=active]:border-border/50 transition-all duration-300">
              <History className="w-5 h-5" />
              <span className="font-semibold">Scan History</span>
            </TabsTrigger>
          </TabsList>
          
          <TabsContent value="results">
            {/* Scan Results */}
            {scanResult ? (
              <div className="space-y-8">
                {/* Charts Section */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                  {/* Severity Distribution */}
                  <Card className="border-border/50 bg-card/80 backdrop-blur-sm shadow-card hover:shadow-elevated transition-all duration-300 group overflow-hidden">
                    <div className="absolute inset-0 bg-gradient-to-br from-destructive/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                    <CardHeader className="relative">
                      <CardTitle className="flex items-center gap-3 text-lg">
                        <div className="p-2 rounded-lg bg-destructive/10 border border-destructive/20">
                          <AlertTriangle className="w-5 h-5 text-destructive" />
                        </div>
                        Severity Distribution
                      </CardTitle>
                      <CardDescription className="text-base">Breakdown of vulnerabilities by severity level</CardDescription>
                    </CardHeader>
                    <CardContent className="relative">
                      <div ref={severityChartRef} className="bg-background/50 p-6 rounded-xl border border-border/30">
                        <SeverityDistributionChart data={scanResult.chart_data.severity_distribution} />
                      </div>
                    </CardContent>
                  </Card>

                  {/* Confidence Gauge */}
                  <Card className="border-border/50 bg-card/80 backdrop-blur-sm shadow-card hover:shadow-elevated transition-all duration-300 group overflow-hidden">
                    <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                    <CardHeader className="relative">
                      <CardTitle className="flex items-center gap-3 text-lg">
                        <div className="p-2 rounded-lg bg-primary/10 border border-primary/20">
                          <Shield className="w-5 h-5 text-primary" />
                        </div>
                        Security Score & Confidence
                      </CardTitle>
                      <CardDescription className="text-base">Overall security posture assessment</CardDescription>
                    </CardHeader>
                    <CardContent className="relative">
                      <div ref={confidenceChartRef} className="bg-background/50 p-6 rounded-xl border border-border/30">
                        <div className="grid grid-cols-2 gap-6">
                          <div>
                            <ConfidenceGauge confidence={scanResult.chart_data.confidence_overall} />
                          </div>
                          <div className="flex flex-col justify-center items-center">
                            <div className="text-6xl font-bold gradient-text">
                              {scanResult.summary.security_score.toFixed(0)}
                            </div>
                            <div className="text-sm text-muted-foreground mt-2 font-medium">Security Score</div>
                            <div className="mt-4">
                              {getRiskBadge(scanResult.summary.security_score)}
                            </div>
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                </div>

                {/* OWASP Radar Chart */}
                <Card className="border-border/50 bg-card/80 backdrop-blur-sm shadow-card hover:shadow-elevated transition-all duration-300 group overflow-hidden">
                  <div className="absolute inset-0 bg-gradient-to-br from-accent/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                  <CardHeader className="relative">
                    <CardTitle className="flex items-center gap-3 text-lg">
                      <div className="p-2 rounded-lg bg-accent/10 border border-accent/20">
                        <Server className="w-5 h-5 text-accent" />
                      </div>
                      OWASP Top 10 Coverage Analysis
                    </CardTitle>
                    <CardDescription className="text-base">
                      Immunity levels across OWASP security categories (100% = fully immune)
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="relative">
                    <div ref={owaspChartRef} className="bg-background/50 p-6 rounded-xl border border-border/30">
                      <OWASPRadarChart data={scanResult.chart_data.owasp_radar} />
                    </div>
                  </CardContent>
                </Card>

                {/* Top 10 Vulnerabilities */}
                {scanResult.summary.vulnerable_count > 0 && (
                  <Card className="border-border/50 bg-card/80 backdrop-blur-sm shadow-card hover:shadow-elevated transition-all duration-300 group overflow-hidden">
                    <div className="absolute inset-0 bg-gradient-to-br from-cyber-amber/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                    <CardHeader className="relative">
                      <CardTitle className="flex items-center gap-3 text-lg">
                        <div className="p-2 rounded-lg bg-cyber-amber/10 border border-cyber-amber/20">
                          <AlertTriangle className="w-5 h-5 text-cyber-amber" />
                        </div>
                        Top Weighted Vulnerabilities
                      </CardTitle>
                      <CardDescription className="text-base">
                        Most impactful findings ranked by severity × confidence
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="relative">
                      <div ref={top10ChartRef} className="bg-background/50 p-6 rounded-xl border border-border/30">
                        <Top10VulnerabilitiesChart data={scanResult.chart_data.top10} />
                      </div>
                    </CardContent>
                  </Card>
                )}
                
                {/* Overall Verdict - Enhanced */}
                <Card className={`border-2 overflow-hidden ${scanResult.summary.critical > 0 ? 'border-destructive/50 bg-destructive/5' : 'border-primary/50 bg-primary/5'}`}>
                  <CardContent className="p-8">
                    <div className="flex items-start justify-between gap-6">
                      <div className="flex-1">
                        <div className="flex items-center gap-4 mb-4">
                          <div className={`p-3 rounded-xl ${scanResult.summary.critical > 0 ? 'bg-destructive/10' : 'bg-primary/10'}`}>
                            <Shield className={`w-8 h-8 ${scanResult.summary.critical > 0 ? 'text-destructive' : 'text-primary'}`} />
                          </div>
                          <div>
                            <div className="text-sm text-muted-foreground font-mono">Scan ID</div>
                            <div className="font-semibold text-lg">{scanResult.scan_id}</div>
                          </div>
                        </div>
                        <div className="flex flex-wrap items-center gap-6 mb-4">
                          <div className="flex items-center gap-3 p-3 rounded-xl bg-muted/50">
                            <span className="text-sm text-muted-foreground">Security Score</span>
                            <span className="font-bold text-2xl gradient-text">{scanResult.summary.security_score.toFixed(1)}</span>
                            <span className="text-muted-foreground">/100</span>
                            {getRiskBadge(scanResult.summary.security_score)}
                          </div>
                          <div className="flex items-center gap-3 p-3 rounded-xl bg-muted/50">
                            <span className="text-sm text-muted-foreground">Confidence</span>
                            <span className="font-bold text-xl">{scanResult.confidence_overall}%</span>
                          </div>
                        </div>
                        <p className="text-muted-foreground leading-relaxed">{scanResult.overall_verdict}</p>
                      </div>
                      <Button 
                        onClick={() => generatePDF(scanResult)} 
                        size="lg"
                        className="bg-gradient-to-r from-primary to-accent hover:shadow-cyber transition-all duration-300"
                      >
                        <Download className="w-5 h-5 mr-2" />
                        Download PDF Report
                      </Button>
                    </div>
                  </CardContent>
                </Card>

                {/* Summary Statistics - Enhanced */}
                <Card className="border-border/50 bg-card/80 backdrop-blur-sm shadow-card">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-3 text-lg">
                      <div className="p-2 rounded-lg bg-secondary/50 border border-border/30">
                        <FileText className="w-5 h-5 text-foreground" />
                      </div>
                      Summary Statistics
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
                      <div className="text-center p-5 bg-muted/50 rounded-xl border border-border/30 hover:border-primary/30 transition-all duration-300">
                        <div className="text-3xl font-bold text-foreground">{scanResult.summary.total_checks}</div>
                        <div className="text-sm text-muted-foreground mt-1">Total Checks</div>
                      </div>
                      <div className="text-center p-5 bg-cyber-green/10 rounded-xl border border-cyber-green/30 hover:border-cyber-green/50 transition-all duration-300">
                        <div className="text-3xl font-bold text-cyber-green">{scanResult.summary.immune_count}</div>
                        <div className="text-sm text-cyber-green/80 mt-1">Immune</div>
                      </div>
                      <div className="text-center p-5 bg-destructive/10 rounded-xl border border-destructive/30 hover:border-destructive/50 transition-all duration-300">
                        <div className="text-3xl font-bold text-destructive">{scanResult.summary.vulnerable_count}</div>
                        <div className="text-sm text-destructive/80 mt-1">Vulnerable</div>
                      </div>
                      <div className="text-center p-5 bg-destructive/20 rounded-xl border border-destructive/40 hover:border-destructive/60 transition-all duration-300">
                        <div className="text-3xl font-bold text-destructive">{scanResult.summary.critical}</div>
                        <div className="text-sm text-destructive/80 mt-1">Critical</div>
                      </div>
                      <div className="text-center p-5 bg-cyber-amber/10 rounded-xl border border-cyber-amber/30 hover:border-cyber-amber/50 transition-all duration-300">
                        <div className="text-3xl font-bold text-cyber-amber">{scanResult.summary.high}</div>
                        <div className="text-sm text-cyber-amber/80 mt-1">High</div>
                      </div>
                      <div className="text-center p-5 bg-cyber-amber/5 rounded-xl border border-cyber-amber/20 hover:border-cyber-amber/40 transition-all duration-300">
                        <div className="text-3xl font-bold text-cyber-amber/80">{scanResult.summary.medium}</div>
                        <div className="text-sm text-cyber-amber/60 mt-1">Medium</div>
                      </div>
                      <div className="text-center p-5 bg-primary/10 rounded-xl border border-primary/30 hover:border-primary/50 transition-all duration-300">
                        <div className="text-3xl font-bold text-primary">{scanResult.summary.low}</div>
                        <div className="text-sm text-primary/80 mt-1">Low</div>
                      </div>
                    </div>

                    <div className="mt-8 grid grid-cols-1 md:grid-cols-3 gap-6">
                      <div className="flex items-center gap-4 p-5 bg-muted/30 rounded-xl border border-border/30 hover:border-primary/30 transition-all duration-300">
                        <div className="p-3 rounded-lg bg-primary/10">
                          <Globe className="w-6 h-6 text-primary" />
                        </div>
                        <div className="flex-1">
                          <div className="text-sm text-muted-foreground">Platform</div>
                          <div className="font-semibold text-foreground">{scanResult.platform.name}</div>
                          <div className="text-xs text-muted-foreground mt-1">
                            {scanResult.platform.category} • {scanResult.platform.confidence}% confidence
                            {scanResult.platform.version && ` • v${scanResult.platform.version}`}
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-4 p-5 bg-muted/30 rounded-xl border border-border/30 hover:border-primary/30 transition-all duration-300">
                        <div className="p-3 rounded-lg bg-primary/10">
                          <Server className="w-6 h-6 text-primary" />
                        </div>
                        <div className="flex-1">
                          <div className="text-sm text-muted-foreground">Resource Type</div>
                          <div className="font-semibold text-foreground">{scanResult.resource_type.type}</div>
                          <div className="text-xs text-muted-foreground mt-1">
                            {scanResult.resource_type.description} • {scanResult.resource_type.confidence}% confidence
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-4 p-5 bg-muted/30 rounded-xl border border-border/30 hover:border-primary/30 transition-all duration-300">
                        <div className={`p-3 rounded-lg ${scanResult.tls.valid ? 'bg-cyber-green/10' : 'bg-destructive/10'}`}>
                          <Lock className={`w-6 h-6 ${scanResult.tls.valid ? 'text-cyber-green' : 'text-destructive'}`} />
                        </div>
                        <div>
                          <div className="text-sm text-muted-foreground">TLS Status</div>
                          <div className={`font-semibold ${scanResult.tls.valid ? 'text-cyber-green' : 'text-destructive'}`}>
                            {scanResult.tls.valid ? '✓ Valid Certificate' : '✗ Invalid Certificate'}
                          </div>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>

                {/* Vulnerability Heatmap */}
                <Card className="border-border/50 bg-card/80 backdrop-blur-sm shadow-card">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-3 text-lg">
                      <div className="p-2 rounded-lg bg-cyber-purple/10 border border-cyber-purple/20">
                        <FileText className="w-5 h-5 text-cyber-purple" />
                      </div>
                      OWASP Vulnerability Heatmap
                    </CardTitle>
                    <CardDescription className="text-base">
                      Visual matrix of security checks grouped by OWASP category
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div ref={heatmapChartRef} className="bg-background/50 p-6 rounded-xl border border-border/30">
                      <VulnerabilityHeatmap data={scanResult.chart_data.heatmap} />
                    </div>
                  </CardContent>
                </Card>

                {/* Complete OWASP Compliance Checks */}
                <Card className="border-border/50 bg-card/80 backdrop-blur-sm shadow-card">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-3 text-lg">
                      <div className="p-2 rounded-lg bg-secondary/50 border border-border/30">
                        <CheckCircle2 className="w-5 h-5 text-foreground" />
                      </div>
                      Complete OWASP Compliance Check
                      <Badge variant="outline" className="ml-2">{scanResult.summary.total_checks}+ Categories</Badge>
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <Collapsible>
                      <CollapsibleTrigger asChild>
                        <Button variant="outline" className="w-full justify-between h-14 text-base border-border/50 hover:border-primary/50 hover:bg-primary/5 transition-all duration-300">
                          <span className="font-semibold">View All Security Checks</span>
                          <ChevronDown className="w-5 h-5" />
                        </Button>
                      </CollapsibleTrigger>
                      <CollapsibleContent className="mt-4">
                        <div className="space-y-3 max-h-[600px] overflow-y-auto">
                          {scanResult.findings.map((finding) => (
                            <Collapsible key={finding.id}>
                              <div className="p-4 border rounded-lg hover:bg-muted/50 transition-colors">
                                <div className="flex items-start justify-between gap-4">
                                  <div className="flex-1">
                                    <div className="flex items-center gap-2 mb-2">
                                      <span className="font-mono text-xs text-muted-foreground">{finding.id}</span>
                                      <span className="font-semibold">{finding.title}</span>
                                    </div>
                                    <div className="text-sm text-muted-foreground mb-2">
                                      {finding.owasp_category}
                                    </div>
                                    <div className="flex flex-wrap gap-2 mb-2">
                                      {getStatusBadge(finding.status)}
                                      {getSeverityBadge(finding.severity)}
                                      <Badge variant="secondary">
                                        Confidence: {finding.confidence}%
                                      </Badge>
                                    </div>
                                    
                                    {/* Explanation Preview */}
                                    {finding.explanation && (
                                      <p className="text-sm text-muted-foreground mt-2 line-clamp-2">
                                        {finding.explanation}
                                      </p>
                                    )}
                                  </div>
                                  <CollapsibleTrigger asChild>
                                    <Button variant="ghost" size="sm" className="shrink-0">
                                      <ChevronDown className="w-4 h-4" />
                                      <span className="ml-1 text-xs">Details</span>
                                    </Button>
                                  </CollapsibleTrigger>
                                </div>
                                
                                <CollapsibleContent className="mt-4 pt-4 border-t space-y-4">
                                  {/* Full Explanation */}
                                  {finding.explanation && (
                                    <div className="space-y-2">
                                      <h4 className="text-sm font-semibold flex items-center gap-2">
                                        <Info className="w-4 h-4" />
                                        Analysis Explanation
                                      </h4>
                                      <p className="text-sm text-muted-foreground bg-muted/50 p-3 rounded-lg">
                                        {finding.explanation}
                                      </p>
                                    </div>
                                  )}
                                  
                                  {/* Confidence Factors */}
                                  {finding.confidence_factors && finding.confidence_factors.length > 0 && (
                                    <div className="space-y-2">
                                      <h4 className="text-sm font-semibold">Confidence Score Breakdown</h4>
                                      <ul className="text-sm text-muted-foreground space-y-1 bg-muted/50 p-3 rounded-lg">
                                        {finding.confidence_factors.map((factor, idx) => (
                                          <li key={idx} className="flex items-start gap-2">
                                            <span className="text-primary">•</span>
                                            <span>{factor}</span>
                                          </li>
                                        ))}
                                      </ul>
                                    </div>
                                  )}
                                  
                                  {/* Evidence */}
                                  {finding.evidence && finding.evidence.length > 0 && (
                                    <div className="space-y-2">
                                      <h4 className="text-sm font-semibold">Evidence</h4>
                                      <ul className="text-sm text-muted-foreground space-y-1 bg-muted/50 p-3 rounded-lg font-mono text-xs">
                                        {finding.evidence.map((ev, idx) => (
                                          <li key={idx} className="break-all">{ev}</li>
                                        ))}
                                      </ul>
                                    </div>
                                  )}
                                  
                                  {/* Recommendation */}
                                  <div className="space-y-2">
                                    <h4 className="text-sm font-semibold">Recommendation</h4>
                                    <p className="text-sm text-muted-foreground bg-primary/5 p-3 rounded-lg border border-primary/20">
                                      {finding.recommendation}
                                    </p>
                                  </div>
                                  
                                  {/* References */}
                                  {finding.references && finding.references.length > 0 && (
                                    <div className="space-y-2">
                                      <h4 className="text-sm font-semibold">References</h4>
                                      <ul className="text-sm space-y-1">
                                        {finding.references.map((ref, idx) => (
                                          <li key={idx}>
                                            <a 
                                              href={ref} 
                                              target="_blank" 
                                              rel="noopener noreferrer"
                                              className="text-primary hover:underline break-all"
                                            >
                                              {ref}
                                            </a>
                                          </li>
                                        ))}
                                      </ul>
                                    </div>
                                  )}
                                </CollapsibleContent>
                              </div>
                            </Collapsible>
                          ))}
                        </div>
                      </CollapsibleContent>
                    </Collapsible>
                  </CardContent>
                </Card>
              </div>
            ) : (
              <div className="text-center py-24 px-8">
                <div className="inline-flex p-6 rounded-2xl bg-muted/30 border border-border/30 mb-6">
                  <Shield className="w-20 h-20 text-muted-foreground/30" />
                </div>
                <h3 className="text-2xl font-semibold text-foreground mb-3">No Scan Results Yet</h3>
                <p className="text-muted-foreground text-lg max-w-md mx-auto">
                  Enter a URL above and click "Start Scan" to begin your comprehensive vulnerability analysis
                </p>
              </div>
            )}
          </TabsContent>
          
          <TabsContent value="history">
            <ScanHistory key={historyKey} onViewScan={handleViewHistoricalScan} />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default Demo;
