# SentinelX: Project Journal & Record of Activities
**Student Name:** Armaan
**Project:** SentinelX - Next-Gen Active Vulnerability Scanner
**Duration:** September 2025 - January 2026

---

## 📅 September 2025: Research & Feasibility Analysis
**Focus:** Problem definition, literature review, and architectural planning.

*   **Week 1: Problem Statement Formulation**
    *   Analyzed current limitations in existing DAST tools (OWASP ZAP, Burp Suite).
    *   Identified correct problem scope: "Static scanners lack context; Active scanners lack remediation."
    *   Formulated the core hypothesis: "Feedback-driven fuzzing coupled with LLMs can autofix vulnerabilities."

*   **Week 2: Literature Review**
    *   Studied academic papers on "Feedback-Driven Fuzzing" and "Automated Program Repair."
    *   Researched the difference between Signature-based detection vs. Heuristic behavior analysis.
    *   Selected "OWASP Top 10" as the primary vulnerability dataset for coverage.

*   **Week 3: Tech Stack Selection & Validation**
    *   Evaluated runtimes: Node.js vs. Deno. Selected **Deno** (Supabase Edge Functions) for its secure V8 sandbox and native TypeScript support.
    *   Selected **React (Vite)** for the frontend due to strict CSP capabilities.
    *   Selected **Supabase** for Backend-as-a-Service (Auth + Database).

*   **Week 4: Architecture Design (High Level)**
    *   Designed the "Monolithic-on-Edge" architecture to reduce cold starts.
    *   Drafted the "Scanner Module Strategy" (Abstract Base Classes for polymorphism).
    *   Created the initial Database Schema (ER Diagram) for storing Scan Results and User Profiles.

---

## 📅 October 2025: Backend Core Development
**Focus:** Building the scanning engine and network layer.

*   **Week 1: Edge Function Environment Setup**
    *   Initialized the Supabase local development environment (`supabase start`).
    *   Created the main entry point `vulnerability-scan/index.ts`.
    *   Implemented CORS handling and secure Environment Variable management.

*   **Week 2: Custom Networking Layer**
    *   Built the `HttpClient` class.
    *   Solved challenges with Cookie persistence (Cookie Jar implementation) for session-based scanning.
    *   Implemented retry logic and timeout handling for unstable target servers.

*   **Week 3: Core Scanner Implementation (SQLi & XSS)**
    *   Developed the `ActiveScannerBase` abstract class.
    *   Implemented the **SQL Injection Module**: Created payload dictionaries for syntax errors.
    *   Implemented the **Reflected XSS Module**: Built logic to detect specific probe strings in HTTP responses.

*   **Week 4: The Crawler Engine**
    *   Built the recursive `Crawler` class to discover attack surfaces.
    *   Implemented logic to extract `href` links and `form` actions from HTML.
    *   Added depth-limiting logic (max depth 2) to prevent infinite loops.

---

## 📅 November 2025: Advanced Heuristics & AI Integration
**Focus:** Enhancing detection accuracy and adding remediation.

*   **Week 1: Advanced Attack Vectors**
    *   Implemented **Time-Based Blind SQLi**: Created logic to measure HTTP response timing deviations (delta > 5000ms).
    *   Added **Headers Scanner**: Checks for CSP, X-Frame-Options, and HSTS.

*   **Week 2: Payload Mutation Engine**
    *   Developed a `PayloadMutator` to dynamically alter attack strings (encoding, bypassing WAFs).
    *   Refined the regex patterns in `signatures.ts` to reduce false positives.

*   **Week 3: AI Remediation Integration**
    *   Designed the interface for the AI Agent.
    *   Integrated OpenAI API (GPT-4o) to analyze vulnerability metadata.
    *   Engineered the prompt structure to generate unified `diff` patches for code fixes.

*   **Week 4: "Dynamic Oracle" Verification**
    *   Built the verification step: When a vulnerability is found, the scanner attempts to "verify" it by sending a benign probe.
    *   Refined scoring algorithms (CVSS v3.1 alignment).

---

## 📅 December 2025: Frontend Development & UI/UX
**Focus:** Visualization, dashboard, and user experience.

*   **Week 1: Dashboard Architecture**
    *   Initialized the React project with Vite and Tailwind CSS.
    *   Implemented Client-side Routing (React Router) and Authentication context.
    *   Designed the "Cybersecurity Aesthetic" theme using `shadcn/ui` components.

*   **Week 2: Real-time Scanning Interface**
    *   Built the "Terminal View" in the UI to show live logs.
    *   Implemented the Scanning Progress Bar and State Management using React Query.
    *   Connected the Frontend `supabase-js` client to the Backend Edge Function.

*   **Week 3: Data Visualization**
    *   Integrated **Recharts** library.
    *   Built the Severity Distribution Pie Chart and Attack Surface Bar Chart.
    *   Implemented the "Confidence Gauge" logic.

*   **Week 4: Reporting Module**
    *   Created the scan details view (Findings tab, Evidence tab).
    *   Implemented the "Attack Path" visualization (Node-link diagram).
    *   Added simulated "history" handling using LocalStorage for the demo.

---

## 📅 January 2026: Testing, Optimization & Final Polish
**Focus:** System integration testing and preparing for the final presentation.

*   **Week 1: Final Integration & Polish**
    *   **Performance Tuning:** Optimized the Edge Function concurrency (Promise.all) to reduce scan time.
    *   **Bug Fixing:** Resolved issues with Tab navigation and State persistence in the Demo page.
    *   **Simulation Mode:** Refined the Demo Simulation (`simulateVulnerabilityScan`) for consistent presentation results.
    *   **Documentation:** Finalized the README, Architecture diagrams, and this Project Journal.
