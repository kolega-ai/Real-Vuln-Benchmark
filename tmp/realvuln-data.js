/* ============================================================
   RealVuln — canonical results data (single source of truth)
   Source: live dashboard, kolega-ai/Real-Vuln-Benchmark reports/.
   Scored set: 26 repos · 697 vulnerabilities · 120 FP traps · 20,062 Python LOC.
   Ranking metric on the live dashboard: F3 (strict). Standard + strict both retained.
   Fields per scanner:
     name, cat (sec|llm|rule), ver, repos (completed of 26),
     f2/f2s  = F2 standard / strict
     f3/f3s  = F3 standard / strict
     rec/recs= recall standard / strict (fraction 0–1)
     prec    = precision (unchanged by mode)
     cost    = USD total for the run (null where not published / free tools)
   ============================================================ */
(function () {
  var S = [
    { name: 'Kolega Enterprise',     cat: 'sec',  ver: 'enterprise-v1', repos: 26, f2: 89.7, f2s: 89.7, f3: 92.4, f3s: 92.4, rec: 0.953, recs: 0.953, prec: 0.727, cost: null },
    { name: 'Kolega.Dev',            cat: 'sec',  ver: 'v0.0.1',        repos: 26, f2: 66.8, f2s: 66.8, f3: 73.0, f3s: 73.0, rec: 0.805, recs: 0.805, prec: 0.398, cost: 25.0 },
    { name: 'GPT-5.5',               cat: 'llm',  ver: 'agentic-v1',    repos: 26, f2: 62.1, f2s: 62.1, f3: 60.2, f3s: 60.2, rec: 0.584, recs: 0.584, prec: 0.832, cost: 66.45 },
    { name: 'GLM-5.1',               cat: 'llm',  ver: 'agentic-v1',    repos: 25, f2: 59.7, f2s: 58.6, f3: 58.3, f3s: 57.1, rec: 0.570, recs: 0.557, prec: 0.741, cost: 9.91 },
    { name: 'DeepSeek V4 Flash',     cat: 'llm',  ver: 'agentic-v1',    repos: 26, f2: 58.1, f2s: 58.1, f3: 56.5, f3s: 56.5, rec: 0.549, recs: 0.549, prec: 0.752, cost: 0.89 },
    { name: 'Kimi K2.6',             cat: 'llm',  ver: 'agentic-v1',    repos: 25, f2: 58.1, f2s: 55.8, f3: 56.3, f3s: 53.9, rec: 0.546, recs: 0.521, prec: 0.786, cost: 4.91 },
    { name: 'Claude Opus 4.8',       cat: 'llm',  ver: 'agentic-v1',    repos: 26, f2: 55.7, f2s: 55.7, f3: 53.6, f3s: 53.6, rec: 0.516, recs: 0.516, prec: 0.807, cost: 35.65 },
    { name: 'DeepSeek V4 Pro',       cat: 'llm',  ver: 'agentic-v1',    repos: 26, f2: 55.0, f2s: 55.0, f3: 52.9, f3s: 52.9, rec: 0.511, recs: 0.511, prec: 0.789, cost: 8.99 },
    { name: 'Claude Sonnet 4.6',     cat: 'llm',  ver: 'agentic-v1',    repos: 23, f2: 57.1, f2s: 53.0, f3: 55.2, f3s: 50.9, rec: 0.534, recs: 0.489, prec: 0.797, cost: 16.60 },
    { name: 'Gemini 3.1 Pro',        cat: 'llm',  ver: 'agentic-v1',    repos: 24, f2: 55.2, f2s: 51.8, f3: 53.3, f3s: 49.7, rec: 0.515, recs: 0.478, prec: 0.776, cost: 27.24 },
    { name: 'Gemini 3.5 Flash',      cat: 'llm',  ver: 'agentic-v1',    repos: 26, f2: 50.0, f2s: 50.0, f3: 47.6, f3s: 47.6, rec: 0.454, recs: 0.454, prec: 0.840, cost: 27.99 },
    { name: 'Claude Opus 4.7',       cat: 'llm',  ver: 'agentic-v1',    repos: 25, f2: 54.7, f2s: 49.4, f3: 53.1, f3s: 47.5, rec: 0.516, recs: 0.458, prec: 0.715, cost: 26.92 },
    { name: 'Claude Opus 4.6',       cat: 'llm',  ver: 'agentic-v1',    repos: 19, f2: 61.4, f2s: 49.4, f3: 59.7, f3s: 47.2, rec: 0.580, recs: 0.451, prec: 0.799, cost: 22.41 },
    { name: 'Kimi K2.5',             cat: 'llm',  ver: 'agentic-v1',    repos: 24, f2: 50.9, f2s: 47.8, f3: 49.3, f3s: 46.0, rec: 0.478, recs: 0.443, prec: 0.693, cost: 2.17 },
    { name: 'GLM-5',                 cat: 'llm',  ver: 'agentic-v1',    repos: 22, f2: 53.8, f2s: 47.2, f3: 51.9, f3s: 45.1, rec: 0.501, recs: 0.431, prec: 0.767, cost: 6.13 },
    { name: 'Minimax M2.7',          cat: 'llm',  ver: 'agentic-v1',    repos: 22, f2: 46.7, f2s: 40.2, f3: 44.8, f3s: 38.2, rec: 0.430, recs: 0.363, prec: 0.713, cost: 0.72 },
    { name: 'Qwen 3.5 397B',         cat: 'llm',  ver: 'agentic-v1',    repos: 24, f2: 42.6, f2s: 39.9, f3: 40.9, f3s: 38.2, rec: 0.394, recs: 0.365, prec: 0.636, cost: 2.84 },
    { name: 'Claude Haiku 4.5',      cat: 'llm',  ver: 'agentic-v1',    repos: 24, f2: 41.3, f2s: 38.6, f3: 39.1, f3s: 36.4, rec: 0.371, recs: 0.344, prec: 0.752, cost: 5.24 },
    { name: 'Grok 4.20 Reasoning',   cat: 'llm',  ver: 'agentic-v1',    repos: 24, f2: 32.2, f2s: 30.0, f3: 29.8, f3s: 27.7, rec: 0.277, recs: 0.257, prec: 0.932, cost: 16.82 },
    { name: 'Claude Haiku 4.5',      cat: 'llm',  ver: 'direct-v1',     repos: 23, f2: 29.4, f2s: 26.8, f3: 28.1, f3s: 25.4, rec: 0.268, recs: 0.241, prec: 0.487, cost: 4.94 },
    { name: 'Grok 3',                cat: 'llm',  ver: 'agentic-v1',    repos: 21, f2: 27.5, f2s: 22.9, f3: 25.4, f3s: 21.0, rec: 0.236, recs: 0.193, prec: 0.844, cost: 4.57 },
    { name: 'Semgrep',               cat: 'rule', ver: 'rule-based',    repos: 25, f2: 20.3, f2s: 19.8, f3: 19.9, f3s: 19.4, rec: 0.197, recs: 0.191, prec: 0.231, cost: null },
    { name: 'Snyk Code',             cat: 'rule', ver: 'pattern+flow',  repos: 25, f2: 19.3, f2s: 18.8, f3: 18.5, f3s: 18.0, rec: 0.177, recs: 0.172, prec: 0.299, cost: null },
    { name: 'SonarQube',             cat: 'rule', ver: 'community',     repos: 26, f2: 7.7,  f2s: 7.7,  f3: 6.9,  f3s: 6.9,  rec: 0.063, recs: 0.063, prec: 0.611, cost: null }
  ];

  // per-CWE-family recall (%) — best LLM-based vs best rule-based, from live per-CWE matrix
  var CWE = [
    { label: 'SQL injection',          cwe: 'CWE-89',        llm: 99, rule: 32 },
    { label: 'Command / OS injection', cwe: 'CWE-77 · 78',   llm: 94, rule: 41 },
    { label: 'Insecure deserialization', cwe: 'CWE-502',     llm: 100, rule: 18 },
    { label: 'Cross-site scripting',   cwe: 'CWE-79',        llm: 69, rule: 22 },
    { label: 'Code injection / RFI',   cwe: 'CWE-94 · 98',   llm: 100, rule: 38 }
  ];

  window.RV = {
    SCANNERS: S,
    CWE: CWE,
    CAT_LABEL: { sec: 'Security-Specialized', llm: 'General-Purpose LLM', rule: 'Rule-Based SAST' },
    CAT_SHORT: { sec: 'Sec.-spec.', llm: 'GP-LLM', rule: 'Rule SAST' },
    COL: { sec: '#cfa45c', llm: '#7e9fc4', rule: '#8c8478' },
    DATASET: { repos: 26, vulns: 697, traps: 120, loc: 20062, scanners: 24, families: 18 }
  };
})();
