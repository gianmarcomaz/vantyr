// Standard deductions applied uniformly across ALL categories
const SEVERITY_DEDUCTIONS = {
  critical: 25,
  high: 15,
  medium: 5,
  low: 3,
  info: 0
};

export function calculateTrustScore(allFindings) {
  // Group findings by category
  const categories = {
    NE: { findings: [], score: 100 },
    CI: { findings: [], score: 100 },
    CL: { findings: [], score: 100 },
    TP: { findings: [], score: 100 },
    SC: { findings: [], score: 100 },
    IV: { findings: [], score: 100 }
  };

  for (const finding of allFindings) {
    if (categories[finding.category]) {
      categories[finding.category].findings.push(finding);
    }
  }

  // Calculate per-category scores using IDENTICAL math for every category
  for (const [key, cat] of Object.entries(categories)) {
    let deduction = 0;
    for (const finding of cat.findings) {
      deduction += SEVERITY_DEDUCTIONS[finding.severity] || 0;
    }
    cat.score = Math.max(0, 100 - deduction);
  }

  // Weighted average using OWASP-aligned weights
  const WEIGHTS = {
    CL: 0.25,  // Credential Leaks — OWASP MCP01 (#1)
    CI: 0.20,  // Command Injection — OWASP MCP05 (#5)
    NE: 0.15,  // Network Exposure — OWASP MCP07 (#7)
    IV: 0.15,  // Input Validation — SSRF/Path Traversal
    TP: 0.15,  // Tool Poisoning — OWASP MCP03 (#3)
    SC: 0.10   // Spec Compliance — Protocol hygiene
  };

  let weightedSum = 0;
  for (const [key, weight] of Object.entries(WEIGHTS)) {
    weightedSum += categories[key].score * weight;
  }

  let trustScore = Math.round(weightedSum);

  // Count totals
  let totalFindings = allFindings.length;
  let criticalCount = allFindings.filter(f => f.severity === 'critical').length;
  let highCount = allFindings.filter(f => f.severity === 'high').length;
  let mediumCount = allFindings.filter(f => f.severity === 'medium').length;
  let lowCount = allFindings.filter(f => f.severity === 'low').length;
  let infoCount = allFindings.filter(f => f.severity === 'info').length;

  // A repo with any HIGH or CRITICAL finding cannot be CERTIFIED.
  // Cap the Trust Score at 75 so the label always falls into WARNING or FAILED,
  // regardless of how clean the other categories are.
  const hasCriticalOrHigh = criticalCount > 0 || highCount > 0;
  let scoreCapped = false;
  if (hasCriticalOrHigh && trustScore > 75) {
    trustScore = 75;
    scoreCapped = true;
  }

  // Determine pass count (categories scoring >= 80)
  let passCount = Object.values(categories).filter(c => c.score >= 80).length;

  return {
    trustScore,
    categories,
    totalFindings,
    stats: { critical: criticalCount, high: highCount, medium: mediumCount, low: lowCount, info: infoCount },
    passCount,
    scoreCapped
  };
}
