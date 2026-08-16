const outputSchemaVersion = 1

const colors = {
  critical: "\u001b[31;1m",
  high: "\u001b[31m",
  medium: "\u001b[33m",
  low: "\u001b[36m",
  success: "\u001b[32m",
  dim: "\u001b[2m",
  reset: "\u001b[0m"
}

const paint = (value, color, enabled) => enabled ? `${colors[color]}${value}${colors.reset}` : value

export const formatText = (result, { color = true } = {}) => {
  const output = []

  if (result.findings.length === 0) {
    output.push(`${paint("OK", "success", color)} No unapproved findings`)
  } else {
    for (const finding of result.findings) {
      const location = finding.line ? `${finding.file}:${finding.line}` : finding.file
      output.push(`${paint(finding.severity.toUpperCase().padEnd(8), finding.severity, color)} ${location}`)
      output.push(`         ${finding.description} ${paint(`[${finding.rule}]`, "dim", color)}`)
    }
  }

  for (const diagnostic of result.diagnostics) {
    output.push(`${paint(diagnostic.severity.toUpperCase().padEnd(8), diagnostic.severity === "error" ? "high" : "medium", color)} ${diagnostic.file}`)
    output.push(`         ${diagnostic.message} ${paint(`[${diagnostic.code}]`, "dim", color)}`)
  }

  const { files, bytes, skipped, ignored, baselined, errors } = result.stats
  const size = bytes < 1_000_000 ? `${Math.ceil(bytes / 1000)} kB` : `${(bytes / 1_000_000).toFixed(1)} MB`
  output.push("")
  output.push(`${result.findings.length} finding${result.findings.length === 1 ? "" : "s"} in ${files} files (${size}), ${skipped} skipped, ${ignored} ignored, ${baselined} baselined, ${errors} error${errors === 1 ? "" : "s"}`)
  return output.join("\n")
}

export const formatJson = result => JSON.stringify({
  schemaVersion: outputSchemaVersion,
  version: outputSchemaVersion,
  input: result.input,
  findings: result.findings,
  diagnostics: result.diagnostics,
  stats: result.stats
}, null, 2)

const sarifLevel = severity => severity === "critical" || severity === "high" ? "error" : severity === "medium" ? "warning" : "note"

export const formatSarif = (result, version) => {
  const rules = new Map()
  for (const finding of result.findings) {
    if (!rules.has(finding.rule)) {
      rules.set(finding.rule, {
        id: finding.rule,
        shortDescription: { text: finding.description },
        properties: { category: finding.category, severity: finding.severity }
      })
    }
  }

  return JSON.stringify({
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "ShareGuard",
          informationUri: "https://github.com/6fmh/shareguard-cli",
          semanticVersion: version,
          rules: [...rules.values()]
        }
      },
      results: result.findings.map(finding => ({
        ruleId: finding.rule,
        level: sarifLevel(finding.severity),
        message: { text: finding.description },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: encodeURI(finding.file.replaceAll("\\", "/")) },
            ...(finding.line ? { region: { startLine: finding.line } } : {})
          }
        }],
        partialFingerprints: { shareGuardFingerprint: finding.fingerprint },
        properties: { category: finding.category, severity: finding.severity }
      })),
      invocations: [{
        executionSuccessful: result.stats.errors === 0,
        toolExecutionNotifications: result.diagnostics.map(diagnostic => ({
          level: diagnostic.severity === "error" ? "error" : "warning",
          message: { text: diagnostic.message },
          descriptor: { id: diagnostic.code },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: encodeURI(diagnostic.file.replaceAll("\\", "/")) }
            }
          }]
        }))
      }]
    }]
  }, null, 2)
}
