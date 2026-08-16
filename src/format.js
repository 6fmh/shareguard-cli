const colors = {
  critical: "\u001b[31;1m",
  high: "\u001b[31m",
  medium: "\u001b[33m",
  low: "\u001b[36m",
  dim: "\u001b[2m",
  reset: "\u001b[0m"
}

const paint = (value, color, enabled) => enabled ? `${colors[color]}${value}${colors.reset}` : value

export const formatText = (result, { color = true } = {}) => {
  const output = []

  if (result.findings.length === 0) {
    output.push(`${paint("OK", "medium", color)} No unapproved findings`)
  } else {
    for (const finding of result.findings) {
      const location = finding.line ? `${finding.file}:${finding.line}` : finding.file
      output.push(`${paint(finding.severity.toUpperCase().padEnd(8), finding.severity, color)} ${location}`)
      output.push(`         ${finding.description} ${paint(`[${finding.rule}]`, "dim", color)}`)
      if (finding.preview) output.push(`         ${paint(finding.preview, "dim", color)}`)
    }
  }

  const { files, bytes, skipped, baselined } = result.stats
  const size = bytes < 1_000_000 ? `${Math.ceil(bytes / 1000)} kB` : `${(bytes / 1_000_000).toFixed(1)} MB`
  output.push("")
  output.push(`${result.findings.length} finding${result.findings.length === 1 ? "" : "s"} in ${files} files (${size}), ${skipped} skipped, ${baselined} baselined`)
  return output.join("\n")
}

export const formatJson = result => JSON.stringify({
  version: 1,
  findings: result.findings,
  stats: result.stats
}, null, 2)
