import { ruleById } from "./rules.js"

const outputSchemaVersion = 1
const documentationUri = "https://github.com/6fmh/shareguard-cli/blob/main/docs/RULES.md"

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

const readableSize = bytes => bytes < 1_000_000 ? `${Math.ceil(bytes / 1000)} kB` : `${(bytes / 1_000_000).toFixed(1)} MB`

export const summarize = result => {
  const { files, bytes, skipped, ignored, suppressed = 0, baselined, errors } = result.stats
  const count = result.findings.length
  return `${count} finding${count === 1 ? "" : "s"} in ${files} files (${readableSize(bytes)}), ${skipped} skipped, ${ignored} ignored, ${suppressed} suppressed, ${baselined} baselined, ${errors} error${errors === 1 ? "" : "s"}`
}

export const formatText = (result, { color = true, quiet = false } = {}) => {
  const output = []

  if (result.findings.length === 0) {
    if (!quiet) output.push(`${paint("OK", "success", color)} No unapproved findings`)
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

  if (!quiet) {
    output.push("")
    output.push(summarize(result))
  }
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
    if (rules.has(finding.rule)) continue
    const definition = ruleById.get(finding.rule)
    rules.set(finding.rule, {
      id: finding.rule,
      name: finding.rule,
      shortDescription: { text: finding.description },
      fullDescription: { text: `${definition?.description ?? finding.description}. ShareGuard reports the location, rule, and severity only; the matched value is never included.` },
      helpUri: `${documentationUri}#${finding.rule}`,
      defaultConfiguration: { level: sarifLevel(finding.severity) },
      properties: { category: finding.category, severity: finding.severity, tags: [finding.category, finding.severity] }
    })
  }

  return JSON.stringify({
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      properties: { stats: result.stats },
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

const githubLevel = severity => severity === "critical" || severity === "high" ? "error" : severity === "medium" ? "warning" : "notice"
const commandData = value => String(value ?? "").replaceAll("%", "%25").replaceAll("\r", "%0D").replaceAll("\n", "%0A")
const commandProperty = value => commandData(value).replaceAll(":", "%3A").replaceAll(",", "%2C")

export const formatGithub = (result, { quiet = false } = {}) => {
  const output = []

  for (const finding of result.findings) {
    const properties = [`file=${commandProperty(finding.file)}`]
    if (finding.line) properties.push(`line=${finding.line}`)
    properties.push(`title=${commandProperty(`ShareGuard ${finding.severity}: ${finding.rule}`)}`)
    output.push(`::${githubLevel(finding.severity)} ${properties.join(",")}::${commandData(`${finding.description} [${finding.rule}]`)}`)
  }

  for (const diagnostic of result.diagnostics) {
    const level = diagnostic.severity === "error" ? "error" : "warning"
    const properties = `file=${commandProperty(diagnostic.file)},title=${commandProperty(`ShareGuard ${diagnostic.code}`)}`
    output.push(`::${level} ${properties}::${commandData(diagnostic.message)}`)
  }

  if (!quiet) output.push(summarize(result))
  return output.join("\n")
}

const markdownCell = value => String(value ?? "").replaceAll(/[\r\n]+/g, " ").replaceAll("|", "&#124;")

export const formatMarkdown = result => {
  const output = ["## ShareGuard", "", summarize(result), ""]

  if (result.findings.length > 0) {
    output.push("| Severity | Location | Rule | Description |", "| --- | --- | --- | --- |")
    for (const finding of result.findings) {
      const location = finding.line ? `${finding.file}:${finding.line}` : finding.file
      output.push(`| ${finding.severity.toUpperCase()} | \`${markdownCell(location)}\` | \`${markdownCell(finding.rule)}\` | ${markdownCell(finding.description)} |`)
    }
    output.push("")
  }

  if (result.diagnostics.length > 0) {
    output.push("| Diagnostic | File | Message |", "| --- | --- | --- |")
    for (const diagnostic of result.diagnostics) {
      output.push(`| \`${markdownCell(diagnostic.code)}\` | \`${markdownCell(diagnostic.file)}\` | ${markdownCell(diagnostic.message)} |`)
    }
    output.push("")
  }

  output.push("Matched values are never included in ShareGuard output.")
  return output.join("\n")
}

const csvField = value => {
  const text = String(value ?? "")
  const guarded = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text
  return /[",\r\n]/.test(guarded) ? `"${guarded.replaceAll('"', '""')}"` : guarded
}

export const formatCsv = result => {
  const rows = [["type", "severity", "category", "rule", "description", "file", "line", "fingerprint"]]

  for (const finding of result.findings) {
    rows.push(["finding", finding.severity, finding.category, finding.rule, finding.description, finding.file, finding.line ?? "", finding.fingerprint])
  }
  for (const diagnostic of result.diagnostics) {
    rows.push(["diagnostic", diagnostic.severity, "", diagnostic.code, diagnostic.message, diagnostic.file, "", ""])
  }

  return rows.map(row => row.map(csvField).join(",")).join("\n")
}

const xmlText = value => [...String(value ?? "")]
  .filter(character => character >= " " || character === "\t" || character === "\n")
  .join("")
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&apos;")

export const formatJunit = (result, version) => {
  const failures = result.findings.length
  const errors = result.diagnostics.filter(diagnostic => diagnostic.severity === "error").length
  const total = failures + result.diagnostics.length
  const cases = []

  for (const finding of result.findings) {
    const location = finding.line ? `${finding.file}:${finding.line}` : finding.file
    cases.push(`    <testcase name="${xmlText(`${finding.rule} ${location}`)}" classname="shareguard.${xmlText(finding.category)}">`)
    cases.push(`      <failure type="${xmlText(finding.severity)}" message="${xmlText(finding.description)}">${xmlText(`${finding.description} [${finding.rule}] at ${location} fingerprint=${finding.fingerprint}`)}</failure>`)
    cases.push("    </testcase>")
  }

  for (const diagnostic of result.diagnostics) {
    cases.push(`    <testcase name="${xmlText(`${diagnostic.code} ${diagnostic.file}`)}" classname="shareguard.diagnostic">`)
    cases.push(`      <error type="${xmlText(diagnostic.severity)}" message="${xmlText(diagnostic.message)}">${xmlText(`${diagnostic.message} [${diagnostic.code}] at ${diagnostic.file}`)}</error>`)
    cases.push("    </testcase>")
  }

  if (total === 0) cases.push('    <testcase name="no unapproved findings" classname="shareguard"/>')

  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    `<testsuites name="ShareGuard" tests="${Math.max(total, 1)}" failures="${failures}" errors="${errors}">`,
    `  <testsuite name="shareguard" tests="${Math.max(total, 1)}" failures="${failures}" errors="${errors}" time="0">`,
    "    <properties>",
    `      <property name="shareguard.version" value="${xmlText(version)}"/>`,
    `      <property name="shareguard.input" value="${xmlText(result.input)}"/>`,
    "    </properties>",
    ...cases,
    "  </testsuite>",
    "</testsuites>"
  ].join("\n")
}
