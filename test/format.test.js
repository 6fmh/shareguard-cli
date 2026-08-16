import test from "node:test"
import assert from "node:assert/strict"
import { formatJson, formatSarif, formatText } from "../src/format.js"

const result = {
  input: "filesystem",
  findings: [{ rule: "generic-secret", category: "secret", severity: "high", description: "Hard-coded credential", file: "src/app.js", line: 4, preview: null, fingerprint: "abc123" }],
  diagnostics: [],
  stats: { files: 1, bytes: 100, skipped: 0, ignored: 0, symlinks: 0, errors: 0, baselined: 0 }
}

test("formats stable JSON without a scan root", () => {
  const output = JSON.parse(formatJson(result))

  assert.equal(output.schemaVersion, 1)
  assert.equal(output.version, 1)
  assert.equal(output.input, "filesystem")
  assert.equal(Object.hasOwn(output, "root"), false)
})

test("formats SARIF 2.1 with relative locations and fingerprints", () => {
  const output = JSON.parse(formatSarif(result, "0.2.0"))
  const sarifResult = output.runs[0].results[0]

  assert.equal(output.version, "2.1.0")
  assert.equal(output.runs[0].tool.driver.semanticVersion, "0.2.0")
  assert.equal(sarifResult.locations[0].physicalLocation.artifactLocation.uri, "src/app.js")
  assert.equal(sarifResult.partialFingerprints.shareGuardFingerprint, "abc123")
})

test("text output contains metadata but no source preview", () => {
  const output = formatText(result, { color: false })

  assert.match(output, /src\/app.js:4/)
  assert.match(output, /generic-secret/)
  assert.equal(output.includes("preview"), false)
})
