import test from "node:test"
import assert from "node:assert/strict"
import { formatCsv, formatGithub, formatJunit, formatMarkdown } from "../src/format.js"

const stats = { files: 2, bytes: 2048, skipped: 1, ignored: 0, symlinks: 0, suppressed: 1, errors: 1, baselined: 0 }

const finding = (overrides = {}) => ({
  rule: "generic-secret",
  category: "secret",
  severity: "high",
  description: "Hard-coded credential",
  file: "src/app.js",
  line: 7,
  preview: null,
  fingerprint: "abc123",
  ...overrides
})

const result = {
  input: "filesystem",
  findings: [
    finding(),
    finding({ rule: "ipv4-address", category: "privacy", severity: "low", description: "IPv4 address", file: "notes, draft.txt", line: null })
  ],
  diagnostics: [{ code: "unreadable-file", severity: "error", file: "locked.bin", message: "Could not read file" }],
  stats
}

test("emits GitHub annotations with escaped properties", () => {
  const output = formatGithub(result)
  const lines = output.split("\n")

  assert.equal(lines[0], "::error file=src/app.js,line=7,title=ShareGuard high%3A generic-secret::Hard-coded credential [generic-secret]")
  assert.equal(lines[1].startsWith("::notice file=notes%2C draft.txt,title="), true)
  assert.equal(lines[1].includes("line="), false)
  assert.equal(lines[2], "::error file=locked.bin,title=ShareGuard unreadable-file::Could not read file")
  assert.match(lines[3], /^2 findings in 2 files/)
  assert.equal(formatGithub(result, { quiet: true }).split("\n").length, 3)
})

test("escapes annotation data that could inject workflow commands", () => {
  const injected = formatGithub({
    ...result,
    findings: [finding({ description: "100% risky\n::error::spoofed", file: "a,b:c.txt" })],
    diagnostics: []
  })

  assert.equal(injected.includes("\n::error::spoofed"), false)
  assert.match(injected, /100%25 risky%0A::error::spoofed/)
  assert.match(injected, /file=a%2Cb%3Ac.txt/)
})

test("escapes Markdown table cells and reports diagnostics", () => {
  const output = formatMarkdown({
    ...result,
    findings: [finding({ description: "Credential | pipe" })]
  })

  assert.match(output, /^## ShareGuard$/m)
  assert.match(output, /Credential &#124; pipe/)
  assert.match(output, /\| `unreadable-file` \| `locked.bin` \| Could not read file \|/)
  assert.match(output, /Matched values are never included/)
})

test("writes CSV rows that cannot execute in a spreadsheet", () => {
  const output = formatCsv({
    ...result,
    findings: [finding({ description: "=cmd|' /c calc", file: "a,b.txt" })]
  })
  const rows = output.split("\n")

  assert.equal(rows[0], "type,severity,category,rule,description,file,line,fingerprint")
  assert.equal(rows[1], `finding,high,secret,generic-secret,'=cmd|' /c calc,"a,b.txt",7,abc123`)
  assert.equal(rows[2].startsWith("diagnostic,error,,unreadable-file,"), true)
})

test("writes JUnit XML with escaped text and no control characters", () => {
  const bell = String.fromCharCode(7)
  const output = formatJunit({
    ...result,
    findings: [finding({ description: `value <tag> & control${bell}` })]
  }, "0.4.0")

  assert.match(output, /^<\?xml version="1.0" encoding="UTF-8"\?>$/m)
  assert.match(output, /<testsuites name="ShareGuard" tests="2" failures="1" errors="1">/)
  assert.match(output, /value &lt;tag&gt; &amp; control/)
  assert.equal(output.includes(bell), false)
  assert.match(formatJunit({ ...result, findings: [], diagnostics: [] }, "0.4.0"), /<testcase name="no unapproved findings"/)
})
