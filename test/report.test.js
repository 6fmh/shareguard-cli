import test from "node:test"
import assert from "node:assert/strict"
import { readFile, rm } from "node:fs/promises"
import path from "node:path"
import { parseArgs, resolveReports } from "../src/cli.js"
import { fixture, generated, runCli } from "./helpers.js"

test("parses report, since, and quiet options", () => {
  const options = parseArgs(["scan", "repo", "--since", "origin/main", "--quiet", "--report", "markdown:summary.md", "--report", "csv"])

  assert.equal(options.since, "origin/main")
  assert.equal(options.quiet, true)
  assert.deepEqual(options.reports, [{ format: "markdown", file: "summary.md" }, { format: "csv", file: undefined }])
})

test("rejects invalid reports and incompatible sources", () => {
  assert.throws(() => parseArgs(["--report", "xml"]), /--report format must be/)
  assert.throws(() => parseArgs(["--report", "markdown:"]), /requires a file path/)
  assert.throws(() => parseArgs(["--format", "yaml"]), /--format must be/)
  assert.throws(() => parseArgs(["--since", "main", "--staged"]), /cannot be used together/)
  assert.throws(() => parseArgs(["--since", "main", "--stdin"]), /cannot be used together/)
})

test("keeps the primary report only when a format or output is requested", () => {
  assert.deepEqual(resolveReports(parseArgs([])), [{ format: "text", file: undefined }])
  assert.deepEqual(resolveReports(parseArgs(["--report", "csv:findings.csv"])), [{ format: "csv", file: "findings.csv" }])
  assert.deepEqual(resolveReports(parseArgs(["--json", "--report", "csv:findings.csv"])), [
    { format: "json", file: undefined },
    { format: "csv", file: "findings.csv" }
  ])
  assert.throws(() => resolveReports(parseArgs(["--output", "out.txt", "--report", "csv:out.txt"])), /different file/)
})

test("writes several report formats from one scan", async t => {
  const credential = generated("npm_", 36)
  const root = await fixture({ "settings.js": `const token = "${credential}"\n` })
  const sarifFile = path.join(root, "result.sarif")
  const markdownFile = path.join(root, "summary.md")
  const junitFile = path.join(root, "result.xml")
  t.after(() => rm(root, { recursive: true, force: true }))

  const result = await runCli([
    root, "--sarif", "--output", sarifFile,
    "--report", `markdown:${markdownFile}`,
    "--report", `junit:${junitFile}`,
    "--report", "github",
    "--no-gitignore"
  ])
  const [sarif, markdown, junit] = await Promise.all([sarifFile, markdownFile, junitFile].map(file => readFile(file, "utf8")))

  assert.equal(result.status, 1)
  assert.match(result.stdout, /^::error file=settings.js,line=1/m)
  assert.equal(JSON.parse(sarif).version, "2.1.0")
  assert.match(markdown, /\| CRITICAL \| `settings.js:1` \| `npm-token` \|/)
  assert.match(junit, /<testsuites name="ShareGuard"/)
  for (const output of [result.stdout, sarif, markdown, junit]) assert.equal(output.includes(credential), false)
})

test("supports none as a fail-on threshold and quiet output", async t => {
  const root = await fixture({ "settings.js": `const token = "${generated("npm_", 36)}"\n` })
  t.after(() => rm(root, { recursive: true, force: true }))

  const permissive = await runCli([root, "--fail-on", "none", "--no-gitignore", "--no-color", "--quiet"])

  assert.equal(permissive.status, 0)
  assert.match(permissive.stdout, /npm-token/)
  assert.equal(permissive.stdout.includes("findings in"), false)
})

test("lists every rule as text and JSON", async () => {
  const text = await runCli(["--list-rules"])
  const json = await runCli(["--list-rules", "--json"])
  const listed = JSON.parse(json.stdout)

  assert.equal(text.status, 0)
  assert.match(text.stdout, /^generic-secret\s+secret\s+high\s+Hard-coded credential$/m)
  assert.equal(listed.schemaVersion, 1)
  assert.equal(listed.rules.length, text.stdout.trim().split("\n").length)
  assert.equal(listed.rules.every(rule => rule.id && rule.category && rule.severity && rule.description), true)
})
