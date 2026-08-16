import test from "node:test"
import assert from "node:assert/strict"
import { readFile, rm } from "node:fs/promises"
import path from "node:path"
import { Readable } from "node:stream"
import { run } from "../src/cli.js"
import { fixture, generated } from "./helpers.js"

const runCli = async (args, options = {}) => {
  let stdout = ""
  const io = {
    stdin: Readable.from(options.input === undefined ? [] : [Buffer.from(options.input)]),
    stdout: { write: value => { stdout += value } }
  }
  try {
    return { status: await run(args, io), stdout, stderr: "" }
  } catch (error) {
    return { status: 2, stdout, stderr: error.message }
  }
}

test("scans stdin with stable JSON and complete redaction", async () => {
  const secret = generated("", 40)
  const result = await runCli(["--stdin", "--stdin-filename", "settings.ini", "--json", "--fail-on", "high"], {
    input: `password = "${secret}"\n`
  })
  const output = JSON.parse(result.stdout)

  assert.equal(result.status, 1)
  assert.equal(output.schemaVersion, 1)
  assert.equal(output.input, "stdin")
  assert.equal(output.findings[0].file, "settings.ini")
  assert.equal(result.stdout.includes(secret), false)
  assert.equal(result.stderr.includes(secret), false)
})

test("writes redacted SARIF to a file", async t => {
  const secret = generated("npm_", 36)
  const root = await fixture({ "source.txt": secret })
  const outputFile = path.join(root, "result.sarif")
  t.after(() => rm(root, { recursive: true, force: true }))

  const result = await runCli([root, "--sarif", "--output", outputFile, "--no-gitignore"])
  const output = JSON.parse(await readFile(outputFile, "utf8"))

  assert.equal(result.status, 1)
  assert.equal(result.stdout, "")
  assert.equal(output.version, "2.1.0")
  assert.equal(JSON.stringify(output).includes(secret), false)
})

test("initializes configuration without overwriting by default", async t => {
  const parent = await fixture({})
  const root = path.join(parent, "project")
  t.after(() => rm(parent, { recursive: true, force: true }))

  const first = await runCli(["init", root])
  const second = await runCli(["init", root])
  const config = JSON.parse(await readFile(path.join(root, ".shareguard.json"), "utf8"))

  assert.equal(first.status, 0)
  assert.equal(second.status, 2)
  assert.equal(config.schemaVersion, 1)
  assert.deepEqual(config.ignore, [])
  assert.deepEqual(config.allow, [])
})

test("refreshes baselines from all current findings", async t => {
  const secret = generated("", 40)
  const root = await fixture({ "settings.js": `const password = "${secret}"\n` })
  const baseline = path.join(root, "baseline.json")
  t.after(() => rm(root, { recursive: true, force: true }))

  const created = await runCli([root, "--write-baseline", baseline, "--no-gitignore", "--no-color"])
  const compared = await runCli([root, "--baseline", baseline, "--write-baseline", baseline, "--no-gitignore", "--json"])
  const data = JSON.parse(await readFile(baseline, "utf8"))

  assert.equal(created.status, 1)
  assert.equal(compared.status, 0)
  assert.equal(data.schemaVersion, 1)
  assert.equal(data.version, 1)
  assert.equal(data.findings.length, 1)
  assert.equal(JSON.stringify(data).includes(secret), false)
})

test("uses deterministic process exit codes", async t => {
  const root = await fixture({ "settings.js": `const password = "${generated("", 40)}"\n` })
  t.after(() => rm(root, { recursive: true, force: true }))

  assert.equal((await runCli([root, "--fail-on", "critical", "--no-gitignore"])).status, 0)
  assert.equal((await runCli([root, "--fail-on", "high", "--no-gitignore"])).status, 1)
  assert.equal((await runCli([path.join(root, "missing")])).status, 2)
})
