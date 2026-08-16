import test from "node:test"
import assert from "node:assert/strict"
import { rm } from "node:fs/promises"
import { defaults } from "../src/config.js"
import { scan } from "../src/scanner.js"
import { fixture, generated } from "./helpers.js"

test("finds secrets without retaining source values or previews", async t => {
  const first = generated("", 40)
  const second = generated("", 44)
  const root = await fixture({
    "settings.js": `const password = "${first}", token = "${second}"\n`,
    ".env": "SERVICE_MODE=production\n"
  })
  t.after(() => rm(root, { recursive: true, force: true }))

  const result = await scan({ root, config: defaults, useGitignore: false })
  const serialized = JSON.stringify(result)

  assert.equal(result.findings.filter(item => item.rule === "generic-secret").length, 2)
  assert.equal(result.findings.some(item => item.rule === "dotenv-file"), true)
  assert.equal(result.findings.every(item => item.preview === null), true)
  assert.equal(serialized.includes(first), false)
  assert.equal(serialized.includes(second), false)
})

test("honors allow rules and rule selection", async t => {
  const address = ["contact", "example.invalid"].join("@")
  const root = await fixture({ "team.txt": `${address}\n${generated("npm_", 36)}\n` })
  t.after(() => rm(root, { recursive: true, force: true }))

  const result = await scan({
    root,
    config: { ...defaults, allow: [{ rule: "email-address", path: "team.txt" }] },
    useGitignore: false,
    includeRules: ["email-address", "npm-token"],
    excludeRules: ["email-address"]
  })

  assert.deepEqual(result.findings.map(item => item.rule), ["npm-token"])
})

test("does not duplicate provider findings with the generic rule", async t => {
  const root = await fixture({ "settings.js": `const token = "${generated("npm_", 36)}"\n` })
  t.after(() => rm(root, { recursive: true, force: true }))

  const result = await scan({ root, config: defaults, useGitignore: false })

  assert.deepEqual(result.findings.map(item => item.rule), ["npm-token"])
})

test("detects conservative entropy candidates and ignores hashes", async t => {
  const randomValue = generated("", 48)
  const root = await fixture({ "values.txt": `const signingCredential = "${randomValue}"\nconst credentialHash = "${"a".repeat(64)}"\n` })
  t.after(() => rm(root, { recursive: true, force: true }))

  const result = await scan({ root, config: defaults, useGitignore: false, includeRules: ["high-entropy-secret"] })

  assert.equal(result.findings.length, 1)
  assert.equal(result.findings[0].rule, "high-entropy-secret")
})

test("reads UTF-16 text with a byte-order mark", async t => {
  const secret = generated("", 40)
  const encoded = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`password = "${secret}"`, "utf16le")])
  const root = await fixture({ "settings.txt": encoded })
  t.after(() => rm(root, { recursive: true, force: true }))

  const result = await scan({ root, config: defaults, useGitignore: false })

  assert.equal(result.findings.some(item => item.rule === "generic-secret"), true)
})

test("warns and skips invalid text encodings", async t => {
  const root = await fixture({ "invalid.txt": Buffer.from([0xc3, 0x28]) })
  t.after(() => rm(root, { recursive: true, force: true }))

  const result = await scan({ root, config: defaults, useGitignore: false })

  assert.equal(result.diagnostics[0].code, "unsupported-encoding")
  assert.equal(result.diagnostics[0].severity, "warning")
  assert.equal(result.stats.skipped, 1)
})

test("keeps re-included files below ignored directories", async t => {
  const address = ["visible", "example.invalid"].join("@")
  const root = await fixture({ "fixtures/private.txt": address, "fixtures/safe.txt": address })
  t.after(() => rm(root, { recursive: true, force: true }))

  const result = await scan({ root, config: { ...defaults, ignore: ["fixtures/", "!fixtures/safe.txt"] }, useGitignore: false })

  assert.equal(result.stats.files, 1)
  assert.equal(result.findings[0].file, "fixtures/safe.txt")
})

test("refreshes baseline entries even when findings are suppressed", async t => {
  const address = ["known", "example.invalid"].join("@")
  const root = await fixture({ "team.txt": address })
  t.after(() => rm(root, { recursive: true, force: true }))

  const first = await scan({ root, config: defaults, useGitignore: false })
  const baseline = new Set(first.findings.map(item => item.fingerprint))
  const second = await scan({ root, config: defaults, useGitignore: false, baseline })

  assert.equal(second.findings.length, 0)
  assert.equal(second.stats.baselined, 1)
  assert.equal(second.baselineEntries.length, 1)
})

test("flags large files without reading their contents", async t => {
  const root = await fixture({ "artifact.bin": Buffer.alloc(128) })
  t.after(() => rm(root, { recursive: true, force: true }))
  const config = { ...defaults, maxFileSize: 32, largeFileSize: 64 }

  const result = await scan({ root, config, useGitignore: false, includeRules: ["large-file"] })

  assert.equal(result.findings[0].rule, "large-file")
  assert.equal(result.stats.skipped, 1)
})
