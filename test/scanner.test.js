import test from "node:test"
import assert from "node:assert/strict"
import { rm } from "node:fs/promises"
import { defaults } from "../src/config.js"
import { scan } from "../src/scanner.js"
import { fixture, generated, hex } from "./helpers.js"

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

test("detects new provider tokens and never retains their values", async t => {
  // Every credential-shaped value is built at runtime; none appears literally in this file.
  const tokens = {
    "openai.txt": generated("sk-proj-", 100),
    "anthropic.txt": generated("sk-ant-api03-", 90),
    "google.txt": generated("GOCSPX-", 28),
    "doppler.txt": generated("dp.st.", 44),
    "linear.txt": generated("lin_api_", 44),
    "shopify.txt": `shpat_${hex(32)}`,
    "grafana.txt": `${generated("glsa_", 32)}_${hex(8)}`
  }
  const root = await fixture(Object.fromEntries(Object.entries(tokens).map(([name, value]) => [name, `key = "${value}"\n`])))
  t.after(() => rm(root, { recursive: true, force: true }))

  const result = await scan({ root, config: defaults, useGitignore: false })
  const serialized = JSON.stringify(result)
  const detected = new Set(result.findings.map(item => item.rule))

  for (const rule of ["openai-api-key", "anthropic-api-key", "google-oauth-client-secret", "doppler-token", "linear-api-key", "shopify-token", "grafana-service-account-token"]) {
    assert.equal(detected.has(rule), true, rule)
  }
  assert.equal(result.findings.every(item => item.preview === null), true)
  for (const value of Object.values(tokens)) assert.equal(serialized.includes(value), false)
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

test("reads big-endian UTF-16 text without exposing uninitialized memory", async t => {
  const secret = generated("", 40)
  const little = Buffer.from(`password = "${secret}"`, "utf16le")
  const big = Buffer.alloc(little.length)
  for (let index = 0; index + 1 < little.length; index += 2) {
    big[index] = little[index + 1]
    big[index + 1] = little[index]
  }
  const root = await fixture({ "settings.txt": Buffer.concat([Buffer.from([0xfe, 0xff]), big]) })
  t.after(() => rm(root, { recursive: true, force: true }))

  const result = await scan({ root, config: defaults, useGitignore: false })
  const serialized = JSON.stringify(result)

  assert.equal(result.findings.some(item => item.rule === "generic-secret"), true)
  assert.equal(serialized.includes(secret), false)
})

test("reports the line number of each finding", async t => {
  const secret = generated("", 40)
  const root = await fixture({ "settings.js": `// header\n\nconst blank = 1\npassword = "${secret}"\n` })
  t.after(() => rm(root, { recursive: true, force: true }))

  const result = await scan({ root, config: defaults, useGitignore: false, includeRules: ["generic-secret"] })

  assert.equal(result.findings.length, 1)
  assert.equal(result.findings[0].line, 4)
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

test("reports risky filenames and ignores their documented samples", async t => {
  const root = await fixture({
    "deploy/id_ed25519": "content\n",
    "deploy/cluster.ovpn": "content\n",
    "deploy/service-account.json": "{}\n",
    "deploy/terraform.tfstate": "{}\n",
    "deploy/notes.txt.bak": "content\n",
    "deploy/.DS_Store": "content\n",
    "deploy/.env.example": "TOKEN=replace-me\n",
    "deploy/app.pem.example": "content\n"
  })
  t.after(() => rm(root, { recursive: true, force: true }))

  const result = await scan({ root, config: defaults, useGitignore: false, selectedCategories: ["secret", "hygiene"] })
  const rules = new Set(result.findings.map(item => item.rule))

  assert.equal(rules.has("private-key-file"), true)
  assert.equal(rules.has("secret-store-file"), true)
  assert.equal(rules.has("service-account-key-file"), true)
  assert.equal(rules.has("infrastructure-state-file"), true)
  assert.equal(rules.has("backup-file"), true)
  assert.equal(rules.has("os-metadata-file"), true)
  assert.equal(result.findings.some(item => item.file.endsWith(".env.example")), false)
})
