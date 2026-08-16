import test from "node:test"
import assert from "node:assert/strict"
import { rm, writeFile } from "node:fs/promises"
import path from "node:path"
import { loadBaseline, loadConfig, validateConfig } from "../src/config.js"
import { fixture } from "./helpers.js"

test("validates and merges configuration", () => {
  const config = validateConfig({ schemaVersion: 1, ignore: ["generated/"], concurrency: 3, entropy: { enabled: false } })

  assert.equal(config.ignore.includes("node_modules/"), true)
  assert.equal(config.ignore.includes("generated/"), true)
  assert.equal(config.concurrency, 3)
  assert.equal(config.entropy.enabled, false)
})

test("reports actionable configuration errors", () => {
  assert.throws(() => validateConfig({ schemaVersion: 2 }), /schemaVersion must be 1/)
  assert.throws(() => validateConfig({ unknown: true }), /unknown field/)
  assert.throws(() => validateConfig({ allow: [{}] }), /must specify rule/)
  assert.throws(() => validateConfig({ maxFileSize: 20, largeFileSize: 10 }), /greater than or equal/)
})

test("does not echo invalid configuration contents", async t => {
  const root = await fixture({ ".shareguard.json": "not valid private material" })
  t.after(() => rm(root, { recursive: true, force: true }))

  await assert.rejects(() => loadConfig(root), error => {
    assert.match(error.message, /invalid JSON/)
    assert.equal(error.message.includes("private material"), false)
    return true
  })
})

test("requires a valid versioned baseline", async t => {
  const root = await fixture({ "baseline.json": JSON.stringify({ schemaVersion: 1, findings: ["abc"] }) })
  t.after(() => rm(root, { recursive: true, force: true }))

  assert.deepEqual([...await loadBaseline(path.join(root, "baseline.json"))], ["abc"])
  await writeFile(path.join(root, "baseline.json"), JSON.stringify({ schemaVersion: 2, findings: [] }))
  await assert.rejects(() => loadBaseline(path.join(root, "baseline.json")), /unsupported schemaVersion/)
  await assert.rejects(() => loadBaseline(path.join(root, "missing.json")), /does not exist/)
})
