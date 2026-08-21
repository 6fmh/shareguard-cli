import test from "node:test"
import assert from "node:assert/strict"
import { rm } from "node:fs/promises"
import { defaults } from "../src/config.js"
import { scan } from "../src/scanner.js"
import { createSuppressions } from "../src/suppress.js"
import { fixture, generated } from "./helpers.js"

test("returns null when a file carries no directive", () => {
  assert.equal(createSuppressions("const value = 1\n"), null)
  assert.equal(createSuppressions("shareguard-allow everything\n"), null)
})

test("scopes directives to the requested line and rules", () => {
  const suppressed = createSuppressions([
    "first shareguard-ignore-next-line generic-secret",
    "second",
    "third shareguard-ignore-line: aws-access-key, ipv4-address",
    "fourth shareguard-ignore"
  ].join("\n"))

  assert.equal(suppressed("generic-secret", 2), true)
  assert.equal(suppressed("aws-access-key", 2), false)
  assert.equal(suppressed("aws-access-key", 3), true)
  assert.equal(suppressed("ipv4-address", 3), true)
  assert.equal(suppressed("generic-secret", 3), false)
  assert.equal(suppressed("generic-secret", 4), true)
  assert.equal(suppressed("email-address", 4), true)
})

test("treats unknown rule identifiers as every rule", () => {
  const suppressed = createSuppressions("value shareguard-ignore-line not-a-rule\n")

  assert.equal(suppressed("generic-secret", 1), true)
  assert.equal(suppressed("ipv4-address", 1), true)
})

test("applies file directives to every line", () => {
  const suppressed = createSuppressions("header shareguard-ignore-file generic-secret\nbody\n")

  assert.equal(suppressed("generic-secret", 1), true)
  assert.equal(suppressed("generic-secret", 99), true)
  assert.equal(suppressed("ipv4-address", 99), false)
})

test("counts suppressed findings during a scan without reporting them", async t => {
  const kept = generated("", 40)
  const hidden = generated("", 44)
  const root = await fixture({
    "kept.js": `const password = "${kept}"\n`,
    "hidden.js": `const password = "${hidden}" // shareguard-ignore-line generic-secret\n`,
    "whole.js": "// shareguard-ignore-file\nconst ip = \"51.75.18.200\"\n"
  })
  t.after(() => rm(root, { recursive: true, force: true }))

  const result = await scan({ root, config: defaults, useGitignore: false })
  const serialized = JSON.stringify(result)

  assert.deepEqual(result.findings.map(item => item.file), ["kept.js"])
  assert.equal(result.stats.suppressed, 2)
  assert.equal(serialized.includes(hidden), false)
})
