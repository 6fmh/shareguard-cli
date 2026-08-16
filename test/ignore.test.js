import test from "node:test"
import assert from "node:assert/strict"
import { createIgnoreMatcher, globToRegex } from "../src/ignore.js"

test("matches directory, extension, and recursive patterns", () => {
  const ignored = createIgnoreMatcher(["node_modules/", "*.map", "build/**"])

  assert.equal(ignored("node_modules/pkg/index.js"), true)
  assert.equal(ignored("packages/app/node_modules/pkg/index.js"), true)
  assert.equal(ignored("src/app.js.map"), true)
  assert.equal(ignored("build/linux/app"), true)
  assert.equal(ignored("src/app.js"), false)
})

test("supports negated paths below ignored directories", () => {
  const ignored = createIgnoreMatcher(["fixtures/", "!fixtures/safe.txt"])

  assert.equal(ignored("fixtures/private.txt"), true)
  assert.equal(ignored("fixtures/safe.txt"), false)
  assert.equal(ignored.shouldDescend("fixtures"), true)
})

test("uses the last matching rule", () => {
  const ignored = createIgnoreMatcher(["*.txt", "!safe.txt", "safe.txt"])

  assert.equal(ignored("safe.txt"), true)
})

test("anchors slash patterns at the root", () => {
  const pattern = globToRegex("config/private.json")
  const leading = globToRegex("/root.txt")

  assert.equal(pattern.test("config/private.json"), true)
  assert.equal(pattern.test("nested/config/private.json"), false)
  assert.equal(leading.test("root.txt"), true)
  assert.equal(leading.test("nested/root.txt"), false)
})
