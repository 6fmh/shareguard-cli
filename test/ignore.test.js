import test from "node:test"
import assert from "node:assert/strict"
import { createIgnoreMatcher, globToRegex } from "../src/ignore.js"

test("matches directory and extension patterns", () => {
  const ignored = createIgnoreMatcher(["node_modules/", "*.map", "build/**"])

  assert.equal(ignored("node_modules/pkg/index.js"), true)
  assert.equal(ignored("src/app.js.map"), true)
  assert.equal(ignored("build/linux/app"), true)
  assert.equal(ignored("src/app.js"), false)
})

test("supports negated patterns", () => {
  const ignored = createIgnoreMatcher(["fixtures/", "!fixtures/safe.txt"])

  assert.equal(ignored("fixtures/private.txt"), true)
  assert.equal(ignored("fixtures/safe.txt"), false)
})

test("anchors slash patterns at the root", () => {
  const pattern = globToRegex("config/private.json")

  assert.equal(pattern.test("config/private.json"), true)
  assert.equal(pattern.test("nested/config/private.json"), false)
})
