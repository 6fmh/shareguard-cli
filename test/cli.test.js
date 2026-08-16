import test from "node:test"
import assert from "node:assert/strict"
import { parseArgs } from "../src/cli.js"

test("parses scan options", () => {
  const options = parseArgs(["release", "--json", "--fail-on", "medium", "--no-gitignore"])

  assert.equal(options.root, "release")
  assert.equal(options.json, true)
  assert.equal(options.failOn, "medium")
  assert.equal(options.useGitignore, false)
})

test("rejects invalid severity", () => {
  assert.throws(() => parseArgs(["--fail-on", "urgent"]), /must be low/)
})
