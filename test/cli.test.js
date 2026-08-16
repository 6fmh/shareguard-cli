import test from "node:test"
import assert from "node:assert/strict"
import { parseArgs } from "../src/cli.js"

test("parses backward-compatible scan options", () => {
  const options = parseArgs(["release", "--json", "--fail-on", "medium", "--no-gitignore"])

  assert.equal(options.command, "scan")
  assert.equal(options.root, "release")
  assert.equal(options.json, true)
  assert.equal(options.format, "json")
  assert.equal(options.failOn, "medium")
  assert.equal(options.useGitignore, false)
})

test("parses staged rule selection", () => {
  const options = parseArgs(["scan", "repo", "--staged", "--include-rule", "github-token,npm-token", "--exclude-rule", "npm-token", "--category", "secret"])

  assert.equal(options.staged, true)
  assert.deepEqual(options.includeRules, ["github-token", "npm-token"])
  assert.deepEqual(options.excludeRules, ["npm-token"])
  assert.deepEqual(options.selectedCategories, ["secret"])
})

test("rejects incompatible or invalid options", () => {
  assert.throws(() => parseArgs(["--fail-on", "urgent"]), /must be low/)
  assert.throws(() => parseArgs(["--stdin", "--staged"]), /cannot be used together/)
  assert.throws(() => parseArgs(["--stdin-filename", "input.txt"]), /requires --stdin/)
  assert.throws(() => parseArgs(["--concurrency", "0"]), /integer from 1 to 64/)
  assert.throws(() => parseArgs(["--concurrency", "3x"]), /integer from 1 to 64/)
  assert.throws(() => parseArgs(["--force"]), /only be used with init/)
  assert.throws(() => parseArgs(["init", "--json"]), /init only accepts/)
})
