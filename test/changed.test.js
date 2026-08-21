import test from "node:test"
import assert from "node:assert/strict"
import { rm } from "node:fs/promises"
import path from "node:path"
import { getChangedFiles } from "../src/git.js"
import { defaults } from "../src/config.js"
import { scan } from "../src/scanner.js"
import { fixture, generated } from "./helpers.js"

test("limits changed files to the requested subdirectory", async () => {
  const root = path.resolve("repository")
  const calls = []
  const runner = async (_, args) => {
    calls.push(args)
    if (args[0] === "rev-parse" && args[1] === "--show-toplevel") return root
    if (args[0] === "rev-parse") return ""
    return "app/a.txt\0docs/b.txt\0app/nested/c.txt\0"
  }

  const result = await getChangedFiles(path.join(root, "app"), "origin/main", runner)

  assert.equal(result.repositoryRoot, root)
  assert.deepEqual(result.files, ["a.txt", "nested/c.txt"])
  assert.deepEqual(calls.at(-1), ["diff", "--name-only", "--diff-filter=ACMR", "-z", "origin/main", "--"])
})

test("rejects references that are empty or look like options", async () => {
  const runner = async () => ""

  await assert.rejects(() => getChangedFiles(".", "", runner), /Invalid Git reference/)
  await assert.rejects(() => getChangedFiles(".", "--upload-pack=payload", runner), /Invalid Git reference/)
  await assert.rejects(() => getChangedFiles(".", 7, runner), /Invalid Git reference/)
})

test("reports unresolvable references without running a diff", async () => {
  const runner = async (_, args) => {
    if (args[0] === "rev-parse" && args[1] === "--show-toplevel") return path.resolve(".")
    if (args[0] === "rev-parse") throw new Error("unknown revision")
    throw new Error("diff should not run")
  }

  await assert.rejects(() => getChangedFiles(".", "missing-branch", runner), /Git reference could not be resolved: missing-branch/)
})

test("scans only changed files and skips paths that no longer exist", async t => {
  const credential = generated("npm_", 36)
  const untouched = generated("npm_", 36)
  const root = await fixture({
    "changed.txt": credential,
    "untouched.txt": untouched
  })
  t.after(() => rm(root, { recursive: true, force: true }))

  const gitOperations = {
    getChangedFiles: async () => ({ repositoryRoot: root, files: ["changed.txt", "deleted.txt", ""] })
  }

  const result = await scan({ root, config: defaults, since: "HEAD~1", useGitignore: false, gitOperations })
  const serialized = JSON.stringify(result)

  assert.equal(result.input, "changed")
  assert.equal(result.stats.files, 1)
  assert.equal(result.stats.skipped, 1)
  assert.deepEqual(result.findings.map(item => item.file), ["changed.txt"])
  assert.equal(serialized.includes(credential), false)
  assert.equal(serialized.includes(untouched), false)
})
