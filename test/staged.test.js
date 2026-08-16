import test from "node:test"
import assert from "node:assert/strict"
import path from "node:path"
import { getStagedEntries } from "../src/git.js"
import { defaults } from "../src/config.js"
import { scan } from "../src/scanner.js"
import { generated } from "./helpers.js"

const stagedOperations = entries => ({
  getStagedEntries: async root => ({ repositoryRoot: root, entries: entries.map(entry => ({ ...entry, object: entry.relative })) }),
  getObjectSize: async (_, object) => entries.find(entry => entry.relative === object).content.length,
  readObject: async (_, object) => Buffer.from(entries.find(entry => entry.relative === object).content)
})

test("reads staged index records and limits them to a requested subdirectory", async () => {
  const root = path.resolve("repository")
  const runner = async (_, args) => {
    if (args[0] === "rev-parse") return root
    if (args[0] === "diff") return "app/a.txt\0docs/b.txt\0"
    return ["100644 aaa 0\tapp/a.txt", "100644 bbb 0\tdocs/b.txt", ""].join("\0")
  }

  const result = await getStagedEntries(path.join(root, "app"), runner)

  assert.equal(result.repositoryRoot, root)
  assert.deepEqual(result.entries, [{ relative: "a.txt", repoRelative: "app/a.txt", mode: "100644", object: "aaa" }])
})

test("scans staged blobs rather than unselected working-tree files", async () => {
  const credential = generated("npm_", 36)
  const entries = [
    { relative: "tracked.txt", mode: "100644", content: credential },
    { relative: "untracked.txt", mode: "100644", content: generated("npm_", 36) }
  ]
  const staged = stagedOperations(entries.slice(0, 1))

  const result = await scan({ root: ".", config: defaults, staged: true, gitOperations: staged })

  assert.equal(result.input, "staged")
  assert.equal(result.stats.files, 1)
  assert.equal(result.findings.some(item => item.rule === "npm-token"), true)
  assert.equal(JSON.stringify(result).includes(credential), false)
})
