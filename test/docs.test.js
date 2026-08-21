import test from "node:test"
import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { version } from "../src/cli.js"
import { allRules, categories } from "../src/rules.js"
import { renderRules } from "../scripts/generate-docs.js"

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const read = name => readFile(path.join(root, name), "utf8")

test("documents every rule with an anchor SARIF help links can reach", async () => {
  const document = await read("docs/RULES.md")

  for (const rule of allRules) assert.equal(document.includes(`### ${rule.id}\n`), true, `missing section for ${rule.id}`)
  for (const category of categories) assert.equal(document.includes(`## ${category}`), true, `missing category ${category}`)
  assert.match(document, new RegExp(`ShareGuard ships ${allRules.length} rules`))
})

test("keeps the generated rule reference in sync", async () => {
  assert.equal(await read("docs/RULES.md"), renderRules())
})

test("keeps the package version and the CLI version identical", async () => {
  const manifest = JSON.parse(await read("package.json"))

  assert.equal(manifest.version, version)
  assert.match(version, /^\d+\.\d+\.\d+$/)
})

test("keeps the changelog and README aligned with the current version", async () => {
  const changelog = await read("CHANGELOG.md")
  const readme = await read("README.md")

  assert.equal(changelog.includes(`## ${version}`), true)
  assert.equal(readme.includes("docs/RULES.md"), true)
})
