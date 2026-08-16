import test from "node:test"
import assert from "node:assert/strict"
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { defaults } from "../src/config.js"
import { scan } from "../src/scanner.js"

const fixture = async files => {
  const root = await mkdtemp(path.join(os.tmpdir(), "shareguard-"))

  for (const [name, content] of Object.entries(files)) {
    const file = path.join(root, name)
    await mkdir(path.dirname(file), { recursive: true })
    await writeFile(file, content)
  }

  return root
}

test("finds secrets and redacts them from output", async t => {
  const root = await fixture({
    "settings.js": "const password = \"this-is-a-real-password\"\n",
    ".env": "SERVICE_TOKEN=something-private\n"
  })
  t.after(() => rm(root, { recursive: true, force: true }))

  const result = await scan({ root, config: defaults, useGitignore: false })

  assert.equal(result.findings.some(item => item.rule === "generic-secret"), true)
  assert.equal(result.findings.some(item => item.rule === "dotenv-file"), true)
  assert.equal(JSON.stringify(result).includes("this-is-a-real-password"), false)
})

test("honors configured allow rules", async t => {
  const root = await fixture({ "team.txt": "hello@example.com\n" })
  t.after(() => rm(root, { recursive: true, force: true }))

  const result = await scan({
    root,
    config: { ...defaults, allow: [{ rule: "email-address", path: "team.txt" }] },
    useGitignore: false
  })

  assert.equal(result.findings.length, 0)
})

test("removes findings present in a baseline", async t => {
  const root = await fixture({ "team.txt": "hello@example.com\n" })
  t.after(() => rm(root, { recursive: true, force: true }))

  const first = await scan({ root, config: defaults, useGitignore: false })
  const baseline = new Set(first.findings.map(item => item.fingerprint))
  const second = await scan({ root, config: defaults, useGitignore: false, baseline })

  assert.equal(second.findings.length, 0)
  assert.equal(second.stats.baselined, 1)
})

test("skips ignored folders", async t => {
  const root = await fixture({ "node_modules/pkg/.env": "TOKEN=private\n", "src/index.js": "export {}\n" })
  t.after(() => rm(root, { recursive: true, force: true }))

  const result = await scan({ root, config: defaults, useGitignore: false })

  assert.equal(result.findings.length, 0)
  assert.equal(result.stats.files, 1)
})
