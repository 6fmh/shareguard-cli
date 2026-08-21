import test from "node:test"
import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import { readFile, rm, mkdtemp } from "node:fs/promises"
import { existsSync } from "node:fs"
import os from "node:os"
import path from "node:path"
import process from "node:process"
import { fixture, generated } from "./helpers.js"

const wrapper = path.join(process.cwd(), "src", "action.js")

const runAction = (workspace, inputs, files = {}) => {
  const environment = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith("INPUT_") && !name.startsWith("GITHUB_")))
  const result = spawnSync(process.execPath, [wrapper], {
    cwd: workspace,
    encoding: "utf8",
    env: { ...environment, GITHUB_WORKSPACE: workspace, ...files, ...inputs }
  })
  return { status: result.status, stdout: result.stdout, stderr: result.stderr }
}

const temporary = async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "shareguard-action-"))
  return { directory, summary: path.join(directory, "summary.md"), output: path.join(directory, "output.txt") }
}

test("writes a job summary and the exit-code output", async t => {
  const root = await fixture({ "notes.md": "nothing sensitive here" })
  const paths = await temporary()
  t.after(() => Promise.all([rm(root, { recursive: true, force: true }), rm(paths.directory, { recursive: true, force: true })]))

  const result = runAction(root, { INPUT_FAIL_ON: "none" }, { GITHUB_STEP_SUMMARY: paths.summary, GITHUB_OUTPUT: paths.output })

  assert.equal(result.status, 0)
  assert.match(await readFile(paths.summary, "utf8"), /^## ShareGuard/)
  assert.match(await readFile(paths.output, "utf8"), /exit-code=0/)
})

test("reports the sarif output path and a failing exit code without leaking the value", async t => {
  const secret = generated("ghp_", 36)
  const root = await fixture({ "config.js": `const token = "${secret}"` + String.fromCharCode(10) })
  const paths = await temporary()
  t.after(() => Promise.all([rm(root, { recursive: true, force: true }), rm(paths.directory, { recursive: true, force: true })]))

  const result = runAction(root, { INPUT_FORMAT: "sarif", INPUT_OUTPUT: "report.sarif" }, { GITHUB_OUTPUT: paths.output })
  const report = await readFile(path.join(root, "report.sarif"), "utf8")

  assert.equal(result.status, 1)
  assert.match(await readFile(paths.output, "utf8"), /sarif=report.sarif/)
  assert.match(result.stdout, /::error file=config.js/)
  assert.equal(report.includes(secret), false)
  assert.equal(result.stdout.includes(secret), false)
})

test("rejects inputs that could inject extra command-line options", async t => {
  const root = await fixture({ "notes.md": "clean" })
  t.after(() => rm(root, { recursive: true, force: true }))

  const dash = runAction(root, { INPUT_FAIL_ON: "--version" })
  const broken = runAction(root, { INPUT_PATH: `.${String.fromCharCode(10)}--help` })

  assert.notEqual(dash.status, 0)
  assert.match(dash.stderr, /cannot start with a dash/)
  assert.notEqual(broken.status, 0)
  assert.match(broken.stderr, /cannot contain line breaks/)
})

test("skips the job summary when the summary input is disabled", async t => {
  const root = await fixture({ "notes.md": "clean" })
  const paths = await temporary()
  t.after(() => Promise.all([rm(root, { recursive: true, force: true }), rm(paths.directory, { recursive: true, force: true })]))

  const result = runAction(root, { INPUT_SUMMARY: "false", INPUT_FAIL_ON: "none" }, { GITHUB_STEP_SUMMARY: paths.summary })

  assert.equal(result.status, 0)
  assert.equal(existsSync(paths.summary), false)
})
