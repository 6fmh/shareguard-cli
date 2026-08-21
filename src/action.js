import { appendFileSync, readFileSync, rmSync } from "node:fs"
import { mkdtempSync } from "node:fs"
import { spawnSync } from "node:child_process"
import os from "node:os"
import path from "node:path"
import process from "node:process"
import { fileURLToPath } from "node:url"

const input = name => process.env[`INPUT_${name.replaceAll("-", "_").toUpperCase()}`]?.trim()

const safe = (name, value) => {
  if (/[\r\n]/.test(value)) throw new Error(`Action input ${name} cannot contain line breaks`)
  if (value.startsWith("-")) throw new Error(`Action input ${name} cannot start with a dash`)
  return value
}

const single = (name, fallback) => {
  const value = input(name) || fallback
  return value === undefined ? undefined : safe(name, value)
}

const many = name => (input(name) ?? "").split(/[\n,]/).map(item => item.trim()).filter(Boolean).map(item => safe(name, item))
const flag = (name, fallback = false) => {
  const value = input(name)?.toLowerCase()
  if (value === undefined || value === "") return fallback
  return value === "true" || value === "1" || value === "yes"
}

const actionRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const workspace = process.env.GITHUB_WORKSPACE || process.cwd()
const format = single("format", "github")
const output = single("output")
const summaryFile = process.env.GITHUB_STEP_SUMMARY
const wantsSummary = flag("summary", true) && Boolean(summaryFile)

const args = ["scan", single("path", "."), "--fail-on", single("fail-on", "high"), "--format", format, "--no-color"]

if (flag("staged")) args.push("--staged")
if (single("since")) args.push("--since", single("since"))
if (single("config")) args.push("--config", single("config"))
if (single("baseline")) args.push("--baseline", single("baseline"))
if (single("concurrency")) args.push("--concurrency", single("concurrency"))
if (output) args.push("--output", output)
if (!flag("gitignore", true)) args.push("--no-gitignore")
if (flag("quiet")) args.push("--quiet")
for (const rule of many("include-rule")) args.push("--include-rule", rule)
for (const rule of many("exclude-rule")) args.push("--exclude-rule", rule)
for (const category of many("category")) args.push("--category", category)
if (flag("annotations", true) && format !== "github") args.push("--report", "github")

let temporary
if (wantsSummary) {
  temporary = mkdtempSync(path.join(os.tmpdir(), "shareguard-"))
  args.push("--report", `markdown:${path.join(temporary, "summary.md")}`)
}

const result = spawnSync(process.execPath, [path.join(actionRoot, "src", "cli.js"), ...args], {
  cwd: workspace,
  env: process.env,
  stdio: "inherit",
  windowsHide: true
})

if (temporary) {
  try {
    appendFileSync(summaryFile, `${readFileSync(path.join(temporary, "summary.md"), "utf8")}\n`, "utf8")
  } catch {
    process.stderr.write("shareguard: could not write the job summary\n")
  }
  rmSync(temporary, { recursive: true, force: true })
}

if (process.env.GITHUB_OUTPUT) {
  const lines = [`exit-code=${result.status ?? 2}`]
  if (format === "sarif" && output) lines.push(`sarif=${output}`)
  appendFileSync(process.env.GITHUB_OUTPUT, `${lines.join("\n")}\n`, "utf8")
}

process.exitCode = result.status ?? 2
