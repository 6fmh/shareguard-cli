import { appendFileSync } from "node:fs"
import { spawnSync } from "node:child_process"
import path from "node:path"
import process from "node:process"
import { fileURLToPath } from "node:url"

const input = name => process.env[`INPUT_${name.replaceAll("-", "_").toUpperCase()}`]?.trim()
const value = (name, fallback) => input(name) || fallback
const enabled = name => input(name)?.toLowerCase() === "true"
const actionRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const format = value("format", "text")
const output = input("output")
const args = ["scan", value("path", "."), "--fail-on", value("fail-on", "high"), "--format", format, "--no-color"]

if (enabled("staged")) args.push("--staged")
if (input("config")) args.push("--config", input("config"))
if (input("baseline")) args.push("--baseline", input("baseline"))
if (output) args.push("--output", output)

const result = spawnSync(process.execPath, [path.join(actionRoot, "src", "cli.js"), ...args], {
  cwd: process.env.GITHUB_WORKSPACE || process.cwd(),
  env: process.env,
  stdio: "inherit",
  windowsHide: true
})

if (format === "sarif" && output && process.env.GITHUB_OUTPUT) {
  if (/[\r\n]/.test(output)) throw new Error("Action output path cannot contain line breaks")
  appendFileSync(process.env.GITHUB_OUTPUT, `sarif=${output}\n`, "utf8")
}

process.exitCode = result.status ?? 2
