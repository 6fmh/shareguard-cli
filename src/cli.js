#!/usr/bin/env node

import { writeFile } from "node:fs/promises"
import path from "node:path"
import process from "node:process"
import { fileURLToPath } from "node:url"
import { loadBaseline, loadConfig } from "./config.js"
import { formatJson, formatText } from "./format.js"
import { scan } from "./scanner.js"
import { severityRank } from "./rules.js"

const version = "0.1.0"
const help = `ShareGuard ${version}

Catch secrets and private data before you share a folder.

Usage:
  shareguard [path] [options]

Options:
  --json                    Print machine-readable JSON
  --config <file>           Use a custom configuration file
  --baseline <file>         Ignore known finding fingerprints
  --write-baseline <file>   Save current finding fingerprints
  --fail-on <severity>      Exit 1 at low, medium, high, or critical
  --no-gitignore            Do not use .gitignore rules
  --no-color                Disable terminal colors
  --version                 Print the version
  --help                    Print this help

Examples:
  shareguard
  shareguard ./release --fail-on medium
  shareguard . --json
  shareguard . --write-baseline .shareguard-baseline.json`

const readValue = (args, index, option) => {
  const value = args[index + 1]
  if (!value || value.startsWith("--")) throw new Error(`${option} requires a value`)
  return value
}

export const parseArgs = args => {
  const options = {
    root: ".",
    json: false,
    color: process.stdout.isTTY,
    useGitignore: true,
    failOn: "high"
  }

  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index]

    if (argument === "--json") options.json = true
    else if (argument === "--no-color") options.color = false
    else if (argument === "--no-gitignore") options.useGitignore = false
    else if (argument === "--help" || argument === "-h") options.help = true
    else if (argument === "--version" || argument === "-v") options.version = true
    else if (argument === "--config") options.config = readValue(args, index++, argument)
    else if (argument === "--baseline") options.baseline = readValue(args, index++, argument)
    else if (argument === "--write-baseline") options.writeBaseline = readValue(args, index++, argument)
    else if (argument === "--fail-on") options.failOn = readValue(args, index++, argument).toLowerCase()
    else if (argument.startsWith("-")) throw new Error(`Unknown option: ${argument}`)
    else if (options.root !== ".") throw new Error("Only one path can be scanned at a time")
    else options.root = argument
  }

  if (!severityRank[options.failOn]) throw new Error("--fail-on must be low, medium, high, or critical")
  return options
}

export const run = async (args = process.argv.slice(2)) => {
  const options = parseArgs(args)
  if (options.help) {
    process.stdout.write(`${help}\n`)
    return 0
  }
  if (options.version) {
    process.stdout.write(`${version}\n`)
    return 0
  }

  const root = path.resolve(options.root)
  const config = await loadConfig(root, options.config)
  const baseline = await loadBaseline(options.baseline)
  const result = await scan({ root, config, useGitignore: options.useGitignore, baseline })

  if (options.writeBaseline) {
    const data = JSON.stringify({ version: 1, findings: result.findings.map(item => item.fingerprint) }, null, 2)
    await writeFile(path.resolve(options.writeBaseline), `${data}\n`, "utf8")
  }

  process.stdout.write(`${options.json ? formatJson(result) : formatText(result, options)}\n`)
  return result.findings.some(item => severityRank[item.severity] >= severityRank[options.failOn]) ? 1 : 0
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)

if (isMain) {
  run().then(code => {
    process.exitCode = code
  }).catch(error => {
    process.stderr.write(`shareguard: ${error.message}\n`)
    process.exitCode = 2
  })
}
