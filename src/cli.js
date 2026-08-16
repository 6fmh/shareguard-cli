#!/usr/bin/env node

import { mkdir, stat, writeFile } from "node:fs/promises"
import path from "node:path"
import process from "node:process"
import { fileURLToPath } from "node:url"
import { configSchemaVersion, loadBaseline, loadConfig, starterConfig } from "./config.js"
import { formatJson, formatSarif, formatText } from "./format.js"
import { categories, severityRank } from "./rules.js"
import { scan } from "./scanner.js"

export const version = "0.2.0"

const help = `ShareGuard ${version}

Detect secrets, personal information, risky files, and oversized artifacts.

Usage:
  shareguard [scan] [path] [options]
  shareguard init [path] [--force]

Scan options:
  --staged                  Scan added and modified files in the Git index
  --stdin                   Read content from standard input
  --stdin-filename <path>   Set the reported path for standard input
  --format <format>         Print text, json, or sarif
  --json                    Alias for --format json
  --sarif                   Alias for --format sarif
  --output <file>           Write formatted output to a file
  --config <file>           Use a custom configuration file
  --baseline <file>         Ignore known finding fingerprints
  --write-baseline <file>   Save all current finding fingerprints
  --include-rule <id>       Scan only a rule, repeatable
  --exclude-rule <id>       Disable a rule, repeatable
  --category <name>         Scan only a category, repeatable
  --concurrency <count>     Override bounded scan concurrency
  --fail-on <severity>      Exit 1 at low, medium, high, or critical
  --no-gitignore            Do not use .gitignore rules
  --no-color                Disable terminal colors
  --version                 Print the version
  --help                    Print this help

Categories: ${categories.join(", ")}

Examples:
  shareguard . --fail-on medium
  shareguard --staged --format sarif --output shareguard.sarif
  shareguard --stdin --stdin-filename config.txt
  shareguard init`

const readValue = (args, index, option) => {
  const value = args[index + 1]
  if (!value || value.startsWith("--")) throw new Error(`${option} requires a value`)
  return value
}

const addValues = (target, value) => {
  for (const item of value.split(",").map(part => part.trim()).filter(Boolean)) target.push(item)
}

export const parseArgs = args => {
  const values = [...args]
  const command = values[0] === "scan" || values[0] === "init" ? values.shift() : "scan"
  const options = {
    command,
    root: ".",
    format: "text",
    color: process.stdout.isTTY,
    useGitignore: true,
    failOn: "high",
    includeRules: [],
    excludeRules: [],
    selectedCategories: []
  }
  let hasRoot = false

  for (let index = 0; index < values.length; index += 1) {
    const argument = values[index]

    if (argument === "--json") {
      options.format = "json"
      options.json = true
    } else if (argument === "--sarif") options.format = "sarif"
    else if (argument === "--staged") options.staged = true
    else if (argument === "--stdin") options.stdin = true
    else if (argument === "--force") options.force = true
    else if (argument === "--no-color") options.color = false
    else if (argument === "--no-gitignore") options.useGitignore = false
    else if (argument === "--help" || argument === "-h") options.help = true
    else if (argument === "--version" || argument === "-v") options.version = true
    else if (argument === "--config") options.config = readValue(values, index++, argument)
    else if (argument === "--baseline") options.baseline = readValue(values, index++, argument)
    else if (argument === "--write-baseline") options.writeBaseline = readValue(values, index++, argument)
    else if (argument === "--output") options.output = readValue(values, index++, argument)
    else if (argument === "--stdin-filename") options.stdinFilename = readValue(values, index++, argument)
    else if (argument === "--format") options.format = readValue(values, index++, argument).toLowerCase()
    else if (argument === "--fail-on") options.failOn = readValue(values, index++, argument).toLowerCase()
    else if (argument === "--concurrency") options.concurrency = Number(readValue(values, index++, argument))
    else if (argument === "--include-rule") addValues(options.includeRules, readValue(values, index++, argument))
    else if (argument === "--exclude-rule") addValues(options.excludeRules, readValue(values, index++, argument))
    else if (argument === "--category") addValues(options.selectedCategories, readValue(values, index++, argument))
    else if (argument.startsWith("-")) throw new Error(`Unknown option: ${argument}`)
    else if (hasRoot) throw new Error("Only one path can be scanned at a time")
    else {
      options.root = argument
      hasRoot = true
    }
  }

  if (!severityRank[options.failOn]) throw new Error("--fail-on must be low, medium, high, or critical")
  if (!["text", "json", "sarif"].includes(options.format)) throw new Error("--format must be text, json, or sarif")
  if (options.concurrency !== undefined && (!Number.isSafeInteger(options.concurrency) || options.concurrency < 1 || options.concurrency > 64)) throw new Error("--concurrency must be an integer from 1 to 64")
  if (options.stdin && options.staged) throw new Error("--stdin and --staged cannot be used together")
  if (options.stdin && hasRoot) throw new Error("A scan path cannot be used with --stdin")
  if (options.stdinFilename && !options.stdin) throw new Error("--stdin-filename requires --stdin")
  if (command === "scan" && options.force) throw new Error("--force can only be used with init")
  if (command === "init" && ([options.staged, options.stdin, options.config, options.baseline, options.writeBaseline, options.output].some(Boolean) || options.format !== "text")) throw new Error("init only accepts a path and --force")
  if (command === "init" && (options.failOn !== "high" || !options.useGitignore || options.concurrency !== undefined)) throw new Error("init only accepts a path and --force")
  if (command === "init" && (options.includeRules.length > 0 || options.excludeRules.length > 0 || options.selectedCategories.length > 0)) throw new Error("init does not accept rule filters")
  return options
}

const readStdin = async stream => {
  const chunks = []
  for await (const chunk of stream) chunks.push(Buffer.from(chunk))
  return Buffer.concat(chunks)
}

const initialize = async (options, stdout) => {
  const root = path.resolve(options.root)
  try {
    await mkdir(root, { recursive: true })
  } catch {
    throw new Error("Could not create the configuration directory")
  }
  const file = path.join(root, ".shareguard.json")
  const data = `${JSON.stringify(starterConfig, null, 2)}\n`

  try {
    await writeFile(file, data, { encoding: "utf8", flag: options.force ? "w" : "wx" })
  } catch (error) {
    if (error.code === "EEXIST") throw new Error(".shareguard.json already exists; use --force to replace it")
    throw new Error("Could not write .shareguard.json")
  }

  stdout.write("Created .shareguard.json\n")
  return 0
}

const findConfigRoot = async root => {
  try {
    return (await stat(root)).isFile() ? path.dirname(root) : root
  } catch {
    return root
  }
}

export const run = async (args = process.argv.slice(2), io = { stdin: process.stdin, stdout: process.stdout }) => {
  const options = parseArgs(args)
  if (options.help) {
    io.stdout.write(`${help}\n`)
    return 0
  }
  if (options.version) {
    io.stdout.write(`${version}\n`)
    return 0
  }
  if (options.command === "init") return initialize(options, io.stdout)

  const root = path.resolve(options.root)
  const configRoot = await findConfigRoot(root)
  let config = await loadConfig(configRoot, options.config)
  if (options.concurrency !== undefined) config = { ...config, concurrency: options.concurrency }
  const baseline = await loadBaseline(options.baseline)
  const stdinContent = options.stdin ? await readStdin(io.stdin) : undefined
  const result = await scan({
    root,
    config,
    useGitignore: options.useGitignore,
    baseline,
    staged: options.staged,
    stdinContent,
    stdinFilename: options.stdinFilename,
    includeRules: options.includeRules,
    excludeRules: options.excludeRules,
    selectedCategories: options.selectedCategories
  })

  if (options.writeBaseline) {
    const data = JSON.stringify({
      schemaVersion: configSchemaVersion,
      version: configSchemaVersion,
      generatedBy: `shareguard-cli ${version}`,
      findings: result.baselineEntries.map(item => item.fingerprint).sort()
    }, null, 2)
    try {
      await writeFile(path.resolve(options.writeBaseline), `${data}\n`, "utf8")
    } catch {
      throw new Error("Could not write baseline")
    }
  }

  const output = options.format === "json" ? formatJson(result) : options.format === "sarif" ? formatSarif(result, version) : formatText(result, options)
  if (options.output) {
    try {
      await writeFile(path.resolve(options.output), `${output}\n`, "utf8")
    } catch {
      throw new Error("Could not write output")
    }
  } else io.stdout.write(`${output}\n`)

  if (result.stats.errors > 0) return 2
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
