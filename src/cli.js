#!/usr/bin/env node

import { mkdir, stat, writeFile } from "node:fs/promises"
import path from "node:path"
import process from "node:process"
import { fileURLToPath } from "node:url"
import { configSchemaVersion, loadBaseline, loadConfig, starterConfig } from "./config.js"
import { formatCsv, formatGithub, formatJson, formatJunit, formatMarkdown, formatSarif, formatText } from "./format.js"
import { allRules, categories, severityRank } from "./rules.js"
import { scan } from "./scanner.js"

export const version = "0.4.0"

export const formats = ["text", "json", "sarif", "github", "markdown", "csv", "junit"]

const failOnValues = [...Object.keys(severityRank), "none"]

const help = `ShareGuard ${version}

Detect secrets, personal information, risky files, and oversized artifacts.

Usage:
  shareguard [scan] [path] [options]
  shareguard init [path] [--force]

Scan options:
  --staged                    Scan added and modified files in the Git index
  --since <ref>               Scan files changed since a Git reference
  --stdin                     Read content from standard input
  --stdin-filename <path>     Set the reported path for standard input
  --format <format>           Print ${formats.join(", ")}
  --json                      Alias for --format json
  --sarif                     Alias for --format sarif
  --output <file>             Write formatted output to a file
  --report <format>[:<file>]  Emit an extra report, repeatable
  --config <file>             Use a custom configuration file
  --baseline <file>           Ignore known finding fingerprints
  --write-baseline <file>     Save all current finding fingerprints
  --include-rule <id>         Scan only a rule, repeatable
  --exclude-rule <id>         Disable a rule, repeatable
  --category <name>           Scan only a category, repeatable
  --concurrency <count>       Override bounded scan concurrency
  --fail-on <severity>        Exit 1 at low, medium, high, critical, or none
  --no-gitignore              Do not use .gitignore rules
  --no-color                  Disable terminal colors
  --quiet                     Print findings without the summary
  --list-rules                Print every rule and exit
  --version                   Print the version
  --help                      Print this help

Categories: ${categories.join(", ")}

Inline suppression:
  shareguard-ignore-line, shareguard-ignore-next-line, and shareguard-ignore-file
  comments skip every rule, or only the rule identifiers listed after them.

Examples:
  shareguard . --fail-on medium
  shareguard --staged --format sarif --output shareguard.sarif
  shareguard . --since origin/main --format github
  shareguard . --sarif --output out.sarif --report markdown:summary.md
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

const parseReport = value => {
  const separator = value.indexOf(":")
  const format = (separator === -1 ? value : value.slice(0, separator)).trim().toLowerCase()
  const file = separator === -1 ? undefined : value.slice(separator + 1).trim()
  if (!formats.includes(format)) throw new Error(`--report format must be ${formats.join(", ")}`)
  if (separator !== -1 && !file) throw new Error("--report requires a file path after the format")
  return { format, file }
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
    selectedCategories: [],
    reports: []
  }
  let hasRoot = false

  for (let index = 0; index < values.length; index += 1) {
    const argument = values[index]

    if (argument === "--json") {
      options.format = "json"
      options.formatGiven = true
      options.json = true
    } else if (argument === "--sarif") {
      options.format = "sarif"
      options.formatGiven = true
    } else if (argument === "--staged") options.staged = true
    else if (argument === "--stdin") options.stdin = true
    else if (argument === "--force") options.force = true
    else if (argument === "--no-color") options.color = false
    else if (argument === "--no-gitignore") options.useGitignore = false
    else if (argument === "--quiet" || argument === "-q") options.quiet = true
    else if (argument === "--list-rules") options.listRules = true
    else if (argument === "--help" || argument === "-h") options.help = true
    else if (argument === "--version" || argument === "-v") options.version = true
    else if (argument === "--config") options.config = readValue(values, index++, argument)
    else if (argument === "--baseline") options.baseline = readValue(values, index++, argument)
    else if (argument === "--write-baseline") options.writeBaseline = readValue(values, index++, argument)
    else if (argument === "--output") options.output = readValue(values, index++, argument)
    else if (argument === "--since") options.since = readValue(values, index++, argument)
    else if (argument === "--stdin-filename") options.stdinFilename = readValue(values, index++, argument)
    else if (argument === "--report") options.reports.push(parseReport(readValue(values, index++, argument)))
    else if (argument === "--format") {
      options.format = readValue(values, index++, argument).toLowerCase()
      options.formatGiven = true
    } else if (argument === "--fail-on") options.failOn = readValue(values, index++, argument).toLowerCase()
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

  if (!failOnValues.includes(options.failOn)) throw new Error(`--fail-on must be ${failOnValues.join(", ")}`)
  if (!formats.includes(options.format)) throw new Error(`--format must be ${formats.join(", ")}`)
  if (options.concurrency !== undefined && (!Number.isSafeInteger(options.concurrency) || options.concurrency < 1 || options.concurrency > 64)) throw new Error("--concurrency must be an integer from 1 to 64")
  if (options.stdin && options.staged) throw new Error("--stdin and --staged cannot be used together")
  if (options.since !== undefined && options.staged) throw new Error("--since and --staged cannot be used together")
  if (options.since !== undefined && options.stdin) throw new Error("--since and --stdin cannot be used together")
  if (options.stdin && hasRoot) throw new Error("A scan path cannot be used with --stdin")
  if (options.stdinFilename && !options.stdin) throw new Error("--stdin-filename requires --stdin")
  if (command === "scan" && options.force) throw new Error("--force can only be used with init")
  if (command === "init") {
    const scanOnly = [
      options.staged, options.stdin, options.stdinFilename, options.config, options.baseline, options.writeBaseline,
      options.output, options.since !== undefined, options.quiet, options.listRules, options.formatGiven,
      options.reports.length > 0, options.concurrency !== undefined, !options.useGitignore, options.failOn !== "high",
      options.includeRules.length > 0, options.excludeRules.length > 0, options.selectedCategories.length > 0
    ]
    if (scanOnly.some(Boolean)) throw new Error("init only accepts a path and --force")
  }
  return options
}

export const resolveReports = options => {
  const reports = []
  if (options.reports.length === 0 || options.formatGiven || options.output !== undefined) {
    reports.push({ format: options.format, file: options.output })
  }
  reports.push(...options.reports)

  const destinations = new Set()
  for (const report of reports) {
    if (report.file === undefined) continue
    const resolved = path.resolve(report.file)
    if (destinations.has(resolved)) throw new Error("Each report must write to a different file")
    destinations.add(resolved)
  }
  return reports
}

const render = (format, result, options) => {
  if (format === "json") return formatJson(result)
  if (format === "sarif") return formatSarif(result, version)
  if (format === "github") return formatGithub(result, options)
  if (format === "markdown") return formatMarkdown(result)
  if (format === "csv") return formatCsv(result)
  if (format === "junit") return formatJunit(result, version)
  return formatText(result, options)
}

const listRules = (options, stdout) => {
  const rules = allRules
    .map(rule => ({ id: rule.id, category: rule.category, severity: rule.severity, description: rule.description }))
    .sort((first, second) => first.category.localeCompare(second.category) || first.id.localeCompare(second.id))

  if (options.format === "json") {
    stdout.write(`${JSON.stringify({ schemaVersion: 1, rules }, null, 2)}\n`)
    return 0
  }

  const width = Math.max(...rules.map(rule => rule.id.length))
  for (const rule of rules) stdout.write(`${rule.id.padEnd(width)}  ${rule.category.padEnd(7)}  ${rule.severity.padEnd(8)}  ${rule.description}\n`)
  return 0
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
  if (options.listRules) return listRules(options, io.stdout)
  if (options.command === "init") return initialize(options, io.stdout)

  const reports = resolveReports(options)
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
    since: options.since,
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

  for (const report of reports) {
    const output = render(report.format, result, options)
    if (report.file === undefined) {
      io.stdout.write(`${output}\n`)
      continue
    }
    try {
      await writeFile(path.resolve(report.file), `${output}\n`, "utf8")
    } catch {
      throw new Error(`Could not write ${report.format} output`)
    }
  }

  if (result.stats.errors > 0) return 2
  if (options.failOn === "none") return 0
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
