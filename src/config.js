import { readFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"

export const configSchemaVersion = 1

export const defaults = {
  schemaVersion: configSchemaVersion,
  ignore: [
    ".git/",
    "node_modules/",
    "vendor/",
    "dist/",
    "build/",
    "coverage/",
    ".next/",
    ".cache/",
    "*.min.js",
    "*.map"
  ],
  allow: [],
  maxFileSize: 2_000_000,
  largeFileSize: 10_000_000,
  concurrency: Math.min(8, Math.max(2, os.availableParallelism?.() ?? os.cpus().length)),
  entropy: {
    enabled: true,
    minLength: 32,
    threshold: 4.5
  }
}

export const starterConfig = {
  schemaVersion: configSchemaVersion,
  ignore: [],
  allow: [],
  maxFileSize: defaults.maxFileSize,
  largeFileSize: defaults.largeFileSize,
  concurrency: defaults.concurrency,
  entropy: defaults.entropy
}

const configKeys = new Set(["schemaVersion", "ignore", "allow", "maxFileSize", "largeFileSize", "concurrency", "entropy"])
const allowKeys = new Set(["rule", "path"])
const entropyKeys = new Set(["enabled", "minLength", "threshold"])
const isObject = value => value !== null && typeof value === "object" && !Array.isArray(value)

const assertKnownKeys = (value, keys, label) => {
  const unknown = Object.keys(value).filter(key => !keys.has(key))
  if (unknown.length > 0) throw new Error(`${label} contains unknown field${unknown.length === 1 ? "" : "s"}: ${unknown.join(", ")}`)
}

const assertPositiveInteger = (value, label) => {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${label} must be a positive integer`)
}

export const validateConfig = (value, source = "configuration") => {
  if (!isObject(value)) throw new Error(`${source} must contain a JSON object`)
  assertKnownKeys(value, configKeys, source)

  if (value.schemaVersion !== undefined && value.schemaVersion !== configSchemaVersion) {
    throw new Error(`${source} schemaVersion must be ${configSchemaVersion}`)
  }

  if (value.ignore !== undefined && (!Array.isArray(value.ignore) || value.ignore.some(item => typeof item !== "string" || item.length === 0))) {
    throw new Error(`${source} ignore must be an array of non-empty strings`)
  }

  if (value.allow !== undefined) {
    if (!Array.isArray(value.allow)) throw new Error(`${source} allow must be an array`)
    for (const [index, rule] of value.allow.entries()) {
      if (!isObject(rule)) throw new Error(`${source} allow[${index}] must be an object`)
      assertKnownKeys(rule, allowKeys, `${source} allow[${index}]`)
      if (!rule.rule && !rule.path) throw new Error(`${source} allow[${index}] must specify rule, path, or both`)
      if (rule.rule !== undefined && (typeof rule.rule !== "string" || rule.rule.length === 0)) throw new Error(`${source} allow[${index}].rule must be a non-empty string`)
      if (rule.path !== undefined && (typeof rule.path !== "string" || rule.path.length === 0)) throw new Error(`${source} allow[${index}].path must be a non-empty string`)
    }
  }

  if (value.maxFileSize !== undefined) assertPositiveInteger(value.maxFileSize, `${source} maxFileSize`)
  if (value.largeFileSize !== undefined) assertPositiveInteger(value.largeFileSize, `${source} largeFileSize`)
  if (value.concurrency !== undefined) {
    assertPositiveInteger(value.concurrency, `${source} concurrency`)
    if (value.concurrency > 64) throw new Error(`${source} concurrency must be 64 or less`)
  }

  if (value.entropy !== undefined) {
    if (!isObject(value.entropy)) throw new Error(`${source} entropy must be an object`)
    assertKnownKeys(value.entropy, entropyKeys, `${source} entropy`)
    if (value.entropy.enabled !== undefined && typeof value.entropy.enabled !== "boolean") throw new Error(`${source} entropy.enabled must be a boolean`)
    if (value.entropy.minLength !== undefined) {
      assertPositiveInteger(value.entropy.minLength, `${source} entropy.minLength`)
      if (value.entropy.minLength < 20 || value.entropy.minLength > 200) throw new Error(`${source} entropy.minLength must be between 20 and 200`)
    }
    if (value.entropy.threshold !== undefined && (!Number.isFinite(value.entropy.threshold) || value.entropy.threshold < 3 || value.entropy.threshold > 8)) {
      throw new Error(`${source} entropy.threshold must be between 3 and 8`)
    }
  }

  const merged = {
    ...defaults,
    ...value,
    schemaVersion: configSchemaVersion,
    ignore: [...defaults.ignore, ...(value.ignore ?? [])],
    allow: value.allow ?? defaults.allow,
    entropy: { ...defaults.entropy, ...(value.entropy ?? {}) }
  }

  if (merged.largeFileSize < merged.maxFileSize) throw new Error(`${source} largeFileSize must be greater than or equal to maxFileSize`)
  return merged
}

const readJson = async file => {
  const content = await readFile(file, "utf8")
  try {
    return JSON.parse(content)
  } catch {
    throw new Error("contains invalid JSON")
  }
}

export const loadConfig = async (root, configPath) => {
  const file = configPath ? path.resolve(configPath) : path.join(root, ".shareguard.json")
  let user = {}

  try {
    user = await readJson(file)
  } catch (error) {
    if (error.code !== "ENOENT") throw new Error(error.message === "contains invalid JSON" ? "Could not read configuration: contains invalid JSON" : "Could not read configuration")
  }

  return validateConfig(user, configPath ? path.basename(configPath) : ".shareguard.json")
}

export const loadGitignore = async root => {
  try {
    return (await readFile(path.join(root, ".gitignore"), "utf8")).split(/\r?\n/)
  } catch (error) {
    if (error.code === "ENOENT") return []
    throw new Error("Could not read .gitignore")
  }
}

export const loadBaseline = async file => {
  if (!file) return new Set()

  try {
    const data = await readJson(path.resolve(file))
    if (!isObject(data)) throw new Error("baseline must contain a JSON object")
    if ((data.schemaVersion !== undefined && data.schemaVersion !== 1) || (data.version !== undefined && data.version !== 1)) throw new Error("unsupported schemaVersion")
    if (!Array.isArray(data.findings) || data.findings.some(item => typeof item !== "string")) throw new Error("findings must be an array of fingerprints")
    return new Set(data.findings)
  } catch (error) {
    if (error.code === "ENOENT") throw new Error("Baseline file does not exist")
    if (["unsupported schemaVersion", "findings must be an array of fingerprints", "baseline must contain a JSON object", "contains invalid JSON"].includes(error.message)) {
      throw new Error(`Could not read baseline: ${error.message}`)
    }
    throw new Error("Could not read baseline")
  }
}
