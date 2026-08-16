import { readFile } from "node:fs/promises"
import path from "node:path"

export const defaults = {
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
  largeFileSize: 10_000_000
}

const readJson = async file => JSON.parse(await readFile(file, "utf8"))

export const loadConfig = async (root, configPath) => {
  const file = configPath ? path.resolve(configPath) : path.join(root, ".shareguard.json")
  let user = {}

  try {
    user = await readJson(file)
  } catch (error) {
    if (error.code !== "ENOENT") throw new Error(`Could not read ${file}: ${error.message}`)
  }

  return {
    ...defaults,
    ...user,
    ignore: [...defaults.ignore, ...(user.ignore ?? [])],
    allow: user.allow ?? defaults.allow
  }
}

export const loadGitignore = async root => {
  try {
    return (await readFile(path.join(root, ".gitignore"), "utf8")).split(/\r?\n/)
  } catch (error) {
    if (error.code === "ENOENT") return []
    throw error
  }
}

export const loadBaseline = async file => {
  if (!file) return new Set()

  try {
    const data = await readJson(path.resolve(file))
    return new Set(data.findings ?? [])
  } catch (error) {
    if (error.code === "ENOENT") return new Set()
    throw new Error(`Could not read baseline: ${error.message}`)
  }
}
