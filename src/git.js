import { execFile } from "node:child_process"
import { promisify } from "node:util"
import path from "node:path"

const execute = promisify(execFile)
const normalize = value => value.split(path.sep).join("/")

const git = async (cwd, args, options = {}) => {
  try {
    const encoding = Object.hasOwn(options, "encoding") ? options.encoding : "utf8"
    const result = await execute("git", ["-C", cwd, ...args], {
      encoding,
      maxBuffer: options.maxBuffer ?? 50_000_000,
      windowsHide: true
    })
    return result.stdout
  } catch {
    throw new Error("Git command failed")
  }
}

const parseIndex = value => {
  const entries = new Map()

  for (const record of value.split("\0")) {
    if (!record) continue
    const match = /^(\d+) ([0-9a-f]+) (\d)\t([\s\S]+)$/.exec(record)
    if (match && match[3] === "0") entries.set(match[4], { mode: match[1], object: match[2] })
  }

  return entries
}

export const getStagedEntries = async (root, run = git) => {
  const repositoryRoot = (await run(root, ["rev-parse", "--show-toplevel"])).trim()
  const prefix = normalize(path.relative(repositoryRoot, path.resolve(root)))
  if (prefix.startsWith("../") || path.isAbsolute(prefix)) throw new Error("Scan path is outside the Git repository")

  const names = (await run(repositoryRoot, ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"]))
    .split("\0")
    .filter(Boolean)
  const index = parseIndex(await run(repositoryRoot, ["ls-files", "--stage", "-z"]))
  const entries = []

  for (const repoRelative of names) {
    if (prefix && repoRelative !== prefix && !repoRelative.startsWith(`${prefix}/`)) continue
    const indexed = index.get(repoRelative)
    if (!indexed) continue
    entries.push({
      relative: prefix ? repoRelative.slice(prefix.length + 1) : repoRelative,
      repoRelative,
      ...indexed
    })
  }

  return { repositoryRoot, entries }
}

export const getObjectSize = async (repositoryRoot, object, run = git) => {
  const output = await run(repositoryRoot, ["cat-file", "-s", object])
  const size = Number.parseInt(output.trim(), 10)
  if (!Number.isSafeInteger(size) || size < 0) throw new Error("Git object has an invalid size")
  return size
}

export const readObject = (repositoryRoot, object, maxBuffer, run = git) => run(repositoryRoot, ["cat-file", "blob", object], { encoding: null, maxBuffer })
