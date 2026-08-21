#!/usr/bin/env node

import { spawnSync } from "node:child_process"
import { readdir } from "node:fs/promises"
import path from "node:path"
import process from "node:process"

const roots = ["src", "test", "scripts"]

const collect = async directory => {
  const files = []
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const target = path.join(directory, entry.name)
    if (entry.isDirectory()) files.push(...(await collect(target)))
    else if (entry.isFile() && entry.name.endsWith(".js")) files.push(target)
  }
  return files
}

const files = (await Promise.all(roots.map(collect))).flat().sort()
const failed = []

for (const file of files) {
  const result = spawnSync(process.execPath, ["--check", file], { encoding: "utf8" })
  if (result.status !== 0) {
    failed.push(file)
    process.stderr.write(result.stderr || `Could not parse ${file}\n`)
  }
}

process.stdout.write(`checked ${files.length} files, ${failed.length} failed\n`)
process.exitCode = failed.length === 0 ? 0 : 1
