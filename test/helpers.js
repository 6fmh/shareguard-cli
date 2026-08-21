import { mkdtemp, mkdir, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"
import { Readable } from "node:stream"
import { run } from "../src/cli.js"

export const fixture = async files => {
  const root = await mkdtemp(path.join(os.tmpdir(), "shareguard-test-"))
  for (const [name, content] of Object.entries(files)) {
    const file = path.join(root, name)
    await mkdir(path.dirname(file), { recursive: true })
    await writeFile(file, content)
  }
  return root
}

export const generated = (prefix, length) => {
  const alphabet = "Ab3xY7mN2pQr5Tuv8Wz0Cde4Fgh6JkLs"
  return prefix + Array.from({ length }, (_, index) => alphabet[(index * 7 + 3) % alphabet.length]).join("")
}

export const hex = length => Array.from({ length }, (_, index) => "0123456789abcdef"[(index * 7 + 5) % 16]).join("")

export const runCli = async (args, options = {}) => {
  let stdout = ""
  const io = {
    stdin: Readable.from(options.input === undefined ? [] : [Buffer.from(options.input)]),
    stdout: { write: value => { stdout += value } }
  }
  try {
    return { status: await run(args, io), stdout, stderr: "" }
  } catch (error) {
    return { status: 2, stdout, stderr: error.message }
  }
}
