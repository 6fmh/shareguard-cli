import { mkdtemp, mkdir, writeFile } from "node:fs/promises"
import os from "node:os"
import path from "node:path"

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
