import { createHash } from "node:crypto"
import { lstat, readdir, readFile } from "node:fs/promises"
import path from "node:path"
import { contentRules, riskyFileRules } from "./rules.js"
import { createIgnoreMatcher, globToRegex } from "./ignore.js"
import { loadGitignore } from "./config.js"

const binaryExtensions = new Set([
  ".7z", ".avi", ".bmp", ".class", ".dll", ".doc", ".docx", ".eot", ".exe", ".gif", ".gz",
  ".ico", ".jar", ".jpeg", ".jpg", ".mov", ".mp3", ".mp4", ".otf", ".pdf", ".png", ".ppt",
  ".pptx", ".rar", ".so", ".tar", ".ttf", ".wav", ".webm", ".webp", ".woff", ".woff2", ".xls",
  ".xlsx", ".zip"
])

const normalize = value => value.split(path.sep).join("/")
const fingerprint = (rule, file, value) => createHash("sha256").update(`${rule}\0${file}\0${value}`).digest("hex").slice(0, 24)
const lineNumberAt = (content, index) => content.slice(0, index).split("\n").length
const redact = (line, value) => line.replace(value, "[REDACTED]").trim().slice(0, 180)
const looksBinary = buffer => buffer.subarray(0, 8000).includes(0)

const isAllowed = (finding, allowRules) => allowRules.some(rule => {
  if (rule.rule && rule.rule !== finding.rule) return false
  if (rule.path && !globToRegex(rule.path).test(finding.file)) return false
  return Boolean(rule.rule || rule.path)
})

const walk = async (root, ignored, visit) => {
  const entries = await readdir(root, { withFileTypes: true })

  for (const entry of entries) {
    const absolute = path.join(root, entry.name)
    const relative = normalize(path.relative(visit.root, absolute))
    if (ignored(relative + (entry.isDirectory() ? "/" : ""))) continue
    if (entry.isSymbolicLink()) continue

    if (entry.isDirectory()) {
      await walk(absolute, ignored, visit)
    } else if (entry.isFile()) {
      await visit(absolute, relative)
    }
  }
}

export const scan = async ({ root, config, useGitignore = true, baseline = new Set() }) => {
  const absoluteRoot = path.resolve(root)
  const gitignore = useGitignore ? await loadGitignore(absoluteRoot) : []
  const ignored = createIgnoreMatcher([...config.ignore, ...gitignore])
  const findings = []
  const stats = { files: 0, bytes: 0, skipped: 0, baselined: 0 }

  const add = finding => {
    if (isAllowed(finding, config.allow)) return
    if (baseline.has(finding.fingerprint)) {
      stats.baselined += 1
      return
    }
    findings.push(finding)
  }

  const visit = async (absolute, relative) => {
    const fileStats = await lstat(absolute)
    stats.files += 1
    stats.bytes += fileStats.size

    for (const rule of riskyFileRules) {
      if (rule.pattern.test(relative) && !rule.except?.test(relative)) {
        add({
          rule: rule.id,
          category: "secret",
          severity: rule.severity,
          description: rule.description,
          file: relative,
          line: null,
          preview: null,
          fingerprint: fingerprint(rule.id, relative, "filename")
        })
      }
    }

    if (fileStats.size > config.largeFileSize) {
      add({
        rule: "large-file",
        category: "hygiene",
        severity: "medium",
        description: `Large file (${(fileStats.size / 1_000_000).toFixed(1)} MB)`,
        file: relative,
        line: null,
        preview: null,
        fingerprint: fingerprint("large-file", relative, String(fileStats.size))
      })
    }

    if (fileStats.size > config.maxFileSize || binaryExtensions.has(path.extname(relative).toLowerCase())) {
      stats.skipped += 1
      return
    }

    const buffer = await readFile(absolute)
    if (looksBinary(buffer)) {
      stats.skipped += 1
      return
    }

    const content = buffer.toString("utf8")
    const lines = content.split(/\r?\n/)

    for (const rule of contentRules) {
      rule.pattern.lastIndex = 0
      let match

      while ((match = rule.pattern.exec(content)) !== null) {
        const value = rule.valueGroup ? match[rule.valueGroup] : match[0]
        const valueOffset = rule.valueGroup ? match[0].indexOf(value) : 0
        const index = match.index + valueOffset + (rule.trimPrefix ? 1 : 0)
        const safeValue = rule.trimPrefix ? value.slice(1) : value
        const line = lineNumberAt(content, index)

        add({
          rule: rule.id,
          category: rule.category,
          severity: rule.severity,
          description: rule.description,
          file: relative,
          line,
          preview: redact(lines[line - 1] ?? "", safeValue),
          fingerprint: fingerprint(rule.id, relative, safeValue)
        })

        if (match[0].length === 0) rule.pattern.lastIndex += 1
      }
    }
  }

  visit.root = absoluteRoot
  await walk(absoluteRoot, ignored, visit)

  findings.sort((a, b) => a.file.localeCompare(b.file) || (a.line ?? 0) - (b.line ?? 0) || a.rule.localeCompare(b.rule))
  return { root: absoluteRoot, findings, stats }
}
