import { createHash } from "node:crypto"
import { lstat, readdir, readFile } from "node:fs/promises"
import path from "node:path"
import { loadGitignore } from "./config.js"
import { getChangedFiles, getObjectSize, getStagedEntries, readObject } from "./git.js"
import { createIgnoreMatcher, globToRegex } from "./ignore.js"
import { contentRules, entropyRule, largeFileRule, resolveRuleSelection, riskyFileRules } from "./rules.js"
import { createSuppressions } from "./suppress.js"

const binaryExtensions = new Set([
  ".7z", ".avi", ".bmp", ".class", ".dll", ".doc", ".docx", ".eot", ".exe", ".gif", ".gz",
  ".ico", ".jar", ".jpeg", ".jpg", ".mov", ".mp3", ".mp4", ".otf", ".pdf", ".png", ".ppt",
  ".pptx", ".rar", ".so", ".tar", ".ttf", ".wav", ".webm", ".webp", ".woff", ".woff2", ".xls",
  ".xlsx", ".zip"
])

const defaultGitOperations = { getStagedEntries, getObjectSize, readObject, getChangedFiles }

const normalize = value => value.split(path.sep).join("/")
const fingerprint = (rule, file, value) => createHash("sha256").update(`${rule}\0${file}\0${value}`).digest("hex").slice(0, 24)
const looksBinary = buffer => buffer.subarray(0, 8000).includes(0)

// Precompute line starts once per file so each finding resolves its line in O(log n)
// instead of slicing the whole prefix, which is quadratic on match-dense content.
const createLineLookup = content => {
  const starts = [0]
  for (let index = content.indexOf("\n"); index !== -1; index = content.indexOf("\n", index + 1)) starts.push(index + 1)

  return offset => {
    let low = 0
    let high = starts.length - 1
    while (low < high) {
      const middle = (low + high + 1) >> 1
      if (starts[middle] <= offset) low = middle
      else high = middle - 1
    }
    return low + 1
  }
}

const isAllowed = (finding, allowRules) => allowRules.some(rule => {
  if (rule.rule && rule.rule !== finding.rule) return false
  if (rule.path && !globToRegex(rule.path).test(finding.file)) return false
  return Boolean(rule.rule || rule.path)
})

const decodeText = buffer => {
  if (buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe) return new TextDecoder("utf-16le", { fatal: true }).decode(buffer.subarray(2))
  if (buffer.length >= 2 && buffer[0] === 0xfe && buffer[1] === 0xff) {
    const pairs = Math.floor((buffer.length - 2) / 2)
    const swapped = Buffer.alloc(pairs * 2)
    for (let index = 0; index < pairs; index += 1) {
      swapped[index * 2] = buffer[3 + index * 2]
      swapped[index * 2 + 1] = buffer[2 + index * 2]
    }
    return new TextDecoder("utf-16le", { fatal: true }).decode(swapped)
  }
  if (looksBinary(buffer)) return null
  return new TextDecoder("utf-8", { fatal: true }).decode(buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf ? buffer.subarray(3) : buffer)
}

const entropy = value => {
  const counts = new Map()
  for (const character of value) counts.set(character, (counts.get(character) ?? 0) + 1)
  let score = 0
  for (const count of counts.values()) {
    const probability = count / value.length
    score -= probability * Math.log2(probability)
  }
  return score
}

const isEntropyCandidate = (value, threshold, context) => {
  if (!/(?:secret|token|password|credential|api[_-]?key|private[_-]?key|authorization|bearer)/i.test(context)) return false
  if (/^[a-f0-9]+$/i.test(value) || /(.)\1{7}/.test(value)) return false
  const classes = [/[a-z]/.test(value), /[A-Z]/.test(value), /\d/.test(value), /[+/_=-]/.test(value)].filter(Boolean).length
  return classes >= 3 && entropy(value) >= threshold
}

const mapConcurrent = async (items, concurrency, worker) => {
  let next = 0
  const run = async () => {
    while (next < items.length) {
      const index = next
      next += 1
      await worker(items[index])
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, run))
}

const createDiagnostic = (code, file, severity = "error") => ({
  code,
  severity,
  file,
  message: code === "unreadable-directory" ? "Could not read directory" : code === "unreadable-file" ? "Could not read file" : "Unsupported text encoding"
})

const collectFilesystemEntries = async (root, ignored, stats, diagnostics) => {
  const entries = []
  let rootStats

  try {
    rootStats = await lstat(root)
  } catch {
    throw new Error("Scan path does not exist or cannot be read")
  }

  if (rootStats.isFile()) {
    entries.push({ relative: path.basename(root), size: rootStats.size, read: () => readFile(root) })
    return entries
  }
  if (!rootStats.isDirectory()) throw new Error("Scan path must be a file or directory")

  const walk = async directory => {
    let children
    try {
      children = await readdir(directory, { withFileTypes: true })
    } catch {
      const relative = normalize(path.relative(root, directory)) || "."
      diagnostics.push(createDiagnostic("unreadable-directory", relative))
      stats.errors += 1
      return
    }

    for (const child of children) {
      const absolute = path.join(directory, child.name)
      const relative = normalize(path.relative(root, absolute))

      if (child.isSymbolicLink()) {
        stats.skipped += 1
        stats.symlinks += 1
        continue
      }

      if (child.isDirectory()) {
        if (ignored(relative) && !ignored.shouldDescend(relative)) {
          stats.ignored += 1
          continue
        }
        await walk(absolute)
        continue
      }

      if (!child.isFile()) {
        stats.skipped += 1
        continue
      }
      if (ignored(relative)) {
        stats.ignored += 1
        continue
      }

      try {
        const fileStats = await lstat(absolute)
        entries.push({ relative, size: fileStats.size, read: () => readFile(absolute) })
      } catch {
        diagnostics.push(createDiagnostic("unreadable-file", relative))
        stats.errors += 1
      }
    }
  }

  await walk(root)
  return entries
}

const collectStagedEntries = async (root, ignored, stats, diagnostics, concurrency, gitOperations) => {
  const staged = await gitOperations.getStagedEntries(root)
  const entries = []

  await mapConcurrent(staged.entries, concurrency, async entry => {
    if (ignored(entry.relative)) {
      stats.ignored += 1
      return
    }
    if (entry.mode === "120000" || entry.mode === "160000") {
      stats.skipped += 1
      stats.symlinks += entry.mode === "120000" ? 1 : 0
      return
    }
    try {
      const size = await gitOperations.getObjectSize(staged.repositoryRoot, entry.object)
      entries.push({
        relative: entry.relative,
        size,
        read: () => gitOperations.readObject(staged.repositoryRoot, entry.object, Math.max(size + 1024, 1_000_000))
      })
    } catch {
      diagnostics.push(createDiagnostic("unreadable-file", entry.relative))
      stats.errors += 1
    }
  })

  return entries
}

const collectChangedEntries = async (root, reference, ignored, stats, diagnostics, gitOperations) => {
  const changed = await gitOperations.getChangedFiles(root, reference)
  const entries = []

  for (const relative of changed.files) {
    if (!relative) continue
    if (ignored(relative)) {
      stats.ignored += 1
      continue
    }

    const absolute = path.join(root, relative)
    try {
      const fileStats = await lstat(absolute)
      if (fileStats.isSymbolicLink()) {
        stats.skipped += 1
        stats.symlinks += 1
        continue
      }
      if (!fileStats.isFile()) {
        stats.skipped += 1
        continue
      }
      entries.push({ relative, size: fileStats.size, read: () => readFile(absolute) })
    } catch (error) {
      if (error.code === "ENOENT") {
        stats.skipped += 1
        continue
      }
      diagnostics.push(createDiagnostic("unreadable-file", relative))
      stats.errors += 1
    }
  }

  return entries
}

export const scan = async ({
  root,
  config,
  useGitignore = true,
  baseline = new Set(),
  staged = false,
  since,
  stdinContent,
  stdinFilename = "stdin",
  includeRules = [],
  excludeRules = [],
  selectedCategories = [],
  gitOperations = defaultGitOperations
}) => {
  const absoluteRoot = path.resolve(root)
  let ignoreRoot = absoluteRoot
  if (useGitignore && !staged && stdinContent === undefined) {
    try {
      if ((await lstat(absoluteRoot)).isFile()) ignoreRoot = path.dirname(absoluteRoot)
    } catch {
      ignoreRoot = absoluteRoot
    }
  }
  const gitignore = useGitignore && !staged && stdinContent === undefined ? await loadGitignore(ignoreRoot) : []
  const ignored = createIgnoreMatcher([...config.ignore, ...gitignore])
  const selected = resolveRuleSelection({ includeRules, excludeRules, selectedCategories })
  const findings = []
  const diagnostics = []
  const baselineEntries = new Map()
  const stats = { files: 0, bytes: 0, skipped: 0, ignored: 0, symlinks: 0, suppressed: 0, errors: 0, baselined: 0 }

  const add = finding => {
    if (isAllowed(finding, config.allow)) return false
    baselineEntries.set(finding.fingerprint, { fingerprint: finding.fingerprint, rule: finding.rule, file: finding.file })
    if (baseline.has(finding.fingerprint)) {
      stats.baselined += 1
      return false
    }
    findings.push(finding)
    return true
  }

  let entries
  let input
  if (stdinContent !== undefined) {
    const buffer = Buffer.isBuffer(stdinContent) ? stdinContent : Buffer.from(stdinContent)
    entries = [{ relative: normalize(stdinFilename), size: buffer.length, read: async () => buffer }]
    input = "stdin"
  } else if (staged) {
    entries = await collectStagedEntries(absoluteRoot, createIgnoreMatcher(config.ignore), stats, diagnostics, config.concurrency, gitOperations)
    input = "staged"
  } else if (since !== undefined) {
    entries = await collectChangedEntries(absoluteRoot, since, ignored, stats, diagnostics, gitOperations)
    input = "changed"
  } else {
    entries = await collectFilesystemEntries(absoluteRoot, ignored, stats, diagnostics)
    input = "filesystem"
  }

  await mapConcurrent(entries, config.concurrency, async entry => {
    const relative = normalize(entry.relative)
    stats.files += 1
    stats.bytes += entry.size

    for (const rule of riskyFileRules) {
      if (selected(rule) && rule.pattern.test(relative) && !rule.except?.test(relative)) {
        add({
          rule: rule.id,
          category: rule.category,
          severity: rule.severity,
          description: rule.description,
          file: relative,
          line: null,
          preview: null,
          fingerprint: fingerprint(rule.id, relative, "filename")
        })
      }
    }

    if (selected(largeFileRule) && entry.size > config.largeFileSize) {
      add({
        rule: largeFileRule.id,
        category: largeFileRule.category,
        severity: largeFileRule.severity,
        description: `${largeFileRule.description} (${(entry.size / 1_000_000).toFixed(1)} MB)`,
        file: relative,
        line: null,
        preview: null,
        fingerprint: fingerprint("large-file", relative, String(entry.size))
      })
    }

    if (entry.size > config.maxFileSize || binaryExtensions.has(path.extname(relative).toLowerCase())) {
      stats.skipped += 1
      return
    }

    let buffer
    try {
      buffer = await entry.read()
    } catch {
      diagnostics.push(createDiagnostic("unreadable-file", relative))
      stats.errors += 1
      return
    }

    let content
    try {
      content = decodeText(buffer)
    } catch {
      diagnostics.push(createDiagnostic("unsupported-encoding", relative, "warning"))
      stats.skipped += 1
      return
    }
    if (content === null) {
      stats.skipped += 1
      return
    }

    const secretSpans = []
    const lineAt = createLineLookup(content)
    const suppressed = createSuppressions(content)
    for (const rule of contentRules) {
      if (!selected(rule)) continue
      rule.pattern.lastIndex = 0
      let match

      while ((match = rule.pattern.exec(content)) !== null) {
        const value = rule.extract ? rule.extract(match) : rule.valueGroup ? match[rule.valueGroup] : match[0]
        if (rule.validate && !rule.validate(value)) continue
        const valueOffset = rule.extract || rule.valueGroup ? match[0].indexOf(value) : 0
        const index = match.index + valueOffset + (rule.trimPrefix ? 1 : 0)
        const safeValue = rule.trimPrefix ? value.slice(1) : value
        const end = index + safeValue.length
        if (rule.category === "secret" && secretSpans.some(([start, previousEnd]) => index < previousEnd && end > start)) continue
        const line = lineAt(index)
        if (suppressed?.(rule.id, line)) {
          stats.suppressed += 1
          if (rule.category === "secret") secretSpans.push([index, end])
          continue
        }
        const finding = {
          rule: rule.id,
          category: rule.category,
          severity: rule.severity,
          description: rule.description,
          file: relative,
          line,
          preview: null,
          fingerprint: fingerprint(rule.id, relative, safeValue)
        }
        add(finding)
        if (rule.category === "secret") secretSpans.push([index, end])
        if (match[0].length === 0) rule.pattern.lastIndex += 1
      }
    }

    if (config.entropy.enabled && selected(entropyRule)) {
      const pattern = new RegExp(`["']([A-Za-z0-9+/_=-]{${config.entropy.minLength},200})["']`, "g")
      let match
      while ((match = pattern.exec(content)) !== null) {
        const value = match[1]
        const index = match.index + 1
        if (secretSpans.some(([start, end]) => index < end && index + value.length > start)) continue
        const lineStart = content.lastIndexOf("\n", index - 1) + 1
        const context = content.slice(lineStart, index)
        if (!isEntropyCandidate(value, config.entropy.threshold, context)) continue
        const line = lineAt(index)
        if (suppressed?.(entropyRule.id, line)) {
          stats.suppressed += 1
          continue
        }
        add({
          rule: entropyRule.id,
          category: entropyRule.category,
          severity: entropyRule.severity,
          description: entropyRule.description,
          file: relative,
          line,
          preview: null,
          fingerprint: fingerprint(entropyRule.id, relative, value)
        })
      }
    }
  })

  findings.sort((a, b) => a.file.localeCompare(b.file) || (a.line ?? 0) - (b.line ?? 0) || a.rule.localeCompare(b.rule))
  diagnostics.sort((a, b) => a.file.localeCompare(b.file) || a.code.localeCompare(b.code))
  const baselineItems = [...baselineEntries.values()].sort((a, b) => a.file.localeCompare(b.file) || a.rule.localeCompare(b.rule))
  return { input, findings, diagnostics, stats, baselineEntries: baselineItems }
}
