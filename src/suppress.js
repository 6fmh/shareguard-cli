import { ruleById } from "./rules.js"

const directivePattern = /shareguard-ignore(-next-line|-line|-file)?\b[ \t]*[:=]?[ \t]*([^\r\n]*)/gi
const everyRule = "*"

const parseScope = value => {
  const tokens = value.split(/[^A-Za-z0-9_-]+/).filter(Boolean).map(token => token.toLowerCase())
  if (tokens.length === 0 || !tokens.every(token => ruleById.has(token))) return everyRule
  return new Set(tokens)
}

const mergeScopes = (existing, scope) => {
  if (existing === undefined) return scope
  if (existing === everyRule || scope === everyRule) return everyRule
  return new Set([...existing, ...scope])
}

export const createSuppressions = content => {
  if (!content.toLowerCase().includes("shareguard-ignore")) return null

  const lines = content.split(/\r?\n/)
  const lineScopes = new Map()
  let fileScope

  for (const [index, text] of lines.entries()) {
    directivePattern.lastIndex = 0
    let match

    while ((match = directivePattern.exec(text)) !== null) {
      const scope = parseScope(match[2] ?? "")
      if (match[1] === "-file") fileScope = mergeScopes(fileScope, scope)
      else {
        const line = index + (match[1] === "-next-line" ? 2 : 1)
        lineScopes.set(line, mergeScopes(lineScopes.get(line), scope))
      }
    }
  }

  if (fileScope === undefined && lineScopes.size === 0) return null

  return (rule, line) => {
    if (fileScope === everyRule || (fileScope !== undefined && fileScope.has(rule))) return true
    const scope = lineScopes.get(line)
    return scope === everyRule || (scope !== undefined && scope.has(rule))
  }
}
