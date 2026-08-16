import path from "node:path"

const escapeRegex = value => value.replace(/[|\\{}()[\]^$+?.]/g, "\\$&")
const normalize = value => value.split(path.sep).join("/").replace(/^\.\//, "").replace(/^\//, "")

const parsePattern = raw => {
  let value = raw.replace(/(?<!\\)\s+$/, "").replace(/\\ $/, " ")
  if (!value || value.startsWith("#")) return null

  let negate = false
  if (value.startsWith("!")) {
    negate = true
    value = value.slice(1)
  } else if (value.startsWith("\\!") || value.startsWith("\\#")) {
    value = value.slice(1)
  }

  return value ? { value, negate } : null
}

export const globToRegex = glob => {
  const anchored = glob.replaceAll("\\", "/").replace(/^\.\//, "").startsWith("/")
  const normalized = normalize(glob)
  const directory = normalized.endsWith("/")
  const body = normalized.replace(/\/$/, "")
  let source = ""

  for (let index = 0; index < body.length; index += 1) {
    const character = body[index]

    if (character === "*") {
      if (body[index + 1] === "*") {
        index += 1
        source += body[index + 1] === "/" ? "(?:.*/)?" : ".*"
        if (body[index + 1] === "/") index += 1
      } else {
        source += "[^/]*"
      }
    } else if (character === "?") {
      source += "[^/]"
    } else {
      source += escapeRegex(character)
    }
  }

  const hasSlash = anchored || body.includes("/")
  const prefix = hasSlash ? "^" : "(?:^|/)"
  const suffix = directory ? "(?:/.*)?$" : "(?:$|/.*$)"
  return new RegExp(prefix + source + suffix)
}

const staticPrefix = pattern => {
  const normalized = normalize(pattern).replace(/\/$/, "")
  const wildcard = normalized.search(/[?*[]/)
  return wildcard === -1 ? normalized : normalized.slice(0, wildcard)
}

export const createIgnoreMatcher = patterns => {
  const rules = patterns
    .map(parsePattern)
    .filter(Boolean)
    .map(rule => ({ ...rule, regex: globToRegex(rule.value), prefix: staticPrefix(rule.value) }))

  const matcher = relativePath => {
    const normalized = normalize(relativePath).replace(/\/$/, "")
    let ignored = false

    for (const rule of rules) {
      if (rule.regex.test(normalized)) ignored = !rule.negate
    }

    return ignored
  }

  matcher.shouldDescend = relativePath => {
    const normalized = `${normalize(relativePath).replace(/\/$/, "")}/`
    return rules.some(rule => rule.negate && (!rule.prefix || rule.prefix.startsWith(normalized)))
  }

  return matcher
}
