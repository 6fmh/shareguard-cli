import path from "node:path"

const escapeRegex = value => value.replace(/[|\\{}()[\]^$+?.]/g, "\\$&")

export const globToRegex = glob => {
  const normalized = glob.replaceAll("\\", "/").replace(/^\.\//, "").replace(/^\//, "")
  let source = ""

  for (let index = 0; index < normalized.length; index += 1) {
    const character = normalized[index]

    if (character === "*") {
      if (normalized[index + 1] === "*") {
        index += 1
        source += normalized[index + 1] === "/" ? "(?:.*/)?" : ".*"
        if (normalized[index + 1] === "/") index += 1
      } else {
        source += "[^/]*"
      }
    } else if (character === "?") {
      source += "[^/]"
    } else {
      source += escapeRegex(character)
    }
  }

  const hasSlash = normalized.includes("/")
  const directory = normalized.endsWith("/")
  const prefix = hasSlash ? "^" : "(?:^|/)"
  const suffix = directory ? ".*$" : "(?:$|/.*$)"
  return new RegExp(prefix + source.replace(/\/$/, "") + suffix)
}

export const createIgnoreMatcher = patterns => {
  const rules = patterns
    .map(value => value.trim())
    .filter(value => value && !value.startsWith("#"))
    .map(value => ({
      negate: value.startsWith("!"),
      regex: globToRegex(value.replace(/^!/, ""))
    }))

  return relativePath => {
    const normalized = relativePath.split(path.sep).join("/")
    let ignored = false

    for (const rule of rules) {
      if (rule.regex.test(normalized)) ignored = !rule.negate
    }

    return ignored
  }
}
