const secret = "secret"
const privacy = "privacy"

const placeholderValues = new Set([
  "changeme", "change-me", "example", "example-value", "placeholder", "redacted", "replace-me",
  "sample", "test", "test-value", "todo", "your-token", "your_api_key", "xxxxxxxx", "xxxxxxxxxxxx"
])

export const isPlaceholder = value => {
  const normalized = value.toLowerCase().replace(/[\s_]+/g, "-")
  return placeholderValues.has(normalized) || /^(?:change|replace|insert|your|example|sample|test|dummy)(?:[-_].*)?$/i.test(value) || /^([x*]|<[^>]+>){4,}$/i.test(value) || /^(process|import|env|os)\.|\$\{|\{\{/.test(value)
}

const hasCredentialValue = value => !isPlaceholder(value) && value.length >= 12

export const contentRules = [
  {
    id: "private-key",
    category: secret,
    severity: "critical",
    description: "Private key material",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g
  },
  {
    id: "github-token",
    category: secret,
    severity: "critical",
    description: "GitHub access token",
    pattern: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,255})\b/g
  },
  {
    id: "gitlab-token",
    category: secret,
    severity: "critical",
    description: "GitLab personal access token",
    pattern: /\bglpat-[A-Za-z0-9_-]{20,128}\b/g
  },
  {
    id: "aws-access-key",
    category: secret,
    severity: "critical",
    description: "AWS access key ID",
    pattern: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g
  },
  {
    id: "slack-token",
    category: secret,
    severity: "critical",
    description: "Slack token",
    pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,200}\b/g
  },
  {
    id: "stripe-key",
    category: secret,
    severity: "critical",
    description: "Stripe secret key",
    pattern: /\bsk_(?:live|test)_[A-Za-z0-9]{16,200}\b/g
  },
  {
    id: "npm-token",
    category: secret,
    severity: "critical",
    description: "npm access token",
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/g
  },
  {
    id: "sendgrid-api-key",
    category: secret,
    severity: "critical",
    description: "SendGrid API key",
    pattern: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g
  },
  {
    id: "digitalocean-token",
    category: secret,
    severity: "critical",
    description: "DigitalOcean access token",
    pattern: /\bdop_v1_[a-f0-9]{64}\b/g
  },
  {
    id: "pypi-token",
    category: secret,
    severity: "critical",
    description: "PyPI API token",
    pattern: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/g
  },
  {
    id: "google-api-key",
    category: secret,
    severity: "high",
    description: "Google API key",
    pattern: /\bAIza[A-Za-z0-9_-]{35}\b/g
  },
  {
    id: "jwt",
    category: secret,
    severity: "high",
    description: "JSON Web Token",
    pattern: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g
  },
  {
    id: "connection-string-password",
    category: secret,
    severity: "high",
    description: "Password in a connection string",
    pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s:@/]+:([^\s@/]+)@[^\s]+/gi,
    valueGroup: 1,
    validate: hasCredentialValue
  },
  {
    id: "generic-secret",
    category: secret,
    severity: "high",
    description: "Hard-coded credential",
    pattern: /\b(?:[A-Z][A-Z0-9]*[_-])*(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|password|passwd|secret|token)["']?\s*[:=]\s*(?:"([^"\r\n]{12,})"|'([^'\r\n]{12,})'|([A-Za-z0-9+/_=.-]{12,}))/gi,
    extract: match => match[1] ?? match[2] ?? match[3],
    validate: hasCredentialValue
  },
  {
    id: "email-address",
    category: privacy,
    severity: "medium",
    description: "Email address",
    pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi
  },
  {
    id: "windows-user-path",
    category: privacy,
    severity: "medium",
    description: "Local Windows user path",
    pattern: /\b[A-Z]:\\Users\\[^\\\s"'<>]+/gi
  },
  {
    id: "unix-home-path",
    category: privacy,
    severity: "medium",
    description: "Local Unix home path",
    pattern: /(?:^|[\s"'=:(])\/(?:Users|home)\/[^/\s"'<>]+/g,
    trimPrefix: true
  },
  {
    id: "ipv4-address",
    category: privacy,
    severity: "low",
    description: "IPv4 address",
    pattern: /\b(?!(?:0|127|192\.0\.2|198\.51\.100|203\.0\.113)\.)(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g
  }
]

export const riskyFileRules = [
  { id: "dotenv-file", category: secret, severity: "high", description: "Environment file", pattern: /(?:^|\/)\.env(?:\..+)?$/i, except: /\.example$|\.sample$|\.template$/i },
  { id: "private-key-file", category: secret, severity: "critical", description: "Private key file", pattern: /(?:^|\/)(?:id_(?:rsa|dsa|ecdsa|ed25519)|.+\.(?:pem|p12|pfx|key))$/i },
  { id: "credential-file", category: secret, severity: "high", description: "Credential configuration file", pattern: /(?:^|\/)(?:credentials|secrets?\.json|\.npmrc|\.pypirc|\.netrc|kubeconfig)$/i }
]

export const entropyRule = {
  id: "high-entropy-secret",
  category: secret,
  severity: "medium",
  description: "High-entropy credential-like value"
}

export const allRules = [...contentRules, ...riskyFileRules, entropyRule, {
  id: "large-file",
  category: "hygiene",
  severity: "medium",
  description: "Large file"
}]

export const ruleById = new Map(allRules.map(rule => [rule.id, rule]))
export const categories = [...new Set(allRules.map(rule => rule.category))].sort()

export const resolveRuleSelection = ({ includeRules = [], excludeRules = [], selectedCategories = [] } = {}) => {
  for (const rule of [...includeRules, ...excludeRules]) {
    if (!ruleById.has(rule)) throw new Error(`Unknown rule: ${rule}`)
  }
  for (const category of selectedCategories) {
    if (!categories.includes(category)) throw new Error(`Unknown category: ${category}`)
  }

  const include = new Set(includeRules)
  const exclude = new Set(excludeRules)
  const categorySet = new Set(selectedCategories)
  return rule => (include.size === 0 || include.has(rule.id)) && (categorySet.size === 0 || categorySet.has(rule.category)) && !exclude.has(rule.id)
}

export const severityRank = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
}
