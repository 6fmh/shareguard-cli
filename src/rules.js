const secret = "secret"
const privacy = "privacy"

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
    pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s:@/]+:[^\s@/]+@[^\s]+/gi
  },
  {
    id: "generic-secret",
    category: secret,
    severity: "high",
    description: "Hard-coded credential",
    pattern: /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|secret)["']?\s*[:=]\s*["']([^"'\s]{12,})["']/gi,
    valueGroup: 1
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
    pattern: /\b(?!(?:127|0)\.)(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g
  }
]

export const riskyFileRules = [
  { id: "dotenv-file", severity: "high", description: "Environment file", pattern: /(?:^|\/)\.env(?:\..+)?$/i, except: /\.example$|\.sample$|\.template$/i },
  { id: "private-key-file", severity: "critical", description: "Private key file", pattern: /(?:^|\/)(?:id_(?:rsa|dsa|ecdsa|ed25519)|.+\.(?:pem|p12|pfx|key))$/i },
  { id: "credential-file", severity: "high", description: "Credential configuration file", pattern: /(?:^|\/)(?:credentials|secrets?\.json|\.npmrc|\.pypirc|\.netrc|kubeconfig)$/i }
]

export const severityRank = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
}
