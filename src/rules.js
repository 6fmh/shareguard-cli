const secret = "secret"
const privacy = "privacy"
const hygiene = "hygiene"

const placeholderValues = new Set([
  "changeme", "change-me", "change-this", "changeit", "example", "example-value", "placeholder",
  "redacted", "replace-me", "sample", "test", "test-value", "todo", "your-token", "your-api-key",
  "your-api-key-here", "your-secret", "your-secret-here", "your-password", "your-key", "your-value",
  "xxxxxxxx", "xxxxxxxxxxxx", "foo", "bar", "baz", "qux", "foobar", "none", "null", "nil", "undefined",
  "password", "passwd", "pwd", "secret", "mysecret", "mypassword", "admin", "administrator", "root",
  "user", "username", "guest", "s3cr3t", "notreal", "fake", "fake-value", "faketoken", "not-a-secret",
  "notasecret", "dummy-value", "dummy-secret", "topsecret", "supersecret", "lorem", "ipsum",
  "abc123", "password123", "hunter2", "123456", "12345678", "insert-here", "token-here", "secret-here"
])

const placeholderPrefix = /^(?:change|replace|insert|your|our|example|sample|test|dummy|fake|foo|bar|baz|lorem|ipsum|todo|notreal|placeholder|redacted|secret|password|passwd|admin|root)(?:[-_].*)?$/i
const placeholderShape = /^([x*0]|<[^>]+>){4,}$/i
const placeholderReference = /^(?:process|import|env|os|config|settings|secrets)\.|\$\{|\{\{|^(?:os\.)?getenv\s*\(|^system\.getenv|^env\[|[-_]here$/i

export const isPlaceholder = value => {
  const normalized = value.toLowerCase().replace(/[\s_]+/g, "-")
  return placeholderValues.has(normalized) || placeholderPrefix.test(value) || placeholderShape.test(value) || placeholderReference.test(value)
}

const hasCredentialValue = value => !isPlaceholder(value) && value.length >= 12
const hasUrlCredentialValue = value => !isPlaceholder(value) && value.length >= 8

const sharedWindowsAccounts = /[\\/](?:public|default|defaultuser\d*|all|administrator|guest)$/i

const documentationCards = new Set([
  "4111111111111111", "4012888888881881", "4222222222222", "4000000000000002", "4242424242424242",
  "5555555555554444", "5105105105105100", "5200828282828210", "5555341244441115", "2223003122003222",
  "378282246310005", "371449635398431", "378734493671000", "6011111111111117", "6011000990139424",
  "30569309025904", "38520000023237", "3530111333300000", "3566002020360505"
])

const cardIssuer = /^(?:4|5[1-5]|2[2-7]|3[47]|30[0-5]|3[689]|35|6011|64[4-9]|65)/

const passesLuhn = digits => {
  let sum = 0
  let double = false
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let value = digits.charCodeAt(index) - 48
    if (double) {
      value *= 2
      if (value > 9) value -= 9
    }
    sum += value
    double = !double
  }
  return sum % 10 === 0
}

const isPaymentCard = value => {
  const digits = value.replace(/[ -]/g, "")
  if (digits.length < 13 || digits.length > 19) return false
  if (!cardIssuer.test(digits) || documentationCards.has(digits)) return false
  if (/^(\d)\1+$/.test(digits)) return false
  return passesLuhn(digits)
}

export const contentRules = [
  {
    id: "private-key",
    category: secret,
    severity: "critical",
    description: "Private key material",
    pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED |SSH2 ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g
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
    id: "aws-secret-access-key",
    category: secret,
    severity: "critical",
    description: "AWS secret access key",
    pattern: /\baws[_-]?secret[_-]?access[_-]?key\b["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi,
    valueGroup: 1,
    validate: hasCredentialValue
  },
  {
    id: "azure-storage-key",
    category: secret,
    severity: "critical",
    description: "Azure Storage account key",
    pattern: /\bAccountKey\s*=\s*([A-Za-z0-9+/]{86}==)/g,
    valueGroup: 1,
    validate: hasCredentialValue
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
    description: "Stripe secret or restricted key",
    pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,200}\b/g
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
    id: "rubygems-api-key",
    category: secret,
    severity: "high",
    description: "RubyGems API key",
    pattern: /\brubygems_[0-9a-f]{48}\b/g
  },
  {
    id: "dockerhub-token",
    category: secret,
    severity: "high",
    description: "Docker Hub personal access token",
    pattern: /\bdckr_pat_[A-Za-z0-9_-]{20,64}(?![A-Za-z0-9_-])/g
  },
  {
    id: "google-api-key",
    category: secret,
    severity: "high",
    description: "Google API key",
    pattern: /\bAIza[A-Za-z0-9_-]{35}\b/g
  },
  {
    id: "anthropic-api-key",
    category: secret,
    severity: "critical",
    description: "Anthropic API key",
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g
  },
  {
    id: "openai-api-key",
    category: secret,
    severity: "critical",
    description: "OpenAI API key",
    pattern: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}\b|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g
  },
  {
    id: "openrouter-api-key",
    category: secret,
    severity: "critical",
    description: "OpenRouter API key",
    pattern: /\bsk-or-v1-[0-9a-f]{64}\b/g
  },
  {
    id: "groq-api-key",
    category: secret,
    severity: "critical",
    description: "Groq API key",
    pattern: /\bgsk_[A-Za-z0-9]{40,64}\b/g
  },
  {
    id: "huggingface-token",
    category: secret,
    severity: "high",
    description: "Hugging Face access token",
    pattern: /\bhf_[A-Za-z0-9]{32,40}\b/g
  },
  {
    id: "replicate-api-token",
    category: secret,
    severity: "high",
    description: "Replicate API token",
    pattern: /\br8_[A-Za-z0-9]{35,45}\b/g
  },
  {
    id: "perplexity-api-key",
    category: secret,
    severity: "high",
    description: "Perplexity API key",
    pattern: /\bpplx-[A-Za-z0-9]{32,64}\b/g
  },
  {
    id: "google-oauth-client-secret",
    category: secret,
    severity: "critical",
    description: "Google OAuth client secret",
    pattern: /\bGOCSPX-[A-Za-z0-9_-]{20,}\b/g
  },
  {
    id: "azure-client-secret",
    category: secret,
    severity: "high",
    description: "Azure client secret",
    pattern: /[A-Za-z0-9_~.]{3}[0-9A-Za-z]Q~[A-Za-z0-9_.~-]{31,34}/g
  },
  {
    id: "atlassian-api-token",
    category: secret,
    severity: "critical",
    description: "Atlassian API token",
    pattern: /\bATATT3xFfGF0[A-Za-z0-9_=-]{100,400}(?![A-Za-z0-9_=-])/g
  },
  {
    id: "slack-app-token",
    category: secret,
    severity: "high",
    description: "Slack app-level token",
    pattern: /\bxapp-\d-[A-Za-z0-9]+-[A-Za-z0-9]+-[a-f0-9]{64}\b/g
  },
  {
    id: "slack-webhook-url",
    category: secret,
    severity: "medium",
    description: "Slack incoming webhook URL",
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9]+\/B[A-Za-z0-9]+\/[A-Za-z0-9]{24}/g
  },
  {
    id: "discord-bot-token",
    category: secret,
    severity: "high",
    description: "Discord bot token",
    pattern: /\b[MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,40}\b/g
  },
  {
    id: "telegram-bot-token",
    category: secret,
    severity: "high",
    description: "Telegram bot token",
    pattern: /\b\d{8,10}:[A-Za-z0-9_-]{35}(?![A-Za-z0-9_-])/g
  },
  {
    id: "jwt",
    category: secret,
    severity: "high",
    description: "JSON Web Token",
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/g
  },
  {
    id: "twilio-account-sid",
    category: secret,
    severity: "low",
    description: "Twilio account SID",
    pattern: /\bAC[0-9a-fA-F]{32}\b/g
  },
  {
    id: "twilio-api-key-sid",
    category: secret,
    severity: "medium",
    description: "Twilio API key SID",
    pattern: /\bSK[0-9a-fA-F]{32}\b/g
  },
  {
    id: "hashicorp-vault-token",
    category: secret,
    severity: "high",
    description: "HashiCorp Vault token",
    pattern: /\bhv[sb]\.(?:[A-Za-z0-9]{24}|[A-Za-z0-9_-]{90,240})/g
  },
  {
    id: "terraform-cloud-token",
    category: secret,
    severity: "high",
    description: "Terraform Cloud API token",
    pattern: /\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_=]{60,70}\b/g
  },
  {
    id: "doppler-token",
    category: secret,
    severity: "high",
    description: "Doppler token",
    pattern: /\bdp\.(?:pt|st|sa|said|ct|scim|audit)\.(?:[a-z0-9_-]{2,35}\.)?[A-Za-z0-9]{40,44}\b/g
  },
  {
    id: "grafana-service-account-token",
    category: secret,
    severity: "high",
    description: "Grafana service account token",
    pattern: /\bglsa_[A-Za-z0-9]{32,48}_[0-9a-fA-F]{8}\b/g
  },
  {
    id: "grafana-cloud-token",
    category: secret,
    severity: "high",
    description: "Grafana Cloud access policy token",
    pattern: /\bglc_[A-Za-z0-9+/=_-]{32,400}/g
  },
  {
    id: "cloudflare-api-token",
    category: secret,
    severity: "high",
    description: "Cloudflare API credential",
    pattern: /\bcf(?:k|ut|at)_[A-Za-z0-9]{40,50}\b/g
  },
  {
    id: "square-access-token",
    category: secret,
    severity: "high",
    description: "Square access token or client secret",
    pattern: /\bsq0(?:atp|csp)-[A-Za-z0-9_-]{40,50}\b/g
  },
  {
    id: "shopify-token",
    category: secret,
    severity: "high",
    description: "Shopify access token",
    pattern: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g
  },
  {
    id: "notion-token",
    category: secret,
    severity: "high",
    description: "Notion integration token",
    pattern: /\bntn_[A-Za-z0-9]{40,50}\b|\bsecret_[A-Za-z0-9]{43}\b/g
  },
  {
    id: "linear-api-key",
    category: secret,
    severity: "high",
    description: "Linear API key",
    pattern: /\blin_(?:api|oauth)_[A-Za-z0-9]{40,48}\b/g
  },
  {
    id: "airtable-token",
    category: secret,
    severity: "high",
    description: "Airtable personal access token",
    pattern: /\bpat[A-Za-z0-9]{14}\.[0-9a-f]{64}\b/g
  },
  {
    id: "supabase-token",
    category: secret,
    severity: "high",
    description: "Supabase access token",
    pattern: /\bsbp_[0-9a-f]{40}\b/g
  },
  {
    id: "postman-api-key",
    category: secret,
    severity: "high",
    description: "Postman API key",
    pattern: /\bPMAK-[0-9a-f]{24}-[0-9a-f]{34}\b/g
  },
  {
    id: "figma-token",
    category: secret,
    severity: "high",
    description: "Figma personal access token",
    pattern: /\bfigd_[A-Za-z0-9_-]{40,64}(?![A-Za-z0-9_-])/g
  },
  {
    id: "new-relic-key",
    category: secret,
    severity: "high",
    description: "New Relic API key",
    pattern: /\bNR(?:AK|AA|II)-[A-Za-z0-9]{27}\b/g
  },
  {
    id: "sonarqube-token",
    category: secret,
    severity: "high",
    description: "SonarQube token",
    pattern: /\bsq[apu]_[0-9a-f]{40}\b/g
  },
  {
    id: "sentry-dsn",
    category: secret,
    severity: "medium",
    description: "Sentry DSN with a project key",
    pattern: /https:\/\/[0-9a-f]{32,64}@o\d+\.ingest\.(?:[a-z]{2}\.)?sentry\.io\/\d+/g
  },
  {
    id: "mailgun-api-key",
    category: secret,
    severity: "high",
    description: "Mailgun API key",
    pattern: /\bkey-[0-9a-f]{32}\b/g
  },
  {
    id: "mailchimp-api-key",
    category: secret,
    severity: "high",
    description: "Mailchimp API key",
    pattern: /\b[0-9a-f]{32}-us\d{1,2}\b/g
  },
  {
    id: "connection-string-password",
    category: secret,
    severity: "high",
    description: "Password in a connection string",
    pattern: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver|clickhouse):\/\/[^\s:@/]+:([^\s@/]+)@[^\s]+/gi,
    valueGroup: 1,
    validate: hasCredentialValue
  },
  {
    id: "url-basic-auth",
    category: secret,
    severity: "high",
    description: "Credential embedded in a URL",
    pattern: /\b(?:https?|ftps?|sftp|ssh|smtps?|ldaps?):\/\/[^\s:@/]+:([^\s@/]{8,})@[^\s]/gi,
    valueGroup: 1,
    validate: hasUrlCredentialValue
  },
  {
    id: "generic-secret",
    category: secret,
    severity: "high",
    description: "Hard-coded credential",
    pattern: /\b(?:[A-Z][A-Z0-9]*[_-]){0,8}(?:api[_-]?key|access[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|passphrase|password|passwd|pwd|secret|token)["']?\s*[:=]\s*(?:"([^"\r\n]{12,})"|'([^'\r\n]{12,})'|([A-Za-z0-9][A-Za-z0-9+/_=.-]{10,}[A-Za-z0-9+/_=]))/gi,
    extract: match => match[1] ?? match[2] ?? match[3],
    validate: hasCredentialValue
  },
  {
    id: "email-address",
    category: privacy,
    severity: "medium",
    description: "Email address",
    pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b(?<!\.(?:png|jpe?g|gif|svg|webp|ico|bmp|css|scss|less|js|mjs|cjs|json|html?|xml|lock|map|woff2?|ttf|eot))/gi
  },
  {
    id: "credit-card-number",
    category: privacy,
    severity: "high",
    description: "Payment card number",
    pattern: /\b(?:\d{13,19}|\d{4}(?:[ -]\d{4}){2,3}(?:[ -]\d{1,3})?|\d{4}[ -]\d{6}[ -]\d{5})\b/g,
    validate: isPaymentCard
  },
  {
    id: "us-social-security-number",
    category: privacy,
    severity: "high",
    description: "US Social Security number",
    pattern: /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g
  },
  {
    id: "windows-user-path",
    category: privacy,
    severity: "medium",
    description: "Local Windows user path",
    pattern: /\b[A-Za-z]:[\\/]Users[\\/][^\\/\s"'<>:*?|]+/g,
    validate: value => !sharedWindowsAccounts.test(value)
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
    pattern: /(?<!\d\.)\b(?!(?:0|127|169\.254|192\.0\.2|198\.51\.100|203\.0\.113|255|22[4-9]|23\d)\.)(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b(?!\.\d)/g
  },
  {
    id: "ipv6-address",
    category: privacy,
    severity: "low",
    description: "IPv6 address",
    pattern: /(?<![0-9a-fA-F:.])(?!(?:2001:0{0,3}db8|3fff|fe80|ff[0-9a-fA-F]{2})[0-9a-fA-F:]*)(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6})(?![0-9a-fA-F:])/g,
    validate: value => value.split(/:+/).filter(Boolean).length >= 3
  }
]

export const riskyFileRules = [
  { id: "dotenv-file", category: secret, severity: "high", description: "Environment file", pattern: /(?:^|\/)\.env(?:\..+)?$/i, except: /\.example$|\.sample$|\.template$/i },
  { id: "private-key-file", category: secret, severity: "critical", description: "Private key file", pattern: /(?:^|\/)(?:id_(?:rsa|dsa|ecdsa|ed25519)|.+\.(?:pem|p12|pfx|key|p8|ppk))$/i },
  { id: "credential-file", category: secret, severity: "high", description: "Credential configuration file", pattern: /(?:^|\/)(?:credentials|credentials\.json|secrets?\.json|\.npmrc|\.pypirc|\.netrc|\.htpasswd|\.pgpass|\.git-credentials|\.dockercfg|kubeconfig)$/i },
  { id: "secret-store-file", category: secret, severity: "high", description: "Key or credential store file", pattern: /(?:^|\/).+\.(?:jks|keystore|truststore|kdbx|ovpn)$/i },
  { id: "service-account-key-file", category: secret, severity: "high", description: "Service account key file", pattern: /(?:^|\/)(?:[^/]*service[_-]?account[^/]*|client[_-]?secret[^/]*)\.json$/i },
  { id: "infrastructure-state-file", category: secret, severity: "medium", description: "Infrastructure state or variable file", pattern: /(?:^|\/)(?:terraform\.tfstate(?:\.backup)?|[^/]+\.tfvars(?:\.json)?)$/i },
  { id: "backup-file", category: hygiene, severity: "low", description: "Backup or editor temporary file", pattern: /(?:^|\/)[^/]*(?:\.(?:bak|old|orig|rej|save|swp|swo)|~)$/i },
  { id: "os-metadata-file", category: hygiene, severity: "low", description: "Operating system metadata file", pattern: /(?:^|\/)(?:\.DS_Store|Thumbs\.db|desktop\.ini)$/i }
]

export const entropyRule = {
  id: "high-entropy-secret",
  category: secret,
  severity: "medium",
  description: "High-entropy credential-like value"
}

export const largeFileRule = {
  id: "large-file",
  category: hygiene,
  severity: "medium",
  description: "Large file"
}

export const allRules = [...contentRules, ...riskyFileRules, entropyRule, largeFileRule]

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
