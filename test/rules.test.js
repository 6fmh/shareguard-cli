import test from "node:test"
import assert from "node:assert/strict"
import { contentRules, resolveRuleSelection } from "../src/rules.js"
import { generated, hex } from "./helpers.js"

const matches = (ruleId, value) => {
  const rule = contentRules.find(item => item.id === ruleId)
  rule.pattern.lastIndex = 0
  const match = rule.pattern.exec(value)
  if (!match) return false
  const detected = rule.extract ? rule.extract(match) : rule.valueGroup ? match[rule.valueGroup] : match[0]
  return rule.validate ? rule.validate(detected) : true
}

test("recognizes high-confidence provider credential shapes", () => {
  const credentials = new Map([
    ["github-token", generated("ghp_", 36)],
    ["gitlab-token", generated("glpat-", 24)],
    ["aws-access-key", `AKIA${"A3B7".repeat(4)}`],
    ["npm-token", generated("npm_", 36)],
    ["sendgrid-api-key", `${generated("SG.", 22)}.${generated("", 43)}`],
    ["digitalocean-token", `dop_v1_${"a3b7".repeat(16)}`],
    ["pypi-token", generated("pypi-AgEIcHlwaS5vcmc", 55)],
    ["google-api-key", generated("AIza", 35)]
  ])

  for (const [rule, credential] of credentials) assert.equal(matches(rule, credential), true, rule)
})

test("recognizes credentials in source and URLs", () => {
  const secret = generated("", 36)
  const connectionString = ["postgres://service:", secret, String.fromCharCode(64), "db.internal/app"].join("")

  assert.equal(matches("generic-secret", `password = "${secret}"`), true)
  assert.equal(matches("generic-secret", `SERVICE_TOKEN=${secret}`), true)
  assert.equal(matches("connection-string-password", connectionString), true)
})

test("avoids placeholders and documentation addresses", () => {
  assert.equal(matches("generic-secret", "password = \"replace-me-now\""), false)
  assert.equal(matches("aws-access-key", "AKIAEXAMPLE"), false)
  assert.equal(matches("ipv4-address", "192.0.2.25"), false)
  assert.equal(matches("email-address", "name at example dot com"), false)
  assert.equal(matches("email-address", "background@2x.png"), false)
})

test("validates rule and category selection", () => {
  const selected = resolveRuleSelection({ includeRules: ["github-token", "email-address"], excludeRules: ["email-address"], selectedCategories: ["secret"] })

  assert.equal(selected(contentRules.find(rule => rule.id === "github-token")), true)
  assert.equal(selected(contentRules.find(rule => rule.id === "email-address")), false)
  assert.throws(() => resolveRuleSelection({ includeRules: ["missing"] }), /Unknown rule/)
  assert.throws(() => resolveRuleSelection({ selectedCategories: ["missing"] }), /Unknown category/)
})

test("recognizes additional provider credential shapes", () => {
  const credentials = [
    ["anthropic-api-key", generated("sk-ant-api03-", 90)],
    ["openai-api-key", generated("sk-proj-", 100)],
    ["openai-api-key", `sk-${generated("", 20)}T3BlbkFJ${generated("", 20)}`],
    ["google-oauth-client-secret", generated("GOCSPX-", 28)],
    ["azure-client-secret", `${generated("", 3)}8Q~${generated("", 34)}`],
    ["stripe-key", generated("rk_live_", 24)],
    ["slack-app-token", `xapp-1-${generated("A", 9)}-${generated("", 13)}-${hex(64)}`],
    ["slack-webhook-url", `https://hooks.slack.com/services/T${generated("", 8)}/B${generated("", 8)}/${generated("", 24)}`],
    ["discord-bot-token", `${generated("N", 24)}.${generated("", 6)}.${generated("", 30)}`],
    ["telegram-bot-token", generated("123456789:", 35)],
    ["twilio-account-sid", `AC${hex(32)}`],
    ["twilio-api-key-sid", `SK${hex(32)}`],
    ["hashicorp-vault-token", generated("hvs.", 95)],
    ["terraform-cloud-token", `${generated("", 14)}.atlasv1.${generated("", 64)}`],
    ["doppler-token", generated("dp.st.", 44)],
    ["grafana-service-account-token", `${generated("glsa_", 32)}_${hex(8)}`],
    ["grafana-cloud-token", generated("glc_", 80)],
    ["cloudflare-api-token", generated("cfat_", 45)],
    ["square-access-token", generated("sq0atp-", 43)],
    ["shopify-token", `shpat_${hex(32)}`],
    ["notion-token", generated("ntn_", 46)],
    ["notion-token", generated("secret_", 43)],
    ["linear-api-key", generated("lin_api_", 44)],
    ["jwt", `${generated("eyJ", 20)}.${generated("eyJ", 20)}.${generated("", 30)}`]
  ]

  for (const [rule, credential] of credentials) assert.equal(matches(rule, credential), true, rule)
})

test("keeps additional rules quiet on placeholders and non-secrets", () => {
  assert.equal(matches("anthropic-api-key", "sk-ant-YOUR_KEY"), false)
  assert.equal(matches("openai-api-key", "sk-proj-XXXX"), false)
  assert.equal(matches("telegram-bot-token", "123456:YOUR_BOT_TOKEN"), false)
  assert.equal(matches("discord-bot-token", "your.bot.token"), false)
  assert.equal(matches("shopify-token", "shpat_notrealnotrealnotrealnotreal"), false)
  assert.equal(matches("jwt", `${generated("eyJ", 20)}.${generated("", 20)}.${generated("", 30)}`), false)
})

test("recovers common credential names and rejects dummy values in the generic rule", () => {
  const secret = generated("", 40)

  assert.equal(matches("generic-secret", `AWS_SECRET_ACCESS_KEY = "${secret}"`), true)
  assert.equal(matches("generic-secret", `passphrase: "${secret}"`), true)
  assert.equal(matches("generic-secret", `DB_PWD=${secret}`), true)
  assert.equal(matches("generic-secret", 'password = "your-secret-here"'), false)
  assert.equal(matches("generic-secret", 'token = "supersecret"'), false)
  assert.equal(matches("generic-secret", 'api_key = os.getenv("REAL_KEY_NAME")'), false)
})

test("scopes IP address rules to identifying addresses", () => {
  // Assemble addresses at runtime so this test file itself stays clean under a self-scan.
  const v4 = (...octets) => octets.join(".")
  const v6 = (...groups) => groups.join(":")

  assert.equal(matches("ipv4-address", v4(8, 8, 8, 8)), true)
  assert.equal(matches("ipv4-address", v4(10, 0, 0, 5)), true)
  assert.equal(matches("ipv4-address", v4(169, 254, 1, 1)), false)
  assert.equal(matches("ipv4-address", v4(255, 255, 255, 0)), false)
  assert.equal(matches("ipv4-address", v4(239, 255, 255, 250)), false)
  assert.equal(matches("ipv4-address", v4(1, 2, 3, 4, 5)), false)
  assert.equal(matches("ipv6-address", v6("2001", "4860", "4860", "", "8888")), true)
  assert.equal(matches("ipv6-address", v6("2001", "db8", "", "1")), false)
  assert.equal(matches("ipv6-address", v6("", "", "1")), false)
  assert.equal(matches("ipv6-address", v6("12", "34", "56")), false)
})
