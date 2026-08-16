import test from "node:test"
import assert from "node:assert/strict"
import { contentRules, resolveRuleSelection } from "../src/rules.js"
import { generated } from "./helpers.js"

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
})

test("validates rule and category selection", () => {
  const selected = resolveRuleSelection({ includeRules: ["github-token", "email-address"], excludeRules: ["email-address"], selectedCategories: ["secret"] })

  assert.equal(selected(contentRules.find(rule => rule.id === "github-token")), true)
  assert.equal(selected(contentRules.find(rule => rule.id === "email-address")), false)
  assert.throws(() => resolveRuleSelection({ includeRules: ["missing"] }), /Unknown rule/)
  assert.throws(() => resolveRuleSelection({ selectedCategories: ["missing"] }), /Unknown category/)
})
