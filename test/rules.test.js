import test from "node:test"
import assert from "node:assert/strict"
import { contentRules } from "../src/rules.js"

const matches = (ruleId, value) => {
  const rule = contentRules.find(item => item.id === ruleId)
  rule.pattern.lastIndex = 0
  return rule.pattern.test(value)
}

test("recognizes provider credential shapes", () => {
  const github = ["ghp", "a".repeat(36)].join("_")
  const aws = `AKIA${"A".repeat(16)}`
  const google = `AIza${"a".repeat(35)}`

  assert.equal(matches("github-token", github), true)
  assert.equal(matches("aws-access-key", aws), true)
  assert.equal(matches("google-api-key", google), true)
})

test("recognizes credentials in source and URLs", () => {
  const connectionString = ["postgres://service:", "private-value", String.fromCharCode(64), "db.internal/app"].join("")

  assert.equal(matches("generic-secret", "password = \"correct-horse-battery-staple\""), true)
  assert.equal(matches("connection-string-password", connectionString), true)
})

test("avoids common placeholders", () => {
  assert.equal(matches("generic-secret", "password = \"change-me\""), false)
  assert.equal(matches("aws-access-key", "AKIAEXAMPLE"), false)
  assert.equal(matches("email-address", "name at example dot com"), false)
})
