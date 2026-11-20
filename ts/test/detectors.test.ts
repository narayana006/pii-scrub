import assert from "node:assert/strict";
import { test } from "node:test";

import { Scrubber, callableDetector, ipv6Valid, luhnValid, regexDetector } from "../src/index.ts";

function found(text: string, label?: string): [string, string][] {
  return new Scrubber()
    .detect(text)
    .filter((f) => label === undefined || f.label === label)
    .map((f) => [f.label, f.value]);
}

test("luhn", () => {
  assert.ok(luhnValid("4111 1111 1111 1111"));
  assert.ok(luhnValid("378282246310005"));
  assert.ok(!luhnValid("4111 1111 1111 1112"));
  assert.ok(!luhnValid(""));
});

test("emails", () => {
  for (const email of ["jo@example.com", "first.last+tag@sub.example.co.uk", "a_b%c@example.io"]) {
    assert.deepEqual(found(`mail ${email}, please`), [["EMAIL", email]]);
  }
  assert.deepEqual(found("Write to jo@example.com."), [["EMAIL", "jo@example.com"]]);
  assert.deepEqual(found("user@localhost or @handle"), []);
});

test("phones", () => {
  const phones = [
    "+14155552671",
    "+1 (415) 555-0132",
    "(415) 555-0132",
    "415-555-0132",
    "415.555.0132",
    "+44 20 7946 0958",
    "+91 98765 43210",
  ];
  for (const phone of phones) assert.deepEqual(found(`call ${phone} today`), [["PHONE", phone]]);
  for (const text of ["on 2024-01-15 at 10:30", "version 3.11.4", "order 12345", "took 1500 ms", "1,000,000"]) {
    assert.deepEqual(found(text), [], text);
  }
});

test("credit cards and SSNs", () => {
  for (const card of ["4111111111111111", "4111 1111 1111 1111", "5500-0000-0000-0004", "378282246310005"]) {
    assert.deepEqual(found(`card: ${card}.`), [["CREDIT_CARD", card]]);
  }
  assert.deepEqual(found("ref 4111 1111 1111 1112"), []);
  assert.deepEqual(found("0000 0000 0000 0000"), []);
  assert.deepEqual(found("SSN 123-45-6789"), [["SSN", "123-45-6789"]]);
  assert.deepEqual(found("SSN 000-45-6789"), []);
});

test("IP addresses", () => {
  for (const ip of ["203.0.113.42", "10.0.0.1", "2001:db8::ff00:42:8329", "::1"]) {
    assert.deepEqual(found(`from ${ip} port 443`), [["IP", ip]]);
  }
  for (const text of ["999.1.1.1", "at 12:30:45", "std::vector", "1.2.3"]) {
    assert.deepEqual(found(text, "IP"), [], text);
  }
  assert.ok(ipv6Valid("1:2:3:4:5:6:7:8"));
  assert.ok(ipv6Valid("1:2:3:4:5:6:7::"));
  assert.ok(!ipv6Valid("1:2:3:4:5:6:7:8:9"));
  assert.ok(!ipv6Valid("1::2::3"));
  assert.ok(!ipv6Valid("12345::1"));
});

test("API keys, JWTs, bearer tokens and private keys", () => {
  const github = "ghp_" + "a1B2".repeat(9);
  const slack = "xoxb-" + "1234567890-abcdefghij";
  const sk = "sk-" + "proj-" + "Zz9".repeat(10);
  for (const token of ["AKIAIOSFODNN7EXAMPLE", github, slack, sk]) {
    assert.deepEqual(found(`key ${token} here`), [["API_KEY", token]]);
  }
  const jwt = ["eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NSJ9", "c2lnbmF0dXJlMTIz"].join(".");
  assert.deepEqual(found(`jwt=${jwt}`), [["TOKEN", jwt]]);
  const opaque = "abcDEF0123456789abcDEF";
  assert.deepEqual(found(`Authorization: Bearer ${opaque}`), [["TOKEN", opaque]]);
  const block = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34\n-----END RSA PRIVATE KEY-----";
  assert.deepEqual(found(`key:\n${block}\ndone`), [["PRIVATE_KEY", block]]);
});

test("secret assignments capture only the value", () => {
  assert.deepEqual(found('DB_PASSWORD="s3cr3t-value!"'), [["SECRET", "s3cr3t-value!"]]);
  assert.deepEqual(found("api_key: abcd1234efgh"), [["SECRET", "abcd1234efgh"]]);
  assert.deepEqual(found("password: short"), []);
  assert.deepEqual(found("api_key=AKIAIOSFODNN7EXAMPLE"), [["API_KEY", "AKIAIOSFODNN7EXAMPLE"]]);
});

test("findings do not overlap and are ordered", () => {
  const text = "a@example.com 10.0.0.1 415-555-0132 a@example.com";
  const findings = new Scrubber().detect(text);
  assert.deepEqual(
    findings.map((f) => f.label),
    ["EMAIL", "IP", "PHONE", "EMAIL"],
  );
  for (let i = 1; i < findings.length; i++) assert.ok(findings[i - 1]!.end <= findings[i]!.start);
  for (const f of findings) assert.equal(text.slice(f.start, f.end), f.value);
});

test("regex detector with group and validator", () => {
  for (const group of [1, "id"]) {
    const detector = regexDetector("EMPLOYEE", String.raw`emp:(?<id>\d+)`, {
      group,
      validator: (v) => Number(v) > 100,
    });
    const findings = new Scrubber({ detectors: [detector] }).detect("emp:42 emp:4200");
    assert.deepEqual(
      findings.map((f) => [f.label, f.value]),
      [["EMPLOYEE", "4200"]],
    );
  }
});

test("callable detector accepts spans and strings and rejects bad spans", () => {
  const names = callableDetector("NAME", () => ["Dana"]);
  const spans = callableDetector("FIRST3", () => [[0, 3]]);
  const findings = new Scrubber({ detectors: [names, spans] }).detect("Hi, Dana and Dana");
  assert.deepEqual(
    findings.map((f) => [f.label, f.value]),
    [
      ["FIRST3", "Hi,"],
      ["NAME", "Dana"],
      ["NAME", "Dana"],
    ],
  );
  const bad = callableDetector("BAD", () => [[5, 2]]);
  assert.throws(() => new Scrubber({ detectors: [bad] }).detect("hello world"));
});

test("label must be UPPER_SNAKE_CASE", () => {
  assert.throws(() => regexDetector("order id", String.raw`\d+`));
});
