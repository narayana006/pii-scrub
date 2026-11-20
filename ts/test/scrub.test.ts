import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { Scrubber, Vault, regexDetector, scrub } from "../src/index.ts";

const TEXT = "Mail jo@example.com or sam@example.com, card 4111 1111 1111 1111. Again: jo@example.com";

test("scrub replaces and numbers per label", () => {
  const [safe, vault] = scrub(TEXT);
  assert.equal(safe, "Mail <EMAIL_1> or <EMAIL_2>, card <CREDIT_CARD_1>. Again: <EMAIL_1>");
  assert.deepEqual(vault.items(), [
    ["<EMAIL_1>", "jo@example.com"],
    ["<EMAIL_2>", "sam@example.com"],
    ["<CREDIT_CARD_1>", "4111 1111 1111 1111"],
  ]);
  assert.deepEqual(vault.counts(), { EMAIL: 2, CREDIT_CARD: 1 });
  assert.equal(vault.restore(safe), TEXT);
});

test("restore in model output leaves unknown placeholders alone", () => {
  const [, vault] = scrub(TEXT);
  assert.equal(
    vault.restore("I emailed <EMAIL_2> and <EMAIL_1> about <CREDIT_CARD_1>."),
    "I emailed sam@example.com and jo@example.com about 4111 1111 1111 1111.",
  );
  assert.equal(vault.restore("<EMAIL_9> <PHONE_1> <b>"), "<EMAIL_9> <PHONE_1> <b>");
});

test("clean and empty text are unchanged", () => {
  const [safe, vault] = scrub("Nothing sensitive here, just 42 apples.");
  assert.equal(safe, "Nothing sensitive here, just 42 apples.");
  assert.equal(vault.size, 0);
  assert.equal(scrub("")[0], "");
});

test("vault is shared across calls", () => {
  const [first, vault] = scrub("from jo@example.com");
  const [second, same] = scrub("cc sam@example.com and jo@example.com", { vault });
  assert.equal(same, vault);
  assert.equal(first, "from <EMAIL_1>");
  assert.equal(second, "cc <EMAIL_2> and <EMAIL_1>");
});

test("extra detectors add to and win ties with built-ins; detectors replaces them", () => {
  const order = regexDetector("ORDER", String.raw`ORD-\d+`);
  const [safe, vault] = scrub("ORD-123 for jo@example.com", { extra: [order] });
  assert.equal(safe, "<ORDER_1> for <EMAIL_1>");
  assert.equal(vault.restore("done: <ORDER_1>"), "done: ORD-123");

  const internal = regexDetector("STAFF_EMAIL", String.raw`[\w.]+@corp\.example`);
  assert.equal(scrub("ping kim@corp.example", { extra: [internal] })[0], "ping <STAFF_EMAIL_1>");
  assert.equal(scrub("ORD-1 jo@example.com", { detectors: [order] })[0], "<ORDER_1> jo@example.com");
});

test("multiline and unicode text is preserved", () => {
  const text = "Zoë → zoe@example.com\n電話 +14155552671\n";
  const [safe, vault] = new Scrubber().scrub(text);
  assert.equal(safe, "Zoë → <EMAIL_1>\n電話 <PHONE_1>\n");
  assert.equal(vault.restore(safe), text);
});

test("vault JSON round trip continues numbering", () => {
  const [safe, vault] = scrub(TEXT);
  const data = JSON.parse(JSON.stringify(vault));
  assert.equal(data.version, 1);
  const loaded = Vault.fromJSON(data);
  assert.equal(loaded.restore(safe), TEXT);
  assert.ok(loaded.has("<EMAIL_1>"));
  assert.equal(loaded.get("<EMAIL_2>"), "sam@example.com");
  assert.equal(scrub("new@example.com and jo@example.com", { vault: loaded })[0], "<EMAIL_3> and <EMAIL_1>");
});

test("reads a vault file written by the Python CLI", () => {
  const data = JSON.parse(readFileSync(new URL("./fixtures/python-vault.json", import.meta.url), "utf8"));
  const vault = Vault.fromJSON(data);
  assert.equal(vault.restore("Reply to <EMAIL_1> about <CREDIT_CARD_1>"), "Reply to dana.whitfield@example.com about 4111 1111 1111 1111");
});

test("scrubbing the sample ticket matches the Python package", () => {
  const ticket = readFileSync(new URL("../../examples/support_ticket.txt", import.meta.url), "utf8");
  const expected = JSON.parse(readFileSync(new URL("./fixtures/python-vault.json", import.meta.url), "utf8"));
  assert.deepEqual(scrub(ticket)[1].toJSON(), expected);
});

test("vault rejects malformed data", () => {
  for (const bad of [{}, { entries: [] }, { entries: { EMAIL_1: "x" } }, [], null]) {
    assert.throws(() => Vault.fromJSON(bad));
  }
});
