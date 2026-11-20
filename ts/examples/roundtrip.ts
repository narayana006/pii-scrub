// Scrub a message, pretend to call a model, restore the reply.
// Run with:  node examples/roundtrip.ts   (from the ts/ directory)

import { regexDetector, scrub } from "../src/index.ts";

const text =
  "Refund order ORD-2024-00917 for jo@example.com, card 4111 1111 1111 1111, phone 415-555-0132.";

// A custom detector for this shop's order numbers.
const orderIds = regexDetector("ORDER", String.raw`ORD-\d{4}-\d{5}`);

const [safe, vault] = scrub(text, { extra: [orderIds] });
console.log("sent to model :", safe);

const fakeModel = (_prompt: string): string => "Refund issued for <ORDER_1>. Receipt sent to <EMAIL_1>.";

console.log("model replied :", fakeModel(safe));
console.log("after restore :", vault.restore(fakeModel(safe)));
