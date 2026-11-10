"""Scrub a message, pretend to call a model, restore the reply.

Run with:  python examples/roundtrip.py
"""

from pii_scrub import regex_detector, scrub

text = (
    "Refund order ORD-2024-00917 for jo@example.com, "
    "card 4111 1111 1111 1111, phone 415-555-0132."
)

# A custom detector for this shop's order numbers.
order_ids = regex_detector("ORDER", r"ORD-\d{4}-\d{5}")

safe, vault = scrub(text, extra=[order_ids])
print("sent to model :", safe)


def fake_model(prompt: str) -> str:
    return "Refund issued for <ORDER_1>. Receipt sent to <EMAIL_1>."


print("model replied :", fake_model(safe))
print("after restore :", vault.restore(fake_model(safe)))
