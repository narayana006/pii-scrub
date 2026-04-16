# pii-scrub

Redact PII and secrets before text reaches an LLM, then restore them in the response.

> **Project status: planning. There is no working code in this repository yet.**
> This README describes what the project will do. Nothing below can be installed or run today.
> Features are ticked off in the checklist as they are built.

## What it is

A Python library.

**The problem it solves:** Sending customer data to third-party models is a compliance blocker for many teams.

## Who it is for

Teams that must not send personal data or secrets to a third-party model.

## How it will work

1. You pass text through the scrubber before calling a model.
2. Emails, phone numbers, ID numbers and keys are replaced with placeholders such as `<EMAIL_1>`; the real values stay on your machine.
3. You pass the model's answer back through the scrubber and the placeholders are swapped for the originals.

## Planned features

Unticked items are not built yet.

- [ ] Detects emails, phone numbers, IDs, credit-card-like numbers, API keys and tokens
- [ ] Reversible placeholders such as `<EMAIL_1>`, with the mapping kept locally
- [ ] Restore originals in model output
- [ ] Custom detectors via regex or callables
- [ ] Python library with a TypeScript port planned

## Planned usage

This is the intended interface, shown so you can judge the design. **It does not work yet**, and names may change before the first release.

```python
safe, vault = scrub(text)
answer = vault.restore(llm(safe))
```

## Contributing

Feedback on the design is the most useful contribution right now. Open an issue to suggest a feature, question an approach or describe your use case. Code contributions are welcome once the first version lands.

## Author

Built and maintained by [Narayana Vemburaj](https://github.com/narayana006).

## License

[MIT](LICENSE)
