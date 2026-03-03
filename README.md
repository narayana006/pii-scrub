# pii-scrub

> Redact PII and secrets before text reaches an LLM, then restore them in the response.

**Status:** 🚧 Early stage — design and roadmap published, implementation in progress. Stars, issues and ideas welcome.

## Why

Sending customer data to third-party models is a compliance blocker for many teams.

## Planned features

- [ ] Detects emails, phone numbers, IDs, credit-card-like numbers, API keys and tokens
- [ ] Reversible placeholders (<EMAIL_1>) with local mapping
- [ ] Restore originals in model output
- [ ] Custom detectors via regex or callables
- [ ] Python library with a TypeScript port planned

## Intended usage

```
safe, vault = scrub(text)
answer = vault.restore(llm(safe))
```

_The interface above is the target design and may change._

## Roadmap

1. Core implementation of the first feature set
2. Examples and tests
3. CI and first tagged release
4. Docs and integrations

## Contributing

Contributions are welcome. Open an issue to discuss an idea or pick an unchecked item from the feature list.

## License

[MIT](LICENSE)
