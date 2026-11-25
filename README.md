# pii-scrub

Redact PII and secrets before text reaches an LLM, then restore them in the response.

**Status: early but working (v0.1.0).** Detection, reversible placeholders, restore, custom detectors and a CLI all work today and are covered by tests. A TypeScript port of the library (no CLI) lives in [`ts/`](ts/). Detection is pattern-based. Names and US-style street addresses are available as opt-in, heuristic detectors (see [Names and addresses](#names-and-addresses-opt-in)); national IDs from a few other countries are available as opt-in, checksum-validated detectors (see [National IDs](#national-ids-opt-in)); other free-form PII is not found.

```python
from pii_scrub import scrub

safe, vault = scrub("Refund jo@example.com, card 4111 1111 1111 1111")
# safe == "Refund <EMAIL_1>, card <CREDIT_CARD_1>"

answer = vault.restore(llm(safe))   # llm is whatever function calls your model
```

The model only ever sees `<EMAIL_1>`. The real values stay in `vault`, in your process.

## Install

Python 3.10 or newer, no dependencies.

```bash
pip install git+https://github.com/narayana006/pii-scrub
```

or from a clone:

```bash
git clone https://github.com/narayana006/pii-scrub
cd pii-scrub
pip install -e .
```

## Quick start (command line)

The repository ships a sample support ticket. Scrub it and keep the mapping in a vault file:

```console
$ pii-scrub scrub examples/support_ticket.txt --vault vault.json
Ticket #48213 - billing issue

Hi team,

I'm Dana Whitfield (<EMAIL_1>). I was charged twice on my
Visa <CREDIT_CARD_1> last Friday. You can reach me on <PHONE_1>
or at my work address <EMAIL_2>.

Our integration calls your API from <IP_1> using the access key
<API_KEY_1>, and the staging config has password=<SECRET_1>
in it, in case that helps you find the account.

Please reply to <EMAIL_1>.

Thanks,
Dana
pii-scrub: replaced 8 value(s): API_KEY 1, CREDIT_CARD 1, EMAIL 3, IP 1, PHONE 1, SECRET 1; vault saved to vault.json
```

The last line goes to stderr, so redirecting stdout gives you just the scrubbed text. Note that the same address became `<EMAIL_1>` both times, and that the name "Dana Whitfield" was not touched (see [Limitations](#limitations)).

`examples/model_reply.txt` is a reply a model might write using those placeholders. Restore it:

```console
$ pii-scrub restore examples/model_reply.txt --vault vault.json
Hello,

Thanks for getting in touch. I can see two charges against the card
4111 1111 1111 1111 and have refunded the duplicate. A confirmation will be sent
to dana.whitfield@example.com; if anything looks wrong we will call you on +1 (415) 555-0132.

For safety, please rotate the access key AKIAIOSFODNN7EXAMPLE since it was shared in
a ticket.
```

To see what would be replaced without changing anything:

```console
$ pii-scrub detect examples/support_ticket.txt
5:21	EMAIL	da************om
6:6	CREDIT_CARD	41************11
6:59	PHONE	+1************32
7:23	EMAIL	d.************le
9:37	IP	20********42
10:1	API_KEY	AK************LE
10:59	SECRET	co************ry
13:17	EMAIL	da************om
```

Columns are `line:column`, label and a masked preview.

## What is detected

| Placeholder | Matches |
| --- | --- |
| `<EMAIL_n>` | Email addresses |
| `<PHONE_n>` | `+14155552671`, `+1 (415) 555-0132`, `415-555-0132`, `+44 20 7946 0958`, `+91 98765 43210` and similar grouped formats |
| `<CREDIT_CARD_n>` | 13 to 19 digits, optionally grouped with spaces or dashes, that pass the Luhn checksum |
| `<SSN_n>` | US Social Security numbers written `123-45-6789` |
| `<IP_n>` | IPv4 and IPv6 addresses |
| `<API_KEY_n>` | AWS access key ids, GitHub and GitLab tokens, `sk-...` keys, Stripe keys, Slack tokens, Google API keys |
| `<TOKEN_n>` | JSON Web Tokens and `Bearer <token>` values |
| `<PRIVATE_KEY_n>` | PEM private key blocks |
| `<SECRET_n>` | The value in assignments such as `password=...`, `API_KEY: ...`, `client_secret = "..."` (8+ characters) |

## Names and addresses (opt-in)

Names and street addresses have no fixed shape, so they are **off by default** and found heuristically. Turn them on with `--with` on the CLI or `extra=` in the library:

```console
$ echo "Hi, I'm Dana Whitfield at 12 Oak Street, Austin, TX 78701. Thanks,
Dana" | pii-scrub scrub --with NAME,ADDRESS
Hi, I'm <NAME_1> at <ADDRESS_1>. Thanks,
<NAME_2>
pii-scrub: replaced 3 value(s): ADDRESS 1, NAME 2; no --vault given, so this cannot be restored
```

```python
from pii_scrub import ADDRESS, NAME, scrub

safe, vault = scrub(text, extra=[NAME, ADDRESS])
```

- **NAME** looks for a capitalised name after a cue: an honorific (`Dr. Jane Smith`), `my name is`, `Name:` / `Customer:`, `I'm` / `I am` / `this is` (two or more words), a greeting (`Dear Jane,`), or alone on the line after a sign-off (`Thanks,` then `Dana`). Once a full name has been found, every other occurrence of that exact string is replaced too. Greetings such as `Hi team,` or `Dear Sir,` are ignored.
- **ADDRESS** matches US-style street addresses (`221B Baker Street`, `1600 Pennsylvania Ave NW`, optional `Apt`/`Suite`, optional `City, ST 12345`) and `P.O. Box 1234`.
- A name with no cue (for example `Dana` on its own in the middle of a sentence, or `Dana` when only `Dana Whitfield` was found) is missed, and the address pattern does not cover non-US formats. For better coverage plug your own name list or NER model in with `callable_detector`.

## National IDs (opt-in)

Beyond the US SSN, these formats can be switched on with `--with` or `extra=`. Each one is checked (checksum or issuing rules) before it is reported, so random digit runs are mostly ignored. They are off by default because they are only useful where your data comes from those countries.

| Label | Country and format | Check applied |
| --- | --- | --- |
| `AADHAAR` | India, 12 digits starting 2-9, as `2345 6789 0124`, `2345-6789-0124` or unspaced | Verhoeff checksum |
| `CPF` | Brazil, `529.982.247-25` or `52998224725` | both check digits |
| `SIN` | Canada, `130 692 544` or `130-692-544` (one separator style) | Luhn, first digit not 0 or 8 |
| `NINO` | UK National Insurance, `AB 12 34 56 C` or `AB123456C` | unissued prefixes and suffixes rejected (no checksum exists) |
| `DNI` | Spain, `12345678Z` or `12345678-Z` | control letter |

```console
$ echo "Aadhaar 2345 6789 0124, CPF 529.982.247-25, SIN 130 692 544" | pii-scrub scrub --with AADHAAR,CPF,SIN
Aadhaar <AADHAAR_1>, CPF <CPF_1>, SIN <SIN_1>
pii-scrub: replaced 3 value(s): AADHAAR 1, CPF 1, SIN 1; no --vault given, so this cannot be restored
```

```python
from pii_scrub import AADHAAR, CPF, scrub

safe, vault = scrub(text, extra=[AADHAAR, CPF])
```

Not covered: other countries, IDs written with unusual separators, and the TypeScript port (it only has the default detectors). Without the checksum a NINO match is only as strict as the prefix rules, so an ordinary word like `AB123456C` in a part number would match.

## Library usage

### Scrub and restore

```python
from pii_scrub import scrub

safe, vault = scrub(text)
reply = vault.restore(model_reply)
```

`vault.restore` replaces every placeholder it knows and leaves anything else alone, including placeholders the model invented.

### One vault for a whole conversation

Pass the vault back in and placeholders stay consistent across messages:

```python
first, vault = scrub("from jo@example.com")
second, _ = scrub("cc sam@example.com and jo@example.com", vault)
# first  == "from <EMAIL_1>"
# second == "cc <EMAIL_2> and <EMAIL_1>"
```

### Save and load a vault

```python
from pii_scrub import Vault

vault.save("vault.json")          # JSON, created with mode 0600
vault = Vault.load("vault.json")
vault.items()                     # [("<EMAIL_1>", "jo@example.com"), ...]
```

The vault file contains the original sensitive values in plain text. Treat it like the data it protects and do not commit it.

### Custom detectors

From a regular expression, optionally with a capture group and a validator:

```python
from pii_scrub import regex_detector, scrub

order_ids = regex_detector("ORDER", r"ORD-\d{4}-\d{5}")
safe, vault = scrub(text, extra=[order_ids])      # adds <ORDER_1>, ...
```

From any callable that returns `(start, end)` spans or plain strings (every occurrence of a returned string is replaced). This is the hook for a name list or an NER model of your own:

```python
from pii_scrub import callable_detector

customers = callable_detector("NAME", lambda text: ["Dana Whitfield", "Jo Park"])
safe, vault = scrub(text, extra=[customers])
```

`extra=` adds to the built-in detectors; `detectors=` replaces them. The built-ins are importable as `pii_scrub.DEFAULT_DETECTORS`. A runnable version of this is in `examples/roundtrip.py`:

```console
$ python examples/roundtrip.py
sent to model : Refund order <ORDER_1> for <EMAIL_1>, card <CREDIT_CARD_1>, phone <PHONE_1>.
model replied : Refund issued for <ORDER_1>. Receipt sent to <EMAIL_1>.
after restore : Refund issued for ORD-2024-00917. Receipt sent to jo@example.com.
```

### Inspect findings

```python
from pii_scrub import Scrubber

for finding in Scrubber().detect(text):
    print(finding.label, finding.start, finding.end, finding.value)
```

When two detectors overlap, the match that starts first wins, then the longer one, then the detector listed first (custom `extra` detectors come before built-ins).

## TypeScript

The [`ts/`](ts/) directory is a port of the library: the same detectors, placeholder numbering, restore and custom detectors. It has no dependencies, is written in plain TypeScript that Node runs directly (Node 22.18 or newer), and reads and writes the same vault JSON as the Python package. It is not published to npm yet, so use it from a clone:

```bash
git clone https://github.com/narayana006/pii-scrub
cd pii-scrub/ts
npm install        # dev tools only: typescript and @types/node
npm test
```

```ts
import { regexDetector, scrub, Vault } from "./src/index.ts";

const [safe, vault] = scrub("Refund jo@example.com, card 4111 1111 1111 1111");
// safe === "Refund <EMAIL_1>, card <CREDIT_CARD_1>"
const answer = vault.restore(reply);

// keep numbering across a conversation, add your own detectors
const orders = regexDetector("ORDER", String.raw`ORD-\d{4}-\d{5}`);
const [next] = scrub("ORD-2024-00917 for jo@example.com", { vault, extra: [orders] });
// next === "<ORDER_1> for <EMAIL_1>"

// same JSON format as Vault.save() in Python
const copy = Vault.fromJSON(JSON.parse(JSON.stringify(vault)));
```

```console
$ node examples/roundtrip.ts
sent to model : Refund order <ORDER_1> for <EMAIL_1>, card <CREDIT_CARD_1>, phone <PHONE_1>.
model replied : Refund issued for <ORDER_1>. Receipt sent to <EMAIL_1>.
after restore : Refund issued for ORD-2024-00917. Receipt sent to jo@example.com.
```

Differences from the Python API:

- `scrub(text, { vault, detectors, extra })` takes an options object and returns a `[safeText, vault]` pair. Names are camelCase (`regexDetector`, `callableDetector`, `luhnValid`, `vault.placeholderFor`).
- `regexDetector`'s `group` option takes a group index or a group name. Python `(?i:...)` inline flags are not available in older Node versions, so pass a `RegExp` with the `i` flag instead.
- `callableDetector` functions return `[start, end]` pairs or strings.
- There is no CLI and no file helper: use `JSON.stringify(vault)` and `Vault.fromJSON(...)` and store the file yourself, with the same care as the Python vault file.
- Finding offsets are JavaScript string indices (UTF-16 code units), so they differ from Python's offsets after characters such as emoji. The scrubbed text and restored text are the same.
- In JavaScript `\w`, `\d` and `\b` only match ASCII, while Python's match any Unicode letter or digit. This only changes behaviour at the edges of a match, for example a phone number written directly after a non-ASCII letter.

The test suite checks that scrubbing `examples/support_ticket.txt` produces exactly the same vault as the Python package.

## CLI reference

```text
pii-scrub scrub   [FILE] [--vault PATH] [-o OUT] [--only LABELS] [--with LABELS] [--pattern LABEL=REGEX]
pii-scrub restore [FILE] --vault PATH [-o OUT]
pii-scrub detect  [FILE] [--json] [--show] [--fail-on-find] [--only LABELS] [--with LABELS] [--pattern LABEL=REGEX]
```

- `FILE` defaults to stdin, so `cat notes.txt | pii-scrub scrub --vault vault.json` works.
- `--vault` on `scrub` creates the file, or extends it if it already exists so numbering stays consistent between runs. Without it the output cannot be restored.
- `--only EMAIL,PHONE` limits the built-in detectors that run.
- `--with NAME,ADDRESS,AADHAAR,...` adds the opt-in detectors described above; `--only` also accepts `NAME` and `ADDRESS`.
- `--pattern 'TICKET=TCK-\d+'` adds a regex detector; repeat it for more.
- `detect --show` prints full values instead of masked ones; `--fail-on-find` exits with status 1 when anything is found, which is handy in a pre-commit hook or CI step.

## Features

- [x] Detects emails, phone numbers, IDs (US SSN), credit-card-like numbers (Luhn-checked), IP addresses, API keys and tokens
- [x] Reversible placeholders such as `<EMAIL_1>`, with the mapping kept locally
- [x] Restore originals in model output
- [x] Custom detectors via regex or callables
- [x] Python library and command-line tool
- [x] TypeScript port of the library (in `ts/`; no CLI, not on npm yet)
- [x] Name and US street address detection (opt-in, heuristic; see above)
- [x] National ID formats beyond the US SSN (India Aadhaar, Brazil CPF, Canada SIN, UK NINO, Spain DNI; opt-in, Python only)
- [ ] Streaming restore for token-by-token model output

## Limitations

- **Pattern matching only.** Names and US street addresses are found only by the opt-in heuristics above; dates of birth and anything else without a recognisable shape are not detected unless you add a detector for them. Do not treat the output as guaranteed free of personal data.
- **False positives happen.** Any dotted quad of numbers up to 255 is treated as an IP address (so a four-part version number such as `1.2.3.4` is replaced), and a random 16-digit number has a one in ten chance of passing the Luhn check.
- **False negatives happen.** Phone numbers written without separators and without a leading `+`, unusual national formats, and secrets with no known prefix or `key=value` shape are missed.
- **Restore needs the placeholder intact.** If the model rewrites `<EMAIL_1>` as `EMAIL_1` or `<email 1>`, it is not restored.
- **Literal placeholders in the input are not escaped.** If your input already contains text like `<EMAIL_1>`, restore will replace it too.
- The vault is plain JSON, not encrypted.

## Contributing

Issues and pull requests are welcome, especially new detectors with test cases showing what should and should not match. To work on the code:

```bash
pip install -e ".[dev]"
pytest
```

For the TypeScript port, `cd ts && npm install && npm test && npm run lint` (the last runs the type checker).

Built and maintained by [Narayana Vemburaj](https://github.com/narayana006).

## License

[MIT](LICENSE)
