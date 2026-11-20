/**
 * Built-in detectors and helpers for writing custom ones.
 *
 * A detector is a label plus a function that returns the [start, end) spans of
 * every sensitive value it finds. The label becomes the placeholder prefix, so
 * a detector labelled EMAIL produces <EMAIL_1>. The patterns mirror the Python
 * package so both versions find the same values.
 */

export type Span = [start: number, end: number];

const LABEL_RE = /^[A-Z][A-Z0-9_]*$/;

export interface Detector {
  readonly label: string;
  find(text: string): Iterable<Span>;
}

function checkLabel(label: string): void {
  if (!LABEL_RE.test(label)) {
    throw new Error(`detector label must be UPPER_SNAKE_CASE, got ${JSON.stringify(label)}`);
  }
}

export interface RegexDetectorOptions {
  /** Reject a candidate after the regex matched, for example with a checksum. */
  validator?: (value: string) => boolean;
  /** Capture group (index or name) that holds the sensitive value; the whole match by default. */
  group?: number | string;
}

/** Build a detector from a regular expression. The "g" and "d" flags are added for you. */
export function regexDetector(
  label: string,
  pattern: string | RegExp,
  options: RegexDetectorOptions = {},
): Detector {
  checkLabel(label);
  const source = typeof pattern === "string" ? pattern : pattern.source;
  const baseFlags = typeof pattern === "string" ? "" : pattern.flags.replace(/[gdy]/g, "");
  const compiled = new RegExp(source, baseFlags + "gd");
  const { validator, group } = options;

  return {
    label,
    *find(text: string): Iterable<Span> {
      compiled.lastIndex = 0;
      for (const match of text.matchAll(compiled)) {
        const span =
          typeof group === "string" ? match.indices?.groups?.[group] : match.indices?.[group ?? 0];
        if (span === undefined || span[0] === span[1]) continue;
        const [start, end] = span;
        if (validator === undefined || validator(text.slice(start, end))) yield [start, end];
      }
    },
  };
}

/**
 * Build a detector from any function. It receives the text and returns spans
 * or plain strings; every occurrence of a returned string is a finding.
 */
export function callableDetector(
  label: string,
  func: (text: string) => Iterable<Span | string>,
): Detector {
  checkLabel(label);
  return {
    label,
    *find(text: string): Iterable<Span> {
      for (const item of func(text)) {
        if (typeof item === "string") {
          if (item === "") continue;
          let pos = text.indexOf(item);
          while (pos !== -1) {
            yield [pos, pos + item.length];
            pos = text.indexOf(item, pos + item.length);
          }
        } else {
          const [start, end] = item;
          if (!(Number.isInteger(start) && Number.isInteger(end) && 0 <= start && start < end && end <= text.length)) {
            throw new Error(`detector ${JSON.stringify(label)} returned an invalid span [${start}, ${end}]`);
          }
          yield [start, end];
        }
      }
    },
  };
}

/** True if the digits in `value` pass the Luhn checksum. */
export function luhnValid(value: string): boolean {
  const digits = Array.from(value.replace(/\D/g, ""), Number);
  if (digits.length === 0) return false;
  let total = 0;
  digits.reverse().forEach((digit, index) => {
    if (index % 2 === 1) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    total += digit;
  });
  return total % 10 === 0;
}

function cardValid(candidate: string): boolean {
  const digits = candidate.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  if (new Set(digits).size === 1) return false; // 0000 0000 0000 0000 passes Luhn but is no card
  return luhnValid(digits);
}

function phoneValid(candidate: string): boolean {
  const count = candidate.replace(/\D/g, "").length;
  return count >= 9 && count <= 15;
}

const HEX_GROUP = /^[0-9A-Fa-f]{1,4}$/;

/** Validate an IPv6 address without an embedded IPv4 tail. */
export function ipv6Valid(candidate: string): boolean {
  if (candidate.split(":").length - 1 < 2 || !/[0-9A-Za-z]/.test(candidate)) return false;
  const halves = candidate.split("::");
  if (halves.length > 2) return false;
  const groups = (part: string): string[] | null => {
    if (part === "") return [];
    const list = part.split(":");
    return list.every((g) => HEX_GROUP.test(g)) ? list : null;
  };
  if (halves.length === 1) return groups(candidate)?.length === 8;
  const head = groups(halves[0]!);
  const tail = groups(halves[1]!);
  return head !== null && tail !== null && head.length + tail.length <= 7;
}

const OCTET = String.raw`(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)`;

export const EMAIL = regexDetector(
  "EMAIL",
  String.raw`(?<![\w.+-])[A-Za-z0-9][A-Za-z0-9._%+-]*@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}(?![\w-])`,
);

export const PHONE = regexDetector(
  "PHONE",
  String.raw`(?<![\w.+-])(?<!\d{4}[ -])` +
    String.raw`(?:\+\d{9,15}` +
    String.raw`|\+\d{1,3}[ .-]\d{4,5}[ .-]\d{4,6}` +
    String.raw`|(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?|\d{2,4}[ .-])\d{3,4}[ .-]\d{3,4})` +
    String.raw`(?![ .-]?\d)(?!\w)`,
  { validator: phoneValid },
);

export const CREDIT_CARD = regexDetector(
  "CREDIT_CARD",
  String.raw`(?<![\w.+-])\d(?:[ -]?\d){12,18}(?![ -]?\d)(?!\w)`,
  { validator: cardValid },
);

export const SSN = regexDetector(
  "SSN",
  String.raw`(?<![\w-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\w-])`,
);

export const IPV4 = regexDetector("IP", String.raw`(?<![\w.])(?:${OCTET}\.){3}${OCTET}(?!\.?\w)`);

export const IPV6 = regexDetector("IP", String.raw`(?<![\w:.])[0-9A-Fa-f:]{3,39}(?![\w:])`, {
  validator: ipv6Valid,
});

export const PRIVATE_KEY = regexDetector(
  "PRIVATE_KEY",
  /-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z]+ )*PRIVATE KEY-----/,
);

export const API_KEY = regexDetector(
  "API_KEY",
  String.raw`(?<![A-Za-z0-9_-])(?:` +
    String.raw`(?:AKIA|ASIA)[0-9A-Z]{16}` + // AWS access key id
    String.raw`|gh[pousr]_[A-Za-z0-9]{36,}` + // GitHub tokens
    String.raw`|github_pat_[A-Za-z0-9_]{22,}` +
    String.raw`|glpat-[A-Za-z0-9_-]{20,}` + // GitLab personal access token
    String.raw`|sk-[A-Za-z0-9_-]{20,}` + // sk- style provider keys
    String.raw`|[sr]k_(?:live|test)_[A-Za-z0-9]{16,}` + // Stripe
    String.raw`|xox[abeprs]-[A-Za-z0-9-]{10,}` + // Slack
    String.raw`|AIza[0-9A-Za-z_-]{35}` + // Google API key
    String.raw`)(?![A-Za-z0-9_-])`,
);

export const JWT = regexDetector(
  "TOKEN",
  String.raw`(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}(?![A-Za-z0-9_-])`,
);

// The value classes already cover both cases, so a whole-pattern "i" flag only
// affects the keyword, matching the Python (?i:...) groups.
export const BEARER = regexDetector("TOKEN", /\bbearer\s+(?<value>[A-Za-z0-9._~+/-]{16,}=*)/i, {
  group: "value",
});

export const SECRET = regexDetector(
  "SECRET",
  new RegExp(
    String.raw`\b[\w-]*(?:api[_-]?key|secret|token|passwd|password)[\w-]*` +
      String.raw`\s*[:=]\s*["']?(?<value>[^\s"'<>,;]{8,})`,
    "i",
  ),
  { group: "value" },
);

/** When two detectors claim the same span, the one listed first wins. */
export const DEFAULT_DETECTORS: readonly Detector[] = Object.freeze([
  PRIVATE_KEY,
  API_KEY,
  JWT,
  BEARER,
  EMAIL,
  CREDIT_CARD,
  SSN,
  IPV4,
  IPV6,
  PHONE,
  SECRET,
]);
