/** The vault maps placeholders back to the original values. */

const PLACEHOLDER_RE = /<([A-Z][A-Z0-9_]*?)_(\d+)>/g;
const PLACEHOLDER_FULL_RE = /^<([A-Z][A-Z0-9_]*?)_(\d+)>$/;
export const FORMAT_VERSION = 1;

/** The JSON shape shared with the Python package's vault files. */
export interface VaultData {
  version: number;
  entries: Record<string, string>;
}

/**
 * Holds the placeholder-to-original mapping for one or more scrub calls.
 *
 * The same original value always gets the same placeholder. The vault holds
 * the real sensitive values: keep it on your side and never send it along.
 */
export class Vault {
  #originals = new Map<string, string>();
  #placeholders = new Map<string, string>();
  #counters = new Map<string, number>();

  /** Return the placeholder for `value`, creating one if needed. */
  placeholderFor(label: string, value: string): string {
    const key = `${label}\u0000${value}`;
    const existing = this.#placeholders.get(key);
    if (existing !== undefined) return existing;
    const number = (this.#counters.get(label) ?? 0) + 1;
    this.#counters.set(label, number);
    const placeholder = `<${label}_${number}>`;
    this.#originals.set(placeholder, value);
    this.#placeholders.set(key, placeholder);
    return placeholder;
  }

  /** Swap every known placeholder in `text` for its original; unknown ones are left alone. */
  restore(text: string): string {
    return text.replace(PLACEHOLDER_RE, (match) => this.#originals.get(match) ?? match);
  }

  get size(): number {
    return this.#originals.size;
  }

  has(placeholder: string): boolean {
    return this.#originals.has(placeholder);
  }

  get(placeholder: string): string | undefined {
    return this.#originals.get(placeholder);
  }

  /** [placeholder, original] pairs in the order they were created. */
  items(): [string, string][] {
    return [...this.#originals.entries()];
  }

  /** Number of distinct values stored per label. */
  counts(): Record<string, number> {
    return Object.fromEntries(this.#counters);
  }

  toJSON(): VaultData {
    return { version: FORMAT_VERSION, entries: Object.fromEntries(this.#originals) };
  }

  /** Rebuild a vault from `toJSON()` output or a vault file written by the Python CLI. */
  static fromJSON(data: unknown): Vault {
    const entries = (data as { entries?: unknown } | null)?.entries;
    if (typeof entries !== "object" || entries === null || Array.isArray(entries)) {
      throw new Error("not a pii-scrub vault: missing 'entries' mapping");
    }
    const vault = new Vault();
    for (const [placeholder, original] of Object.entries(entries)) {
      const match = PLACEHOLDER_FULL_RE.exec(placeholder);
      if (match === null || typeof original !== "string") {
        throw new Error(`invalid vault entry ${JSON.stringify(placeholder)}`);
      }
      const label = match[1]!;
      const number = Number(match[2]);
      vault.#originals.set(placeholder, original);
      vault.#placeholders.set(`${label}\u0000${original}`, placeholder);
      vault.#counters.set(label, Math.max(vault.#counters.get(label) ?? 0, number));
    }
    return vault;
  }
}
