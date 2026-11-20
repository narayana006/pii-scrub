/** Find sensitive values and replace them with placeholders. */

import { DEFAULT_DETECTORS, type Detector } from "./detectors.ts";
import { Vault } from "./vault.ts";

export interface Finding {
  label: string;
  start: number;
  end: number;
  value: string;
}

export interface ScrubberOptions {
  /** Replaces the built-in detectors. */
  detectors?: readonly Detector[];
  /** Added before the built-ins, so they win when both claim the same span. */
  extra?: readonly Detector[];
}

export class Scrubber {
  readonly detectors: readonly Detector[];

  constructor(options: ScrubberOptions = {}) {
    this.detectors = [...(options.extra ?? []), ...(options.detectors ?? DEFAULT_DETECTORS)];
  }

  /**
   * Non-overlapping findings in the order they appear. When candidates
   * overlap, the one that starts first wins, then the longest, then detector order.
   */
  detect(text: string): Finding[] {
    const candidates: { start: number; end: number; rank: number; label: string }[] = [];
    this.detectors.forEach((detector, rank) => {
      for (const [start, end] of detector.find(text)) {
        candidates.push({ start, end, rank, label: detector.label });
      }
    });
    candidates.sort((a, b) => a.start - b.start || b.end - a.end || a.rank - b.rank);

    const findings: Finding[] = [];
    let cursor = 0;
    for (const { start, end, label } of candidates) {
      if (start < cursor) continue;
      findings.push({ label, start, end, value: text.slice(start, end) });
      cursor = end;
    }
    return findings;
  }

  /** Replace every finding with a placeholder. Pass a vault to keep numbering across texts. */
  scrub(text: string, vault: Vault = new Vault()): [string, Vault] {
    const parts: string[] = [];
    let cursor = 0;
    for (const finding of this.detect(text)) {
      parts.push(text.slice(cursor, finding.start));
      parts.push(vault.placeholderFor(finding.label, finding.value));
      cursor = finding.end;
    }
    parts.push(text.slice(cursor));
    return [parts.join(""), vault];
  }
}

export interface ScrubOptions extends ScrubberOptions {
  vault?: Vault;
}

/** Scrub `text` and return [safeText, vault]. Call vault.restore(modelOutput) to put originals back. */
export function scrub(text: string, options: ScrubOptions = {}): [string, Vault] {
  return new Scrubber(options).scrub(text, options.vault);
}
