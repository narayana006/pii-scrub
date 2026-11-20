/** Redact PII and secrets from text with reversible placeholders. */

export {
  DEFAULT_DETECTORS,
  callableDetector,
  ipv6Valid,
  luhnValid,
  regexDetector,
  type Detector,
  type RegexDetectorOptions,
  type Span,
} from "./detectors.ts";
export { Scrubber, scrub, type Finding, type ScrubOptions, type ScrubberOptions } from "./scrubber.ts";
export { FORMAT_VERSION, Vault, type VaultData } from "./vault.ts";
