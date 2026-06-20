# Security Policy

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

Instead, report them privately through GitHub's private vulnerability reporting:

1. Go to the [**Security** tab](https://github.com/dhh1128/entviz-rs/security) of this repository.
2. Click **Report a vulnerability** to open a private advisory draft.
3. Fill in as much detail as you can (see "What to include" below).

This routes the report directly and privately to the maintainer, who is
notified by GitHub. Your report is not visible to the public.

### What to include

A good report helps us confirm and fix the issue quickly. Where possible,
please include:

- The type of issue (e.g. injection, data exposure, auth bypass, dependency vuln).
- The affected component, file path, and/or version or commit.
- Step-by-step instructions to reproduce.
- Proof-of-concept or exploit code, if you have it.
- The impact: what an attacker could do with this.

## Our Commitment

We follow a responsible (coordinated) disclosure model:

- **Acknowledgement:** We will acknowledge your report within **3 business days**.
- **Assessment:** We will investigate and let you know whether we agree it is a
  vulnerability, and our planned course of action.
- **Fix timeline:** For issues we confirm, we aim to release a fix within
  **30 days** of acknowledgement. Complex issues may take longer; if so, we
  will keep you informed of progress.
- **Coordination:** We will coordinate the timing of public disclosure with you
  and credit you in the published advisory unless you prefer to remain anonymous.

We ask that you give us a reasonable opportunity to address the issue before
any public disclosure.

## No Bug Bounty

Entviz is a personal open-source project. **We do not offer a paid bug bounty
or any other monetary reward** for vulnerability reports. We genuinely
appreciate responsible disclosure and are happy to publicly credit reporters in
the advisory, but please report only because you want to help — not in
expectation of payment.

## Supported Versions

The `entviz` crate is pre-1.0 and ships from the `main` branch. Security fixes
are applied to `main` and released as a new version on crates.io; there are no
long-term support branches. Please ensure you are running the latest published
version before reporting.

## Threat model / trust boundaries

`entviz` is a pure, deterministic library: it takes an entropy string plus
rendering parameters and returns an SVG string. It performs no I/O, network, or
filesystem access, spawns no processes, and contains **zero `unsafe` code**. The
main trust boundary is the **untrusted input string** and the fact that the
output SVG is typically **embedded into an HTML page** by a downstream consumer.

- **Input is untrusted.** Callers may pass arbitrary, attacker-controlled
  strings. Two defenses bound this:
  - **Output injection** — the only free-text that reaches the SVG is the
    optional `note`. `sanitize_note` is a MUST-reject gate: a note is rejected
    unless it is ASCII-alphanumeric and at most 8 characters. All other text
    written into the SVG (cell glyphs, labels) is XML-escaped via `esc_attr`
    (escapes `& < > "`) for attribute contexts and `esc_text` (escapes `& < >`)
    for element-text contexts, so an input cannot break out of its markup
    context and inject elements/attributes.
  - **Denial of service** — input is capped at `MAX_INPUT_CHARS` (65536) before
    parsing, and large inputs are tokenized over only a bounded head + tail
    window (plus four digest-derived middle tokens), never the full core, so
    work is bounded regardless of input size.

- **Accepted risk — host-page CSS override.** The SVG carries all visual
  channels via *inline presentation attributes* (`fill`/`stroke`), which sit at
  the lowest tier of the CSS cascade. A hostile or careless host page can apply
  `!important` rules that override these and neutralize the discriminating
  channels. This is inherent to non-isolated embedded SVG, not a defect in this
  crate; consumers that need to defend against it should isolate the SVG (e.g.
  an `<iframe>` or shadow DOM). Treated as an accepted, documented risk.

- **Out of scope.** entviz makes no cryptographic security claim: it is a
  *visualization* of entropy for human comparison, not a commitment, MAC, or
  authentication primitive. The SHA-512 fingerprint is used only to derive
  deterministic visual structure.
