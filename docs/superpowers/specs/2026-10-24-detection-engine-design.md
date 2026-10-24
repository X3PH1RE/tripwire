# Detection engine

Replaces the hard-coded rules in `server/real/rules.ts` with a declarative, measurable engine.

## Goals

- Breadth: hundreds of provider rules (imported Gitleaks baseline + our own).
- Precision: per-rule entropy, allowlists, structure checks, multi-line support.
- Measurable: a labeled benchmark that scores Tripwire and Gitleaks side by side.
- Non-breaking: `matchLine()` and `mask()` keep their signatures; graph, verifier and CLI are untouched.

## Layout

```
server/detect/
  schema.ts      Rule / Allowlist types
  gitleaks.ts    Go-regex -> JS translator and Gitleaks config importer
  rules/         generated gitleaks.json + hand-written tripwire rules
  engine.ts      compile, keyword prefilter, scan a line or a whole file
  filters.ts     entropy, placeholders, stopwords, structure checks, decoders
  baseline.ts    .tripwire-baseline.json (fingerprints, never raw values)
server/real/rules.ts   shim delegating to the engine
bench/                 labeled corpus + runner (Tripwire vs Gitleaks)
```

Rule files are JSON (generated from Gitleaks TOML by `npm run import:gitleaks`) and TypeScript data, so the CLI/Action bundle needs no runtime file reads.

## Behaviour

1. Keyword prefilter: a line is lowercased once; rules whose keywords are absent never run their regex.
2. Match, then take the secret as `secretGroup`, else the first non-empty capture group, else the whole match.
3. Filters, any of which rejects: rule/global allowlists (regexes, stopwords, paths), placeholder check (whole-value only for weak words), per-rule entropy on the secret, structure checks (AWS, GitHub checksum, JWT).
4. Generic assignment rule keeps the variable-name trigger and ignores hashes, UUIDs and version strings.
5. Multi-line rules (`multiline`) run over the whole file; a private key needs BEGIN..END.
6. Decoders: base64 / URL / hex, up to two layers, findings labelled with how they were found.
7. Baseline: fingerprints of accepted findings; those report as `baselined` and do not fail.
8. Every finding carries `confidence` (high/medium/low); `--min-confidence` filters.

## Benchmark

`bench/corpus` holds positives (real token formats, synthetic values) and bait (placeholders, hashes, UUIDs, docs). `bench/run.ts` scores Tripwire, and Gitleaks when a binary is present, reporting precision and recall per tool.

## Licensing

Imported Gitleaks rules stay in `rules/gitleaks.json` with the MIT notice. Own rules are written from provider documentation. Nothing is copied from TruffleHog (AGPL).
