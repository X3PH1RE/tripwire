# Detection benchmark

108 positive cases (real provider token formats with synthetic values, several contexts each, plus encoded and multi-line secrets) and 56 negative cases (placeholders, hashes, UUIDs, env references, lockfiles, docs, identifiers).
A case counts as detected when the tool reports anything in its file. A negative case that gets any finding is a false positive.

| Tool | Version | Precision | Recall | F1 | Missed | False positives | Time |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Tripwire | this repo | 100.0% | 100.0% | 100.0% | 0/108 | 0/56 | 430 ms |
| Gitleaks | 8.30.1 | 97.0% | 88.9% | 92.8% | 12/108 | 3/56 | 1184 ms |

## Tripwire

Missed: none

False positives: none

## Gitleaks

Missed: Docker Hub token (pos-19-1); Replicate API token (pos-22-1); Groq API key (pos-23-1); xAI API key (pos-24-1); Supabase access token (pos-25-1); Figma personal access token (pos-26-1); Neon API key (pos-27-1); Postgres URL with password (pos-29-0); Postgres URL with password (pos-29-1); MongoDB URL with password (pos-30-0); MongoDB URL with password (pos-30-1); Generic bare password key (pos-33-0)

False positives: git commit SHA (neg-git-sha: generic-api-key); sha256 digest in a checksum field (neg-sha256-digest: generic-api-key); cache key that is a sha1 (neg-cache-key-sha1: generic-api-key)

## Caveat

The corpus is written by the Tripwire authors, so it favours Tripwire's own rules. Treat the numbers as a regression gate and a parity check against Gitleaks, not as an independent ranking. Add cases to `bench/corpus.mts` whenever a real-world miss or false positive turns up.
