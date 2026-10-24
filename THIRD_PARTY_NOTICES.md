# Third-party notices

## Gitleaks rule set

`server/detect/rules/gitleaks.json` (and its copy inside the bundled CLI and Action) is generated from the default
configuration of [Gitleaks](https://github.com/gitleaks/gitleaks) v8.30.1 by `npm run import:gitleaks`: rule ids,
regular expressions (translated from Go to JavaScript), keywords, entropy thresholds and allowlists.

```
MIT License

Copyright (c) 2019 Zachary Rice

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

Gitleaks is only used as a source of rules and, for benchmarking, run as a separate program (`npm run bench:fetch`); it is not bundled.

## Rules not taken from elsewhere

Tripwire's own rules (`server/detect/rules/tripwire.ts`) are written from each provider's published token format. No rules were copied from TruffleHog (AGPL-3.0).

## Data sources queried at run time

[OSV.dev](https://osv.dev) (vulnerability data, queried by `tripwire scan`) and [Canarytokens](https://canarytokens.org) (honey secrets) are used as web services and are not distributed with this package.
