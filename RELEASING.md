# Releasing

The Action, the CLI, the pre-commit hook and the npm package all ship the same committed bundle in `action/`, so a release is mostly "rebuild, test, tag".

1. `npm test && npm run typecheck && npm run bench -- --gate` (run `npm run bench:fetch` once first). All must pass.
2. Set the new version in `package.json`, then `npm run build:cli` and commit the rebuilt `action/` with it. The bundle in the tag must match the source in the tag.
3. `npm run scan -- . --skip-vulns --history 0` should pass (this repo scans itself).
4. Tag and push, moving the major tag so `@v1` users get the update:
   ```bash
   git tag -a v1.0.0 -m "v1.0.0" && git tag -fa v1 -m "v1" && git push origin main v1.0.0 && git push -f origin v1
   gh release create v1.0.0 --title "v1.0.0" --generate-notes
   ```
5. **GitHub Marketplace** (first release only, in the browser): open the release, edit it, tick *Publish this Action to the GitHub Marketplace*, choose a category (Security), accept the developer agreement, and save. The name in `action.yml` must be unique across the Marketplace.
6. **npm**: `npm login`, then `npm publish` from a clean checkout of the tag (`prepack` rebuilds the bundle). The package is `tripwire-scan`; the command it installs is `tripwire`. Check the result with `npx tripwire-scan --help`.
7. Bump `rev:` in the README's pre-commit snippet if the tag changed.

Regenerate the imported Gitleaks rules with `npm run import:gitleaks` when you want newer rules; re-run the benchmark afterwards and commit `bench/RESULTS.md`.
