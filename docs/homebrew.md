# Installing via Homebrew

Two routes. Most projects ship a **tap** first (instant, no review), then graduate
to **homebrew-core** (`brew install aegis`) once the project is notable enough.

## Route 1 — your own tap (recommended)

A tap is just a GitHub repo named `homebrew-<name>` with formulae under `Formula/`.

1. Create a repo **`arrowassassin/homebrew-aegis`**.
2. Copy [`packaging/homebrew/aegis.rb`](../packaging/homebrew/aegis.rb) to
   `Formula/aegis.rb` in that repo.
3. Cut a release here (the repo's release workflow tags `vX.Y.Z` and builds
   artifacts). Set the formula's `url` to the tag tarball and its `sha256`:
   ```sh
   curl -L https://github.com/arrowassassin/aegis/archive/refs/tags/v0.1.0.tar.gz \
     | shasum -a 256
   ```
4. Users install with:
   ```sh
   brew install arrowassassin/aegis/aegis
   # or
   brew tap arrowassassin/aegis && brew install aegis
   ```

The formula builds the whole Rust workspace and installs all five binaries
(`aegis`, `aegis-daemon`, `aegis-shim`, `aegis-hook`, `aegis-mcp`).

### Validate before pushing
```sh
brew install --build-from-source ./packaging/homebrew/aegis.rb
brew test aegis
brew audit --strict --online aegis
```

## Route 2 — homebrew-core (`brew install aegis`)

Open a PR to [`Homebrew/homebrew-core`](https://github.com/Homebrew/homebrew-core)
adding `Formula/a/aegis.rb`. Core has strict bars:

- **Notability**: a maintained project with a stable, versioned release (not
  HEAD-only) and real usage (stars/forks/watchers are considered).
- **Builds from source** with a stable `url` + `sha256`; no network in `install`.
- A meaningful **`test do`** block (not just `--version` for some reviewers).
- Passes `brew audit --strict --new aegis` and `brew style`.
- Reviewers may decline niche/very-new tools — which is exactly why the tap comes
  first.

Once accepted, core auto-builds bottles and `brew install aegis` works everywhere.

## Note on the daemon

Homebrew installs the binaries only. Run `aegis init` once to start the resident
daemon and wire your agents. (A `brew services` plist for the daemon can be added
later if there's demand.)
