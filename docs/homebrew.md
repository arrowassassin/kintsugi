# Installing via Homebrew

Two routes. Most projects ship a **tap** first (instant, no review), then graduate
to **homebrew-core** (`brew install kintsugi`) once the project is notable enough.

## Route 1 — your own tap (recommended)

A tap is just a GitHub repo named `homebrew-<name>` with formulae under `Formula/`.

1. Create a repo **`arrowassassin/homebrew-kintsugi`**.
2. Copy [`packaging/homebrew/kintsugi.rb`](../packaging/homebrew/kintsugi.rb) to
   `Formula/kintsugi.rb` in that repo.
3. Cut a release here (the repo's release workflow tags `vX.Y.Z` and builds
   artifacts). Set the formula's `url` to the tag tarball and its `sha256`:
   ```sh
   curl -L https://github.com/arrowassassin/kintsugi/archive/refs/tags/v0.1.0.tar.gz \
     | shasum -a 256
   ```
4. Users install with:
   ```sh
   brew install arrowassassin/kintsugi/kintsugi
   # or
   brew tap arrowassassin/kintsugi && brew install kintsugi
   ```

The formula builds the whole Rust workspace and installs all five binaries
(`kintsugi`, `kintsugi-daemon`, `kintsugi-shim`, `kintsugi-hook`, `kintsugi-mcp`).

### Validate before pushing
```sh
brew install --build-from-source ./packaging/homebrew/kintsugi.rb
brew test kintsugi
brew audit --strict --online kintsugi
```

## Route 2 — homebrew-core (`brew install kintsugi`)

Open a PR to [`Homebrew/homebrew-core`](https://github.com/Homebrew/homebrew-core)
adding `Formula/a/kintsugi.rb`. Core has strict bars:

- **Notability**: a maintained project with a stable, versioned release (not
  HEAD-only) and real usage (stars/forks/watchers are considered).
- **Builds from source** with a stable `url` + `sha256`; no network in `install`.
- A meaningful **`test do`** block (not just `--version` for some reviewers).
- Passes `brew audit --strict --new kintsugi` and `brew style`.
- Reviewers may decline niche/very-new tools — which is exactly why the tap comes
  first.

Once accepted, core auto-builds bottles and `brew install kintsugi` works everywhere.

## Note on the daemon

Homebrew installs the binaries only. Run `kintsugi init` once to start the resident
daemon and wire your agents. (A `brew services` plist for the daemon can be added
later if there's demand.)
