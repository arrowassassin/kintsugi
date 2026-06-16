# Homebrew formula for Kintsugi.
#
# For a tap: put this at `Formula/kintsugi.rb` in a repo named
# `arrowassassin/homebrew-kintsugi`, then users run:
#   brew install arrowassassin/kintsugi/kintsugi
#
# On each release: bump `url` to the new tag and set `sha256` to the tarball's
# checksum (`curl -L <url> | shasum -a 256`). See docs/homebrew.md.
class Kintsugi < Formula
  desc "Local-first safety layer for AI coding agents"
  homepage "https://github.com/arrowassassin/kintsugi"
  url "https://github.com/arrowassassin/kintsugi/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "REPLACE_WITH_TARBALL_SHA256"
  license "MIT"
  head "https://github.com/arrowassassin/kintsugi.git", branch: "main"

  depends_on "rust" => :build

  def install
    # Build the whole workspace and install every shipped binary: the `kintsugi`
    # CLI plus the resident daemon and the three interception adapters.
    system "cargo", "build", "--release", "--workspace", "--locked"
    %w[kintsugi kintsugi-daemon kintsugi-shim kintsugi-hook kintsugi-mcp].each do |b|
      bin.install "target/release/#{b}"
    end
  end

  def caveats
    <<~EOS
      Start the daemon and wire your agents with:
        kintsugi init

      Optional Claude Code plugin (registers the hook + MCP server):
        /plugin marketplace add arrowassassin/kintsugi
        /plugin install kintsugi@kintsugi
    EOS
  end

  test do
    assert_match "kintsugi", shell_output("#{bin}/kintsugi --version")
    # `status` runs without a daemon and reports it as stopped.
    assert_match "daemon", shell_output("#{bin}/kintsugi status 2>&1", 0)
  end
end
