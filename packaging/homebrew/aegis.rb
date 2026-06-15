# Homebrew formula for Aegis.
#
# For a tap: put this at `Formula/aegis.rb` in a repo named
# `arrowassassin/homebrew-aegis`, then users run:
#   brew install arrowassassin/aegis/aegis
#
# On each release: bump `url` to the new tag and set `sha256` to the tarball's
# checksum (`curl -L <url> | shasum -a 256`). See docs/homebrew.md.
class Aegis < Formula
  desc "Local-first safety layer for AI coding agents"
  homepage "https://github.com/arrowassassin/aegis"
  url "https://github.com/arrowassassin/aegis/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "REPLACE_WITH_TARBALL_SHA256"
  license "MIT"
  head "https://github.com/arrowassassin/aegis.git", branch: "main"

  depends_on "rust" => :build

  def install
    # Build the whole workspace and install every shipped binary: the `aegis`
    # CLI plus the resident daemon and the three interception adapters.
    system "cargo", "build", "--release", "--workspace", "--locked"
    %w[aegis aegis-daemon aegis-shim aegis-hook aegis-mcp].each do |b|
      bin.install "target/release/#{b}"
    end
  end

  def caveats
    <<~EOS
      Start the daemon and wire your agents with:
        aegis init

      Optional Claude Code plugin (registers the hook + MCP server):
        /plugin marketplace add arrowassassin/aegis
        /plugin install aegis@aegis
    EOS
  end

  test do
    assert_match "aegis", shell_output("#{bin}/aegis --version")
    # `status` runs without a daemon and reports it as stopped.
    assert_match "daemon", shell_output("#{bin}/aegis status 2>&1", 0)
  end
end
