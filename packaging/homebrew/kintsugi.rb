# Homebrew formula for Kintsugi — mirror of the tap-ready copy at
# `Formula/kintsugi.rb` (repo root); keep the two in sync.
#
# For the tap: copy this file (identical to `Formula/kintsugi.rb` at the repo
# root) to `Formula/kintsugi.rb` in the `kintsugi-tools/homebrew-tap` repo,
# then users run:
#   brew install kintsugi-tools/kintsugi/kintsugi
#
# On each release: bump `url` to the new tag and set `sha256` to the source
# tarball's checksum (`curl -L <url> | shasum -a 256`). See docs/homebrew.md.
class Kintsugi < Formula
  desc "Local-first safety layer for AI coding agents"
  homepage "https://github.com/kintsugi-tools/kintsugi"
  url "https://github.com/kintsugi-tools/kintsugi/archive/refs/tags/v0.3.1.tar.gz"
  # sha256 of the GitHub auto-generated source archive for the v0.3.1 tag.
  sha256 "ce0a4efb9a3a805ed6ecac7fcf74b13c5bac047c785a77e8aec921f0dab618c4"
  license "MIT"
  head "https://github.com/kintsugi-tools/kintsugi.git", branch: "main"

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
        /plugin marketplace add kintsugi-tools/kintsugi
        /plugin install kintsugi@kintsugi
    EOS
  end

  test do
    assert_match "kintsugi", shell_output("#{bin}/kintsugi --version")
    # `status` runs without a daemon and reports it as stopped.
    assert_match "daemon", shell_output("#{bin}/kintsugi status 2>&1", 0)
  end
end
