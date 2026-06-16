# VHS tape for the Kintsugi 30-second demo → docs/kintsugi-demo.gif
#
# Install VHS (https://github.com/charmbracelet/vhs), then:
#     vhs scripts/demo.tape
#
# Produces a GIF of: a safe command passing, `rm -rf` being HELD before it runs,
# you pressing `d` to deny, and the tamper-evident timeline.

Output docs/kintsugi-demo.gif

Set Shell "bash"
Set FontSize 18
Set Width 1100
Set Height 720
Set Padding 24
Set Theme "Dracula"
Set TypingSpeed 60ms

Hide
Type "cargo build --quiet" Enter
Wait
Show

Type "bash scripts/demo.sh"
Sleep 500ms
Enter

# Wait for the hold card to appear, then deny.
Sleep 4s
Type "d"
Enter

# Let the timeline render.
Sleep 4s
