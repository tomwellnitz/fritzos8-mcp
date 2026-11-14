# Demo GIF for the README – regenerate with `make demo` (needs vhs: https://github.com/charmbracelet/vhs).
# Runs scripts/demo.py: the real MCP server against a simulated FRITZ!Box from the test fakes (invented data).
Output docs/demo.gif

Require uv

Set Shell "bash"
Set FontSize 16
Set Width 1000
Set Height 600
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 40ms
Set Framerate 12
Set PlaybackSpeed 1.0

Hide
Type "export PS1='$ ' && uv sync --frozen --group demo -q && clear"
Enter
Sleep 3s
Show

Type "uv run --frozen --group demo python scripts/demo.py"
Sleep 400ms
Enter
Wait+Screen@40s /plan → token → execute/
Sleep 3s
