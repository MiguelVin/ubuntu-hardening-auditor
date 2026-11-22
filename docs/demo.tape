# Terminal GIF for the README and social media, made with VHS
# (https://github.com/charmbracelet/vhs). No video editing needed.
#
#   1. Start the lab:   docker compose -f lab/docker-compose.yml up -d --build --force-recreate
#   2. Record:          vhs docs/demo.tape
#   3. Result:          docs/img/demo.gif

Output docs/img/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1280
Set Height 760
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms

Type "# A deliberately vulnerable Ubuntu. Let's audit it:"
Enter
Sleep 1s
Type "docker exec -t hardaudit-lab hardaudit --no-hints"
Enter
Sleep 6s

Type "clear"
Enter
Type "# Now fix only what is safe to fix automatically:"
Enter
Sleep 1s
Type "docker exec -t hardaudit-lab hardaudit --fix --yes --no-hints | tail -22"
Enter
Sleep 8s
