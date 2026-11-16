# Recorded by scripts/record-gifs.sh. Fills GIF, LOG, SLEEP, and ROOT
# (clone root) at record time so the tape is not tied to one path.
Output "__GIF__"
Require python3
Require datagrant
Set Shell bash
Set FontSize 12
Set FontFamily "JetBrains Mono"
Set Width 840
Set Height 480
Set Padding 10
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set WindowBarSize 28
Set Framerate 8
Set TypingSpeed 1ms
Set PlaybackSpeed 1.0
Hide
Type "cd __ROOT__ && export PS1='$ '"
Enter
Ctrl+L
Show
Type "python3 scripts/play_demo_log.py __LOG__"
Enter
Sleep __SLEEP__
