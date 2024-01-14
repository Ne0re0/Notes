# Terminal multiplexer

***/!\\ Any of the following hostkeys will be activated after pressing `CTRL+B`***

##### Lil configuration
Add theses two lines to `~/.tmux.conf`
The first one allows to changes active panel by clicking on it
The second line activates vi features,
```text
set -g mouse on
setw -g mode-keys vi
```

## Managing sessions
```bash
tmux               # Create a new default session
tmux new -s NAME   # Create a new session called NAME
tmux attach        # Reenter the most recent session
tmux a -t NAME     # Reenter the session called NAME (a = attach)
tmux ls            # List sessions
tmux kill-server   # Kill every single piece from tmux
```

| Hotkey | What is does |
| :--: | ---- |
| d | Detach session |
| w | List windows and sessions and allows to jump to any of these |
| x | From the w menu, you can press `CTRL+b x` to delete an item |

## Managing windows
| Hotkey | What is does |
| :--: | ---- |
| c | Create a new window |
| n | Move to the next window (index based) |
| , | Name or rename a window |
| w | List windows and sessions and allows to jump to any of these |
| & | Kill the current window |

## Managing panels
| Hotkey | What is does |
| :--: | ---- |
| % | Split windows vertically |
| " | Split windows horizontally |
| q | Display panel indexes |
| q `index` | Switch to panel with index |
| Arrows | Switch to panel in direction of the arrow |
| CTRL + Arrows | Change the size of the current panel |
| x | Kill the current panel |
## Copy mode
| Hotkey | What is does |
| :--: | ---- |
| [ | Enter copy mode |
| (space) | Starts the copy buffer |
| Arrows | Highlight what you want to copy |
| ] | Exit copy mode |