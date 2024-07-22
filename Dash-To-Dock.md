
**Ever wanted to make your menu bar always displayed in a Gnome environnement ?**

![](images/Pasted%20image%2020240708170345.png)

Extension : https://github.com/micheleg/dash-to-dock

```bash
sudo apt-get install git ruby-sass sassc gnome-tweaks gnome-shell-extensions
git clone https://github.com/micheleg/dash-to-dock.git
make -C dash-to-dock install
gnome-shell-extensions-prefs
# Enable the extension
```