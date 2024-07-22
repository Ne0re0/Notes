
> chroot allows to run process in an independent filesystem.
> It requires creating the chroot environnement before running the process (i.e. set up all available commands)


> [!NOTE] chroot setup
> chroot environments are a pain to setup but help increase the safety when running untrusted scripts

# Setup

```bash
# Setting up variables
chroot_directory="/newroot/"  # EDIT HERE
BINARIES="/bin/bash /bin/touch /bin/ls /bin/rm /usr/sbin/usermod" # EDIT HERE

# Create the futur chroot directory
mkdir -p $chroot_directory

# Load commands
for cmd in $BINARIES; 
do 
	cp -v --parents "$cmd" "$chroot_directory"
	list="$(ldd "$cmd" | egrep -o '/lib.*\.[0-9]')"
	for i in $list; do cp -v --parents "$i" "${chroot_directory}"; done
done
```

# Launch the chroot env

```bash
sudo chroot $chroot_directory /bin/bash
```