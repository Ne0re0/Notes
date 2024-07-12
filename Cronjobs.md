# Cronjobs

## Create

Add a new line in `/etc/crontab`
```bash
# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed

*  *  *  *  *	root     /bin/echo $(/bin/whoami) >> /tmp/whoami
```

**Note :** 
- Take care to set absolute paths in command value
- It will automatically understand updates after editing `/etc/crontab` file

# Cron folders

Folders :
- `/etc/cron.minute`
- `/etc/cron.hourly`
- `/etc/cron.daily`
- `/etc/cron.weekly`
- `/etc/cron.monthly`
- `/etc/cron.yearly` *not present by default*

You can place scripts or symbolic link to scripts in those folders and they will run one time every hours/days/months/years.

**`/etc/crontab` configuration required**
```bash
17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.daily; }
47 6	* * 7	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.weekly; }
52 6	1 * *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.monthly; }
0  0    1 1 *	root	test -x /usr/sbin/anacron || { cd / && run-parts --report /etc/cron.yearly; }
```


**Symbolic link example**
```bash
sudo ln -s /root/backup.sh /etc/cron.daily/backup
```