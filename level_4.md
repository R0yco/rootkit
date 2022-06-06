# level 4

now we need to hide a process from ps command.
ps gets its information from /proc filesystem.

it iterates over it and gets the relevant information and displays it nicely.

so here, I can, like in level 2, use the call to getdents64 to catch ps trying to list the contents of /proc, and filter by pid.



```
openat(AT_FDCWD, "/proc", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 5
getdents64(5, 0x55dd42415060 /* 387 entries */, 32768) = 9784
```



but this solution is not very good- getdents64 gets an open fd and uses it, it is not aware of what is the name of the directory it lists. this means that if we filter getdents64 entries by "pid", we might have wierd side-effects of users listing things with the same name as that pid and it will be hidden- not very common but possible.

so I will try to find a more subtle solution, and if it doesn't work I will come back to this.

actually, my current solution for hiding from ls works out of the box for hiding procceses with this method too:

```bash
_  ls_rootkit git:(main) _ ps aux | grep python

root         800  0.0  0.5  49668 21448 ?        Ss   Jun05   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root         948  0.0  0.6 126692 23360 ?        Ssl  Jun05   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
royco      16334  0.6  0.4  38716 17256 pts/3    S+   01:11   0:00 python3 -m http.server
royco      16336  0.0  0.0  17864  2372 pts/2    S+   01:11   0:00 grep --color=auto --exclude-dir=.bzr --exclude-dir=CVS --exclude-dir=.git --exclude-dir=.hg --exclude-dir=.svn --exclude-dir=.idea --exclude-dir=.tox python



_  ls_rootkit git:(main) _ sudo ./insert_rootkit.sh 16334 

_  ls_rootkit git:(main) _ ps aux | grep python          
root         800  0.0  0.5  49668 21448 ?        Ss   Jun05   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root         948  0.0  0.6 126692 23360 ?        Ssl  Jun05   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
royco      16374  0.0  0.0  17864  2304 pts/2    S+   01:11   0:00 grep --color=auto --exclude-dir=.bzr --exclude-dir=CVS --exclude-dir=.git --exclude-dir=.hg --exclude-dir=.svn --exclude-dir=.idea --exclude-dir=.tox python

```
