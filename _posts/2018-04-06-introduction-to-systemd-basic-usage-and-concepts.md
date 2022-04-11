---
title: "Introduction to systemd : Basic Usage and Concepts"
date: "2018-04-06"
categories: 
  - "linux"
  - "software"
  - "sysadmin"
tags: 
  - "debate"
  - "debian"
  - "init"
  - "linux"
  - "management"
  - "sysadmin"
  - "systemd"
  - "sysvinit"
coverImage: "Linux_kernel_unified_hierarchy_cgroups_and_systemd.png"
author:
  name: Shahriar
  link: https://github.com/Xcess
---

Hi everyone

In this post I am going to explain some essential systemd commands and concepts. As systemd popularity grew much more and changed the linux ecosystem drastically, every sysadmin, DevOps or every casual linux user should know the basics of this init system (It's really a load of other things too!) and be able to use systemctl, journalctl, etc in order to leverage its power.

For example, by using systemd unit files you can completely get rid of using crontab as systemd replaces this functionality, you can also run the service as a temporary user or even activate a service when a connection is made to a specific port on server. as you can see, the possibilities are endless. Some of them will hopefully be described in further posts and links provided at the end of this post.

 

![systemd logo](../../assets/images/systemd_logo.gif)

* * *

# Concepts

## Unit Files

Most systemd configuration take place in unit files. unit files are short configuration snippets that control behavior of systmed. Unit files are of different types which will be described below:

### Service File

A service unit file is configuration file that shows how you like to run a specific process, like a web server application, a docker container, etc. It can be anything, even your own application.

### Target File

A target unit file is mechanism used for grouping different services and starting them at the same time or in another desired fashion.

### Timer units

Timer units are used to run services at specific times, like crontab.

### Path units

Watches a path and responds based on defined actions.

### Slice Units

Slice units are used for resource management of other units. Units are assigned to a slice which controls their use of resources. By default units are assigned to a default slice. which is "system.slice" for services and scope units, "user.slice" for user sessions and "machine.slice" for containers registered with _systemd-machined._

### Socket Units

Socket units are used to activate another service on request to a socket. It facilitates on-demand service activation. You can setup a server which listen for ssh connection and creates a container for each user which connects to the server and connects the user to the container. only using systemd! your power is limited by your imagination :D

### Device Unit

systemd wrapper for **udev** devices.

### Mount Units

Mount units are simply used to mount a filesystem automatically (or manually).

* * *

A sample service unit file (OpenSSH on debian jessie):

\[Unit\]
Description=OpenBSD Secure Shell server
After=network.target auditd.service
ConditionPathExists=!/etc/ssh/sshd\_not\_to\_be\_run

\[Service\]
EnvironmentFile=-/etc/default/ssh
ExecStartPre=/usr/sbin/sshd -t
ExecStart=/usr/sbin/sshd -D $SSHD\_OPTS
ExecReload=/usr/sbin/sshd -t
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure

\[Install\]
WantedBy=multi-user.target
Alias=sshd.service

It is rather self-explanatory so after another example (a unit file for a docker container from [CoreOS](https://coreos.com/os/docs/latest/getting-started-with-systemd.html)):

\[Unit\]
Description=MyApp
After=docker.service
Requires=docker.service

\[Service\]
TimeoutStartSec=0
ExecStartPre=-/usr/bin/docker kill busybox1
ExecStartPre=-/usr/bin/docker rm busybox1
ExecStartPre=/usr/bin/docker pull busybox
ExecStart=/usr/bin/docker run --name busybox1 busybox /bin/sh -c "trap 'exit 0' INT TERM; while true; do echo Hello World; sleep 1; done"

\[Install\]
WantedBy=multi-user.target

$ sudo systemctl enable /etc/systemd/system/hello.service
$ sudo systemctl start hello.service

 

* * *

## systemd commands

### systemctl

The most import command is probably **systemctl**. It is used for starting/stopping services. Here's a good table from [HighOnCoffee](https://highon.coffee/blog/systemd-cheat-sheet/):

<table style="height: 498px;width:100%"><tbody><tr style="background:#f00;color:#fff"><td>systemctl stop service-name</td><td>systemd stop running service</td></tr><tr style="background:#f00;color:#fff"><td>systemctl start service-name</td><td>systemctl start service</td></tr><tr style="background:#f00;color:#fff"><td>systemctl restart service-name</td><td>systemd restart running service</td></tr><tr style="background:#f00;color:#fff"><td>systemctl reload service-name</td><td>reloads all config files for service</td></tr><tr style="background:#f00;color:#fff"><td>systemctl status service-name</td><td>systemctl show if service is running</td></tr><tr style="background:#f00;color:#fff"><td>systemctl enable service-name</td><td>systemctl start service at boot</td></tr><tr style="background:#f00;color:#fff"><td>systemctrl disable service-name</td><td>systemctl - disable service at boot</td></tr><tr style="background:#f00;color:#fff"><td>systemctl show service-name</td><td>show systemctl service info</td></tr></tbody></table>

List service dependencies with this command:

\# systemctl list-dependencies sshd.service

 

Change ad-hoc runlevel with systemctl isolate command. Boot targets are somehow equivalent to SysV init runlevels:

> - Switch to another target (in this case multi-user/runlevel 3 in old SysV):

systemctl isolate multi-user.target

> - Switch to graphical target (in this case graphical/runlevel 5 in old SysV):

systemctl isolate graphical.target

* * *

### journalctl

View all log entries starting from this boot:

$ journalctl -b

view only kernel messages from this boot:

$ journalctl -k -b

using **\-x** flag attaches some additional data to the logs, **\-n** can get an integer and show this much lines (default 10):

$ journalctl -xn

view all logs from a specific service:

$ journalctl -b -e -u nginx.service

* * *

That's All folks!

systemd has sooo many features (and of course so much [criticism](http://www.zdnet.com/article/linus-torvalds-and-others-on-linuxs-systemd/) and [debate](http://0pointer.de/blog/projects/the-biggest-myths.html)!). I will try to cover more advanced features of systemd in following posts on this blog. Here are some links that will be useful for you:

[https://access.redhat.com/articles/systemd-cheat-sheet](https://access.redhat.com/articles/systemd-cheat-sheet)

[https://gist.github.com/mbodo/8f87c96ce11e91f80fbf6175412a2206](https://gist.github.com/mbodo/8f87c96ce11e91f80fbf6175412a2206)

[https://www.digitalocean.com/community/tutorials/how-to-use-systemctl-to-manage-systemd-services-and-units](https://www.digitalocean.com/community/tutorials/how-to-use-systemctl-to-manage-systemd-services-and-units)

[https://wiki.archlinux.org/index.php/Systemd](https://wiki.archlinux.org/index.php/Systemd)

and this series of articles by Lennart Poettering (core systemd developer!):

- \[systemd-for-admins-I\] ([http://0pointer.net/blog/projects/systemd-for-admins-1.html](http://0pointer.net/blog/projects/systemd-for-admins-1.html))
- \[systemd-for-admins-II\] ([http://0pointer.net/blog/projects/systemd-for-admins-2.html](http://0pointer.net/blog/projects/systemd-for-admins-2.html))
- \[systemd-for-admins-II\] ([http://0pointer.net/blog/projects/systemd-for-admins-3.html](http://0pointer.net/blog/projects/systemd-for-admins-3.html))
- \[systemd-for-admins-IV\] ([http://0pointer.net/blog/projects/systemd-for-admins-4.html](http://0pointer.net/blog/projects/systemd-for-admins-4.html))
- \[systemd-for-admins-V\] ([http://0pointer.net/blog/projects/three-levels-of-off.html](http://0pointer.net/blog/projects/three-levels-of-off.html))
- \[systemd-for-admins-VI\] ([http://0pointer.net/blog/projects/changing-roots.html](http://0pointer.net/blog/projects/changing-roots.html))
- \[systemd-for-admins-VII\] ([http://0pointer.net/blog/projects/blame-game.html](http://0pointer.net/blog/projects/blame-game.html))
- \[systemd-for-admins-VIII\] ([http://0pointer.net/blog/projects/the-new-configuration-files.html](http://0pointer.net/blog/projects/the-new-configuration-files.html))
- \[systemd-for-admins-IX\] ([http://0pointer.net/blog/projects/on-etc-sysinit.html](http://0pointer.net/blog/projects/on-etc-sysinit.html))
- \[systemd-for-admins-X\] ([http://0pointer.net/blog/projects/instances.html](http://0pointer.net/blog/projects/instances.html))
- \[systemd-for-admins-XI\] ([http://0pointer.net/blog/projects/inetd.html](http://0pointer.net/blog/projects/inetd.html))
- \[systemd-for-admins-XII\] ([http://0pointer.net/blog/projects/security.html](http://0pointer.net/blog/projects/security.html))
- \[systemd-for-admins-XIII\] ([http://0pointer.net/blog/projects/systemctl-journal.html](http://0pointer.net/blog/projects/systemctl-journal.html))
- \[systemd-for-admins-XIV\] ([http://0pointer.net/blog/projects/self-documented-boot.html](http://0pointer.net/blog/projects/self-documented-boot.html))
- \[systemd-for-admins-XV\] ([http://0pointer.net/blog/projects/watchdog.html](http://0pointer.net/blog/projects/watchdog.html))
- \[systemd-for-admins-XVI\] ([http://0pointer.net/blog/projects/serial-console.html](http://0pointer.net/blog/projects/serial-console.html))
- \[systemd-for-admins-XVII\] ([http://0pointer.net/blog/projects/journalctl.html](http://0pointer.net/blog/projects/journalctl.html))
- \[systemd-for-admins-XVIII\] ([http://0pointer.net/blog/projects/resources.html](http://0pointer.net/blog/projects/resources.html))
- \[systemd-for-admins-XIX\] ([http://0pointer.net/blog/projects/detect-virt.html](http://0pointer.net/blog/projects/detect-virt.html))
- \[systemd-for-admins-XX\] ([http://0pointer.net/blog/projects/socket-activated-containers.html](http://0pointer.net/blog/projects/socket-activated-containers.html))
