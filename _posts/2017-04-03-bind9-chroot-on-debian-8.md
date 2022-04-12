---
title: "Bind9 chroot on debian 8"
date: "2017-04-03"
categories: 
  - "linux"
  - "network"
  - "software"
  - "sysadmin"
tags: 
  - "bind9-config"
  - "bind9-on-debian"
coverImage: "../../assets/images/debian-logo.jpg"
author:
  name: Shahriar
  link: https://github.com/Xcess
---

![](../../assets/images/debian-logo.jpg)

From Wikipedia:

> **BIND**, or **named**, is the most widely used [Domain Name System](https://en.m.wikipedia.org/wiki/Domain_Name_System "Domain Name System") (DNS) software on the Internet. On [Unix-like](https://en.m.wikipedia.org/wiki/Unix-like "Unix-like") operating systems it is the [_de facto_ standard](https://en.m.wikipedia.org/wiki/De_facto_standard "De facto standard").

As you know chrooting a process is very beneficial for security as any compromise cannot have effect on the whole system. But be aware escaping from chroot is not impossible. and therefore should not be used as your only security measure on a production DNS resolver.

Chrooting Bind is simple, however there are not good HOWTOs, the good ones are all outdated.

So I made this Asciinema for "chrooting bind 9 in debian 8" (systemd)

\[click on it\]

[![](../../assets/images/mknod-terminal.png)](https://asciinema.org/a/98472)

Let me know of any inaccuracies or suggestions as usual :)

Shahriar

- **UPDATE :** Thanks to Behrad Eslamifar for letting me know, This debian 8 package will also do the job if you don't want to do it manually:   [https://github.com/cvak/bind-chroot](https://github.com/cvak/bind-chroot)
