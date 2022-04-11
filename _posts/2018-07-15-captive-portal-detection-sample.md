---
title: "Captive portal detection with a working sample in all major OSs!"
date: "2018-07-15"
categories: 
  - "linux"
  - "network"
  - "sysadmin"
tags: 
  - "captive"
  - "captive-portal"
  - "covachilli"
  - "http"
  - "iptables"
  - "linux"
  - "network"
  - "nodogsplash"
  - "openwrt"
  - "router"
  - "uhttpd"
  - "wifidog"
coverImage: "openwrt-1.png"
author:
  name: Shahriar
  link: https://github.com/Xcess
---

Hi everyone  
I've been working on a project which involves a developing a captive portal system from scratch. and I'm going to gradually post more of challenges we faced and the way we solved them too.

But for now I'm going to talk about captive portal detection in different OSs and how we've implemented it. It is not a really difficult or lengthy concept but the sad thing is that it's not very well documented or not even documented at all!

Before beginning, I should note that there indeed are standard for captive portals detection and login, such as [**WISPr**](https://en.wikipedia.org/wiki/WISPr) but they are not widely used as I know and they are mostly for embedded devices which do not have a browser to open login page and should be logged in automatically. We won't have anything to do with WISPr protocol here.

_This setup is tested with Fedora and Ubuntu, Windows 10, Windows 8.1 and android._

In order to find out whether there is a captive portal at work, the OS (or browser) should go through several steps; Firstly it should find out if internet is indeed connected or not (not disconnected completely), then it will find out that although connected to the internet, this device has limited connectivity (**only DNS packets are transmitted and received**). These two steps are enough for the OS to determine that it has some connection that is limited by the administrator, in some OSs this two steps are enough to detect captive portal. So making sure that only DNS packets are allowed would be enough. Firefox browser is like this and will show a bar indicating that you need to login to this network.

The third step is necessary for other OSs especially Windows; **all HTTP requests going out of the network should be responded with a 302 redirect.**

So it boils down to this:

1. Only allowing DNS packets out of the network.
2. Redirecting all HTTP requests with 302 (to the login page, but the page is not important in detection)

* * *

## Implementation on OpenWRT:

I will explain the steps necessary for detection in OpenWRT, using iptables and uhttpd, the default webserver on OpenWRT.

### IPTables:

This is really easy. Here are the rules:

#start iptables for captive portal

/usr/sbin/iptables -t filter -I FORWARD 1 --protocol tcp --sport 53 --jump ACCEPT
/usr/sbin/iptables -t filter -I FORWARD 1 --protocol udp --sport 53 --jump ACCEPT
/usr/sbin/iptables -t filter -I FORWARD 1 --protocol tcp --dport 53 --jump ACCEPT
/usr/sbin/iptables -t filter -I FORWARD 1 --protocol udp --dport 53 --jump ACCEPT
/usr/sbin/iptables -t filter -I FORWARD 5 -j DROP
/usr/sbin/iptables -t nat -A prerouting\_lan\_rule --protocol tcp --dport 80 --jump DNAT --to-destination $(uci get network.lan.ipaddr):80

#the line above does this, but you don't need to specify the ip manually
#/usr/sbin/iptables -t nat -A prerouting\_lan\_rule --protocol tcp --dport 80 --jump DNAT --to-destination 192.168.100.1:80

1. The first four rules accept all packets with source or destination port of 53 (domain name system)
2. The 5th rule denies all other connections
3. the last rule redirects all web requests to our http server running on router on port 80.

- _These rules work on OpenWRT, in order for them to work on other linuxes, you probably need to replace **prerouting\_lan\_rule** with **PREROUTING.**_
- It is a very good idea to rate limit DNS packets per ip using **hashlimit** iptables module, As this setup has no defense against **DNS tunnels** and covert channels, effectively bypassing all restrictions.
- There sure are better ways to do this (such as only allowing outbound dport 53 and permitting established connections back, etc), but this guide focuses only on captive portal detection.

### HTTP Redirect:

_The webserver is only needed for redirect, so it can be a separate light webserver running on another port too (like 8000), you change DNAT port in iptables only. So this can be a very basic webserver._

Configuring a redirect is pretty straightforward for every webserver you are using, But there wasn't any documentation for uhttpd :/ , so I will explain redirect in uhttpd based on my experiments now.

You should change **/e_tc__/uhttpd/redir.json_** _like this:_

{
	"fallback": \[
		\[ "if", \[ "regex", "REQUEST\_URI", \[ "/\*" \] \],
			\[ "rewrite", "/" \]
		\]
	\]
}

It is a **fallback** redirect, so it will only kick in if the url does not exist. So it will not interfere with other things you will be doing on the webserver.

* * *

If you have done these steps and the three requirements are satisfied, a browser will automatically open when you connect to the network with a windows system. If you happen to accidentally close that page, just open a HTTP website (or the official one [http://msftconnecttest.com/redirect](http://msftconnecttest.com/redirect) ) to reach the login again.

* * *

Here are some links for further reading:

[https://en.wikipedia.org/wiki/Captive\_portal](https://en.wikipedia.org/wiki/Captive_portal)

[https://www.secplicity.org/2016/08/26/lessons-defcon-2016-bypassing-captive-portals/](https://www.secplicity.org/2016/08/26/lessons-defcon-2016-bypassing-captive-portals/)

Have fun (!) with captive portals :)
