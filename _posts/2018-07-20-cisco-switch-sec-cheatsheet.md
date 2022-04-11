---
title: "Cisco switch security features cheatsheet"
date: "2018-07-20"
categories: 
  - "cisco"
  - "network"
  - "security"
tags: 
  - "cisco"
  - "defense"
  - "ios"
  - "port"
  - "port-security"
  - "security"
  - "switch"
  - "switchport"
coverImage: "Cisco-SF100-24-NA-AN-1.jpg"
author:
  name: Shahriar
  link: https://github.com/Xcess
---

Cisco switches (running IOS) have plenty of features that are critical to modern networks. Some are Cisco security features that eliminate several important attack vectors on layer 2. This is arguably the most important defense mechanism because ACLs and security mechanisms on software (layer 7) will sometimes fall short protecting the network because of the extreme complexity of communication up in this layer. So the earlier you close the holes the better!

As an example security features like _protected ports_ can effectively harden lateral movement in windows networks (Active Directory domains), also while being so dead simple compared to more advanced methods implemented on top of active directory itself.

In this post I will give you the commands needed to implement some security features in a Cisco switch in a **cheetsheet** like manner.

It is important to fully understand what each feature will do, as failing to do so and running the commands blindly may cause disruption in your network. Just look up each one and read about it. :)

_Reading official Cisco CCNP books is super recommended!_

### Port Security

int INTERFACE
	switchport mode access
	switchport access vlan 123 

	#port security configuration starts here:
	switchport port-security maximum # 
	switchport port-security aging type inactive 
	switchport port-security aging time 5 
	switchport port-security violation restrict 
	switchport port-security mac-address MAC 
	switchport port-security mac-address sticky

These two commands show you port-security stats and make troubleshooting easier:

show port-sec address
show port-sec interface INTERFACE

### DHCP Snooping

#(conf)
	ip dhcp snooping
	ip dhcp snooping vlan #

interface INTERFACE
	ip dhcp snooping trust 

int USER-INTERFACE 
	ip dhcp snooping limit rate #(pps)

Related show command:

show ip dhcp snooping

### Dynamic ARP Inspection

ip arp inspection 
ip arp inspection vlan 123

interface INTERFACE 
	ip arp inspection trust
	
interface USER-INTERFACE 
	ip arp inspection limit rate #(pps)

Related show command:

show ip arp inspection vlan 123

### IP Source Guard

- _**It requires DHCP snooping (or static ip/mac bindings)**_

_Port based:_

interface INTERFACE
ip verify source(ip) port-security(mac)

_Creating manual entries:_

ip source binding MAC vlan # IP\_ADDRESS interface INTERFACE

Related show command:

show ip source binding

### Protected ports

_Ports that cannot communicate with each other directly._

##private vlan edge aka protected ports : no direct traffic between those ports##

interface INTERFACE
switchport protected

### Spanning Tress root guard

int INTERFACE
	spanning-tree guard root   superior bpdu

### STP BPDU Guard:

- _**with Spanning tree port-fast**_

spanning-tree bpduguard enable

### Storm Control

interface INTERFACE
	#(do not clip anymore – all specified traffic is dropped until end of duration \[1s\])
	storm-conftrol broadcast level (bbp | pps | %) # #
	show storm-control b|m|u
	storm-control action ACTION

* * *

I hope you like this post.

_I am looking forward to improving this post using your contributions in a wiki-like manner. so if you think of any other feature which would be nice to be included in this post, please comment or email me and I will add it here. Thanks :)_
