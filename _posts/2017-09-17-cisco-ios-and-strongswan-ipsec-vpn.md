---
title: "Cisco IOS and StrongSWAN IPSEC VPN"
date: "2017-09-17"
categories: 
  - "linux"
  - "network"
  - "sysadmin"
tags: 
  - "cisco"
  - "debian"
  - "ios"
  - "ipsec"
  - "linux"
  - "opensource"
  - "openswan"
  - "strongswan"
  - "tunnel"
  - "vpn"
coverImage: "strongswan-vpn.png"
---

In this blog post we will cover IPSEC tunnel between Linux StrongSWAN and Cisco IOS.

The strongSWAN config file can copied exactly as is to another server with the IP of Cisco Router and the tunnel will be connected between two linux routers. That is you do not need to change right and left in config files. It will be automatically detected from interface IP address (if available of course)

Cisco IOS configuration is very similar to [previous post.](/topics/gre-over-ipsec-in-cisco-ios/)

Here are the configuration files:

### **IOS Configuration:**

 crypto isakmp policy 1
     encr aes
     hash sha256
     authentication pre-share
     group 14
     lifetime 14400
     crypto isakmp key cisco address 20.0.0.2
     crypto ipsec transform-set ts1 esp-aes esp-sha256-hmac

mode tunnel
crypto map cm1 10 ipsec-isakmp

set peer 20.0.0.2
set transform-set ts1
match address 105

interface FastEthernet0/0
      ip address 20.0.0.1 255.0.0.0
      duplex full
      crypto map cm1

interface FastEthernet2/0
      ip address 192.168.5.1 255.255.255.0
      duplex full

ip route 192.168.6.0 255.255.255.0 20.0.0.2

route outside 192.168.6.0 255.255.255.0 20.0.0.2

access-list 105 permit ip 192.168.5.0 0.0.0.255 192.168.6.0 0.0.0.255

### **StrongSWAN configuration:**

**_/etc/ipsec.conf_**

conn site2site
           authby=secret
           esp=aes128-sha256
           ike = aes128-sha256-modp2048
           ikelifetime = 4h
           leftid=20.0.0.2
           rightid=20.0.0.1
           left=20.0.0.2
           leftsubnet=192.168.6.0/24
           right=20.0.0.1
           rightsubnet=192.168.5.0/24
           keyexchange=ikev1
           pfs=no
           auto=start
           remote\_peer\_type=cisco

**_/etc/ipsec.secret_**

 20.0.0.2 20.0.0.1 : PSK cisco

**_/etc/sysctl.conf_**

ip\_forward=1 (uncomment)

# sysctl -p (run command)
