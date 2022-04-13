---
title: "Useful Configs for Squid3 Cache"
date: "2017-03-21"
categories: 
  - "linux"
  - "network"
  - "software"
  - "sysadmin"
tags: 
  - "cache"
  - "debian"
  - "linux"
  - "proxy"
  - "squid"
  - "squid3"
coverImage: "../../assets/images/squid-proxy-logo.png"
comments: true
author:
  name: Shahriar
  link: https://github.com/Xcess
---

![](../../assets/images/squid-proxy-logo.png)

Hi everyone!

After searching the web so many times and testing different configurations of Squid, I have found these minimal working configs which you can use to achieve the features you want from Squid3 Cache (which is really robust and powerful btw)

Read more for config...

_"shutdown\_lifetime 3" added for quicker restart of squid service, It's not really important._

**Basic caching forward proxy:**

```
http_port 3128
cache_dir ufs /var/spool/squid3 100 16 256
acl MYNET src 192.168.200.0/24
http_access allow MYNET
shutdown_lifetime 3
```

 

**Transparent caching forward proxy:**

```
http_port 3128 transparent
cache_dir ufs /var/spool/squid3 100 16 256
acl MYNET src 192.168.200.0/24
http_access allow MYNET
shutdown_lifetime 3
```

**\*You will also need to forward port to squid!\*** `iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 3128`

_Note that using forward proxy compared to transparent proxying has better performance and is a better solution in general for reasons which are outside the scope of this How-To. So try to use it if you can and then use a proxy config script or Active Directory (if in a domain environment) to make users' browsers use your proxy._

 

**Caching forward proxy with basic file authentication:**

```
http_port 3128
cache_dir ufs /var/spool/squid3 100 16 256
auth_param basic program /usr/lib/squid3/basic_ncsa_auth
/etc/squid3/passwords
auth_param basic realm proxy
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
```

_Authentication is not available with transparent proxy (obviously...duh)_

 

**Caching forward proxy with LDAP authentication:**

```
http_port 3128
cache_dir ufs /var/spool/squid3 100 16 256
auth_param basic program /usr/lib/squid3/basic_ldap_auth -v 3 -b
"dc=rio,dc=local" -f uid=%s 192.168.100.10
auth_param basic realm proxy
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
```

_This LDAP config can't be used with Active Directory. That's because unlike openldap (default config), AD DS doesn't allow a user to bind to its ldap database without presenting a valid user (Binding DN). If you want to use this config with AD DS or a securely and properly configured OpenLDAP, you should specify the binding DN in the auth\_param line using "-D" for more info visit [Official Squid Guide on ActiveDirectory](http://wiki.squid-cache.org/ConfigExamples/Authenticate/WindowsActiveDirectory) (which has way more than necessary info and may be a little confusing, just use the syntax from the last part of the guide, I hope it works!)_

 

**Caching forward proxy with PAM authentication:**

```
http_port 3128
cache_dir ufs /var/spool/squid3 100 16 256
auth_param basic program /usr/lib/squid3/basic_pam_auth
auth_param basic realm proxy
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
shutdown_lifetime 3
```

_Basically for authentication with local linux users..._

 

**Caching forward proxy with RADIUS authentication:**

```
http_port 3128
cache_dir ufs /var/spool/squid3 100 16 256
auth_param basic program /usr/lib/squid3/basic_radius_auth -f
/etc/squid3/radius-cred
auth_param basic realm proxy
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
```

**Caching forward proxy with domain filtering and PAM authentication:**

```
http_port 3128
acl toblock dstdomain .block.rio.local
cache_dir ufs /var/spool/squid3 100 16 256
auth_param basic program /usr/lib/squid3/basic_pam_auth
auth_param basic realm proxy
acl authenticated proxy_auth REQUIRED
http_access deny toblock
http_access allow authenticated
shutdown_lifetime 3
```

_You can use all types of access-list in Squid. Which allows for really flexible and powerful access control for your users._

 

Squid3 not only has lots of features but also very good documentation. The main config file is around 6000 lines which only like 15 are not comments! LOL. so you get the idea...

- _Further reading: WCCP, Delay Pools_

Thanks for reading this post. Any advice? please tell me in the comments!
