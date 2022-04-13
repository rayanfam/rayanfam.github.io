---
title: "Simple OpenLDAP + phpLDAPadmin setup"
date: "2017-09-29"
categories: 
  - "linux"
  - "network"
tags: 
  - "debian"
  - "directory-service"
  - "ldap"
  - "openldap"
  - "phpldapadmin"
coverImage: "../../assets/images/php-ldap-admin.png"
author:
  name: Shahriar
  link: https://github.com/Xcess
---

![](../../assets/images/php-ldap-admin.png)

Hello everyone,

In this blog post I'm going to show you how to setup a simple OpenLDAP server  with phpldapadmin on apache. I'm posting this because I didn't find any up to date content on how to do this.

Installing OpenLDAP and exploring it with phpLDAPadmin helps you learn LDAP structure and use cases. Also you can redirect authentication of other devices on your network to this server.

These steps are run in a fresh debian wheezy (7) installation:

\[click on it\]

[![](../../assets/images/asciinema-bind9.png)](https://asciinema.org/a/97546)

LDAP authentication can be used with a lot of services like Apache web authentication, FreeRADIUS, Cisco network devices, etc. which we will go over one by one in future posts.

Any comments are appreciated as always.
