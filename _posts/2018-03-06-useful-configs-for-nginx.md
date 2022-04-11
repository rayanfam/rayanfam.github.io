---
title: "Useful Configs for NGINX"
date: "2018-03-06"
categories: 
  - "linux"
  - "network"
  - "sysadmin"
tags: 
  - "cache"
  - "debian"
  - "https"
  - "linux"
  - "loadbalance"
  - "nginx"
  - "opensource"
  - "php-fpm"
  - "proxy"
  - "webserver"
coverImage: "NGINX.png"
---

After posting the first of my _linux SysAdmin quick config sample series_ titled "Useful Configs for squid" (which you can read [here](https://rayanfam.com/topics/useful-config-squid3/)). I decided to write another post, this time about the powerful and popular web/cache server **NGINX**!

I spent quite some time reading through nginx official docs and other blogs/websites while testing each configuration directive in different scenarios. Some of the options presented in this post do not have good or any documentation. I hope you find them useful!

_\*\*\* snippets are tested on nginx on Debian 8 (jessie) but they will work on other distros/OSs with minimal or no modification._

_Disclaimer: These configuration files are meant to be small and simple and designed to help you get an idea of what is possible with NGINX or quickly test some of its capabilities in a lab environment. although they probably work but they may be far from complete at times. So It's up to you to research further if you want to leverage nginx in production._

* * *

### Connecting to PHP:

Probably the first thing you want to do after installing nginx is to connect it to some php interpreter to be able to run your web application.

- Install PHP (on debian : `apt install php5 php5-fpm`)
- change NGINX config file like this (essentially only uncomment the relevant section):

         
location ~ \\.php$ {
     include snippets/fastcgi-php.conf;

     # With php5-cgi alone:
     #fastcgi\_pass 127.0.0.1:9000;
     # With php5-fpm:
     fastcgi\_pass unix:/var/run/php5-fpm.sock;
}

- add _index.php_ to index line
- verify socket properties in _/etc/php5/fpm/pools.d/www.conf_
    - socket permissions and user must be correct (they are correct in a default Debian Jessie install)

### Redirect HTTP to HTTPS:

There any many ways to accomplish this. Some websites advocate the use of _if__($scheme ..._ but **THIS IS WRONG**. it causes performance issues and also _if_ in nginx behaves differently and you might get unexpected results. The correct way to do this is presented below, **no _rewrite, if , etc_ are needed** [this](https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls/#taxing-rewrites)(see ):

location / {
    return 301 https://$server\_name$request\_uri;
}

\*\*\* Note that since we are doing a **permanent redirect (301)**, it will be cached by browsers so it will be a one time thing and they will connect to https port by default in subsequent visits.

 

### **Nginx Reverse Proxy:**

Reverse proxy is a very popular and useful feature of nginx. It's important that you completely understand how it works and how to use it effectively. _a large number of websites and services are based on nginx reverse proxy like Netflix, CloudFlare CDN and many more!_

basic reverse proxy:

server {
    listen 80;
    server\_name rayanfam.com;
    location / {
        proxy\_pass http://<IP of other web server>/\[path of real website if not hosted on root\];
    }
}

This feature is usually utilized minimally like this:

server {
    listen 80;
    server\_name www.rayanfam.com devel.rayanfam.com rayanfam.com;

    location / {
        proxy\_pass http://222.222.222.222:8080;
        proxy\_set\_header Host $host;
        proxy\_set\_header X-Real-IP $remote\_addr;
        proxy\_set\_header X-Forwarded-For $proxy\_add\_x\_forwarded\_for;
        proxy\_set\_header X-Forwarded-Proto $scheme;
    }
}

I suggest you read [official docs](https://docs.nginx.com/nginx/admin-guide/web-server/reverse-proxy/) on this feature at least, there are many good articles on reverse proxying with nginx on other websites too.

### Forward Proxy:

This is not a very used feature but for the sake of completeness and also because it is not available on other websites I will show you how to configure nginx as a forward proxy for your organization. It will do the job very well!

server {
	listen 80;
	server\_name \_;
	location / {
		resolver 8.8.8.8;
		proxy\_pass http://$http\_host$uri$is\_args$args;
	}
}

_\*\*\* Do not host this on a public facing IP!_

### IP-based Block:

You may want to deny or allow access only from a specific ip range. you can achieve this with iptables, but this is an acceptable way too:

location / {
    allow 192.168.20.0/24;
    deny all;
    #... other directives
}

### Custom Error Pages:

You can easily customize your error page using nginx and setup fancy error pages for all types of error ([GitHub](https://github.com/login_404) is my favorite ^\_^ ):

#Both are mandatory. error paged should be marked as internal

error\_page 403 /forbidden.html;

location /forbidden.html {
    internal;
}

### Log format and Destination:

Changing the log format and log destination is trivial in nginx. I create a new access log format and then use it to log to syslog facility.

#creating log format
log\_format mylogformat ‘$remote\_addr $request’

#log to a file using mylogformat
access\_log /var/log/nginx/custom\_access.log mylogformat;

#log to syslog server using mylogformat
access\_log syslog:server=192.168.10.10 mylogformat;

_you can view official nginx docs regarding field names for logs and support for [syslog](https://nginx.org/en/docs/syslog.html), etc._

### Basic Caching with Nginx:

This snippet is intended to give you a very rough idea of caching with nginx and the minimal configuration required to activate that. In a real server more sophisticated caching will probably be required but this will get you started on this topic.

_\*\*\* Caching is one of the most advanced  features of nginx, make sure to study and understand it._

#First create the directory and set the required permissions#

proxy\_cache\_path /var/cache/nginx keys\_zone=CACHE:10m;

server {
    proxy\_cache CACHE;
    # ... other directives
}

### HTTP Basic Authentication:

It's the simplest form of authentication you can have for your website or a single page. yet it is effective and secure (if your password is only known by you of course). **BE CAREFUL** **not to put your password file in your web directory!** (yes I've seen people do that)

run this command in your shell. It's not part of nginx config:
$ htpasswd -c /etc/nginx/.htpasswd shahriar

# nginx config → add in desired location block

    auth\_basic "Private Content"; 
    auth\_basic\_user\_file /etc/nginx/.htpasswd;

* * *

some links:

[Official docs](https://nginx.org/en/docs/)

[Common config pitfalls (official docs)](https://www.nginx.com/resources/wiki/start/topics/tutorials/config_pitfalls)

* * *

I hope you found this blog post useful... spread the word and tell your friends! also do not hesitate to comment. Have fun sysadmin-ing!
