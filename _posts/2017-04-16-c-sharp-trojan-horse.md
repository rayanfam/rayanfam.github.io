---
title: "A simple c# Trojan Horse example"
date: "2017-04-16"
categories: 
  - "programming"
tags: 
  - "net-virus"
  - "c-trojan"
  - "c-virus-source"
  - "trojan-horse-source"
  - "trojan-source"
coverImage: "../../assets/images/trojan_horse.jpg"
author:
  name: Mohammad Sina Karvandi
  link: https://twitter.com/Intel80x86
---

![](../../assets/images/trojan_horse.jpg)

**A simple c# Trojan Horse example**

There were times when I started to learn C# just for creating trojans and this kind of stuffs.

It was 4 years ago when I built this Trojan horse to use it for educational purposes but soon I understood that this kind of trojan horse that is written in such a high level programming languages like C# is not good enough because they are (almost) easily reversible and new Trojan horses should be written using assembly based compilers like C and C++ not C# compilers that build IL (Intermediate Language).

So with new techniques I have learnt in these years I improved my malware knowledge and now I can study malware design and structure written in assembly.

Now I want to share my first trojan horse which works perfectly as I test it right now.

I will share new methods with you in future post !

I never use this trojan for a bad purpose just for some of my friends and we have lots of fun :)

This project is under AVs surveillance as I scanned it on VirusTotal so this post is just for educational purpose.

I changed some code from original virus so that no one can easily use it but if you read it completely you can find how it works and how it is modified.

So don’t use it in bad purposes, it just a sample of how IL viruses work.

In the final version one could use an obfuscater to change the ILs.

How it works?

It actually consists of two processes; one of them is win32.exe which changes registry keys to run in startUp (Which is a bad method nowadays anyway), then it starts winconf.exe and it connects to its server via http and gives the programmer opportunities to run exe on target machines or provides a command line shell from target computers.

For starting win32.exe you should just run winconf.exe. It first checks if another instance of this virus is already available and if it exists, it just closes the process silently else if not, it copies itself to target directory and listens to commands from servers.

If winconf is started from win32 then it just tries to listen.

I made the source code available in the following link, however it has been modified to prevent abuse.

Source Download : [https://github.com/SinaKarvandi/first-trojan-horse](https://github.com/SinaKarvandi/first-trojan-horse)
