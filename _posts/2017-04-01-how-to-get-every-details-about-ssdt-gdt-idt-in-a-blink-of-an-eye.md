---
title: "How to get every detail about SSDT , GDT , IDT in a blink of an eye"
date: "2017-04-01"
categories: 
  - "debugging"
  - "kernel-mode"
tags: 
  - "gdt"
  - "global-descriptor-table"
  - "idt"
  - "interrupt-descriptor-table"
  - "ssdt"
  - "swishdbgext"
  - "system-service-descriptor-table"
  - "windbg-extension"
coverImage: "../../assets/images/service-descriptor-table.jpg"
author:
  name: Mohammad Sina Karvandi
  link: https://twitter.com/Intel80x86
---

![](../../assets/images/service-descriptor-table.jpg)

In a few days ago I was looking for something to show me the SSDT and GDT (Which is really important in malware analyzing because most of rootkits are interested in hooking and changing this stuffs.)

• SSDT (System Service Descriptor Table) • GDT (Global Descriptor Table) • IDT (Interrupt Descriptor Table)

They're really important table in OSes for example SSDT is something like IAT (Import Address Table) in user-mode applications which holds pointer to exported functions of all .dll assemblies and in this case SSDT holds pointer to native windows APIs.

You can imagine how an attacker can just change or hook them and start and filter your arguments every time you go through this functions. then I found something like :

```
lkd> u dwo(nt!KiServiceTable)+nt!KiServiceTable L1
nt!NtMapUserPhysicalPagesScatter:
fffff800‘013728b0 488bc4 mov rax,rsp
lkd> u dwo(nt!KiServiceTable+4)+nt!KiServiceTable L1
nt!NtWaitForSingleObject:
fffff800‘012b83a0 4c89442418 mov [rsp+0x18],r8
```

Which wasn't what I really wants to, but can somehow help cause as I read in one of the articles about Patchguard bypassing,

It said :

" On Windows x64 kernels, nt!KeServiceDescriptorTable conveys the address of the actual dispatch table and the number of entries in the dispatch table for the native system call interface. In this case, the actual dispatch table is stored as an array of relative offsets in nt!KiServiceTable. "

If you don't know about SSDT and GDT and IDT first google about it then I want to show an amazing tools which called SwishDbgExt and it's open source and free !

available at : [https://github.com/comaeio/SwishDbgExt](https://github.com/comaeio/SwishDbgExt)

it helps me a lot ! After compiling it from source you need to load dll like :

```
!load C:\\users\\sina\\desktop\\SwishDbgExt.dll
```

and then just use !ms\_ssdt , and !ms\_gdt and !ms\_idt in Windbg to get a complete list of information about following tables.

Note : Windows kernel also uses Patchguard to protect its kernel from such changes but its just security over obscurity because Kernel Drivers run in a privilege same as kernel and there are tons of article about how to bypass Patchguard and there is nothing like this protection in x86 systems because they don't have such thing like patchguard (But I don't know precisely if windows has any special mechanism to protect these tables in x86 machines.).

So that's it guys. There are lots of good things you can find in this Windbg extension that you can find in readme or in github page and it really worths to test.
