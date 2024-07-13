---
title: "Change User-Mode application's virtual address through Kernel Debugging"
date: "2017-04-02"
categories: 
  - "debugging"
  - "kernel-mode"
  - "user-mode"
tags: 
  - "change-process-from-kernel"
  - "change-virtual-address"
  - "kernel-mode-to-user-mode"
  - "ring0-to-ring3"
coverImage: "../../assets/images/kernelmode-usermode.jpg"
comments: true
author:
  name: Sina Karvandi
  link: https://twitter.com/Intel80x86
---

![](../../assets/images/kernelmode-usermode.jpg)

Well, it's somehow an odd topic but sometimes it could be really helpful in some situations.

So what are the situations?

Imagine sometimes you need to access windows stuffs that aren't available from user-mode debuggers like ollydbg or through user-mode debugging (e.g memory after 0x7fffffff). In my experience I see some conditions that protectors make a sophisticated check for finding any debugger in memory and then change their approach to stop reverser from reversing the rest of the code. In such a situation you can make a virtual environment then break the machine completely and change your context to process and continue analyzing image. In this case you can overcome protection levels completely or at least overcome some protection levels. (some protectors never allow to run from a Virtual Machine or call some windows APIs to see if a kernel debugger is present or not and you should check for this stuffs first then continue debugging.)

So let's get down to business,

In the following tutorial I use a VMware Virtual Machine that is ready for kernel debugging (if you don't know how to make one pls see [this link](/topics/kernel-mode-debugging-by-windbg/) ,it describes how to do it). Then a kernel debugger (in my case Windbg) and a user-mode debugger (ollydbg).

First run myfile.exe in guest machine and attach to it from guest machine by ollydbg to see any editing that made in kernel debugging takes place in myfile.exe then break the Windbg to edit memory from host machine.

So I use the following command to get all the processes to see where you can find myfile.exe :

```
kd> !process 0 0
```

And it gives you a long list of processes where you can finally find myfile.exe.

```
PROCESS ffffe001f9652080
SessionId: 1 Cid: 0da4 Peb: 7ffdf000 ParentCid: 0588
DirBase: 11d6d000 ObjectTable: ffffc0013e905680 HandleCount: <Data Not Accessible>
Image: myfile.exe
```

So for more details about this process you can run :

```
kd> !process ffffe001f9652080 7
```

It should give you something like :

```
1: kd> !process ffffe001f9652080 7
PROCESS ffffe001f9652080
SessionId: 1 Cid: 0da4 Peb: 7ffdf000 ParentCid: 0588
DirBase: 11d6d000 ObjectTable: ffffc0013e905680 HandleCount: <Data Not Accessible>
Image: myfile.exe
VadRoot ffffe001f64dda10 Vads 129 Clone 0 Private 5676. Modified 520. Locked 0.
DeviceMap ffffc0013dff8c30
Token ffffc0014336a8e0
ElapsedTime 00:08:14.197
UserTime 00:00:00.046
KernelTime 00:00:00.125
...
```

then for switch to myfile.exe you should run :

```
kd> .process /p /r ffffe001f9652080
Implicit process is now ffffe001f9652080
.cache forcedecodeuser done
Loading User Symbols
.....................
```

Now you're almost done ! you are in a 32 bit enviroment for myfile.exe which you can run all Windbg commands like what you run in Virtual Address (Instead of physical address.)

For a sample run :

```
kd> dc 400000
```

It gives you all the memory in myfile.exe's base address (0x400000) which you can edit memory by something like ea command in windbg and see what's going on after pressing g and then go to Guest Machine where you can find myfile.exe's base address from ollydbg and see how it changed form kernel debugger.

Thanks for reading
