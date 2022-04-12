---
title: "Kernel Mode Debugging by Windbg"
date: "2017-03-19"
categories: 
  - "debugging"
  - "kernel-mode"
tags: 
  - "debug-virtual-machine"
  - "debug-windows"
  - "debugging-kernel-mode"
  - "kernel-mode"
  - "vmware-and-windbg"
  - "vmware-debugging"
coverImage: "../../assets/images/kernel-debugging-5.png"
author:
  name: Mohammad Sina Karvandi
  link: https://twitter.com/Intel80x86
---

![](../../assets/images/kernel-debugging-5.png)

Hey there,

Today I'm gonna show you how to make a kernel mode debugging using VMWare and Windbg and Windows.

So why should you do this ?!

It's clear , everything such as Kernel Mode Driver Debugging , searching for zero days and understanding windows mechanism.

There are other types of kernel debugging as described in Windows Internals by Mark Russinovich that I describe in future posts.

So let's start.

First you need a Windbg and as I'm working in a x64 version of Windows so I use AMD64 version of Windbg. If you don't know how to download and install windbg just google it :)

let's get down to business. First Start VMWare and open the OS that you want to debug.

(Please note : in kernel mode debugging all U need is host machine that debugs a target machine)

Then go to edit virtual machine and click to add new hardware.In this time click next and in the new window choose the **"Output to named pipe"** and click next.

![](../../assets/images/kernel-debugging-1.png)

In the new window choose a name for your new serial port.This name will be used in **Windbg**.

![](../../assets/images/kernel-debugging-2.png)

Now start the virtual machine and after starting you should make windows into debugging mode.

There are several ways to do this and have same affects , In this case I started Run (Win Key + R) and go to **msconfig**.

In the msconfig choose **Boot** from tabs and then click on Advanced Option and check Debug checkbox and Debug port and set debug port to your serial port number (In this case COM2).

![](../../assets/images/kernel-debugging-3.png)

Note : It might be different in your computer so please check VMWare hardwares before set it.

After applying the above settings, Windows asks if you want to restart computer for your actions to take place.In this time leave Windows alone and Start **Windbg** based on your operating system CPU.

In Windbg go to File > Kernel Debug...

Now go to COM tab and set your serial port name (From what you choose in VMWare.)

![](../../assets/images/kernel-debugging-4.png)

then click OK and restart the VMWare.

After restarting Windows you should see something like this :

![](../../assets/images/kernel-debugging-5.png)

Then your're done ...

Now you can stop Windbg and see how it works like a charm.

Please remember if you stop Windbg and make breakpoint, the target windows will stop.

After doing this you can debug your Windows in Kernel Mode.
