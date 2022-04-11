---
title: "Getting started with Windows Server command line"
date: "2017-11-10"
categories: 
  - "network"
  - "sysadmin"
  - "windows"
tags: 
  - "active-directory"
  - "cmd"
  - "network"
  - "powershell"
  - "server-core"
  - "windows"
  - "windows-server"
  - "windows-server-2012-r2"
  - "windows-server-core"
coverImage: "../../assets/images/cmd-1024x579.jpg"
author:
  name: Shahriar
  link: https://github.com/Xcess
---

![](../../assets/images/cmd-1024x579.jpg)

Hello everyone, In this post I am going to introduce some basic commands that are used to configure Windows Server. Of course if you are using Windows Server with GUI, you may not need these command at all (except for automation maybe). However if you work in an environment in which you configure windows network on a regular basis, you need to know some basic stuff B)

OK, Imagine you have installed **Windows Server Core 2012 R2** on a server and now want to set basic configuration of your server (It's highly possible that other versions of windows are configured exactly the same (like even windows 7 etc), _but It is not tested by me)_:

#### Network:

#ip address
netsh interface ipv4 address name="Local Area Network" source=static address=192.168.1.10 mask=255.255.255.0 gateway=192.168.1.1

#dns server
netsh interface ipv4 add dnsserver name="Local Area Connection" address=8.8.8.8

#### Hostname:

#view hostname (output of this command shows hostname)
hostname

#change hostname
netdom renamecomputer WINSRV1 /NewName:WINSRV2

(you should reboot after setting hostname)

#### reboot:

shutdown /r /t 0

okay, now we want to join this computer to a domain:

#### Joining to a domain:

netdom join WINSRV2 /domain:lab.local /Userd:Administrator /password:Ab123456@

(you should reboot after joining to domain)

#### Installing a Role:

well, windows server is of no use without any roles installed. So as an example we will install Internet Information Services (IIS):

#the first method uses pkgmgr and is kinda obsolete. but if it works and is supported on your platform then no need to change... :)
start /w pkgmgr /l:log.etw /u:IIS-WebServerRole;WAS-WindowsActivationService;WAS-ProcessModel;WAS-NetFxEnvironment;WAS-ConfigurationAPI

#the second command uses powershell cmdlets and is newer and will be supported in future versions of windows (probably even as the main method of interacting with windows server)
import-module servermanager
add-windowsfeature web-server -includeallsubfeature

#### Enable PowerShell Remoting:

PowerShell remoting enables you to run powershell command over the network on other computer. I know many powershell or cmd command for management have -ComputerName or similar argument for specifying the destination computer, but most of them work over non-standard ports and each of them may use a different microsoft remote managemnt facility. Furthermore you may run into strange permission or other problems. So it won't result in a smooth remote exprience.

To enable PS Remoting run this command

_(it can be enabled with Group Policy if you have a lot of systems to manage remotely)_:

Enable-PSRemoting –Force

then connect to them like this:

Enter-PSSession –Computername
#specifying credentials be like:
Enter-PSSession –Computername "WINSRV2" –Credential "LAB\\administrator"

or if you want to run a command of multiple machines in parallel:

Invoke-Command –name WINSRV1, WINSRV2, PC3 –ScriptBlock {Get-Process}

* * *

That is the end of this post! Please feel free to comment below.

Thanks
