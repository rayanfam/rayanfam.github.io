---
title: "Hypervisor From Scratch - Part 1: Basic Concepts & Configuring A Test Environment"
date: "2018-08-21"
categories: 
  - "cpu"
  - "hypervisor"
  - "tutorials"
tags: 
  - "hypervisor"
  - "hypervisor-tutorial"
  - "VMX-tutorial"
  - "create-a-virtual-machine"
  - "how-to-create-virtual-machine"
  - "hypervisor-fundamentals"
  - "hypervisor-tutorials"
  - "intel-virtualization"
  - "intel-vmx"
  - "intel-vtx-tutorial"
  - "using-cpu-virtualization"
  - "vmm-implementation"
coverImage: "../../assets/images/hypervisor-from-scratch-1-cover.png"
comments: true
author:
  name: Mohammad Sina Karvandi
  link: https://twitter.com/Intel80x86
---

![](../../assets/images/hypervisor-from-scratch-1-cover.png)


## **Introduction**

Welcome to the first part of a multi-part series of tutorials called "**Hypervisor From Scratch**". As the name implies, this course contains technical details to create a basic Virtual Machine based on hardware virtualization. If you follow this tutorial, you'll be able to create your own virtual environment and understand how VMWare, VirtualBox, KVM, and other virtualization software use processors' facilities to create a virtual environment.

# **Table of Contents**

- **Introduction**
- **Table of Contents**
- **Overview**
- **Hypervisors and Platforms**
- **Installing Tools**
- **Creating A Testing Environment**
- **Creating A Driver**
   - **Disabling The Driver Signature Enforcement (DSE)**
- **Nested-Virtualization**
    - Hyper-V's Nested-Virtualization
    - VMware Workstation's Nested-Virtualization
- **Concepts**
- **VMX Instructions**
- **Related Work**
- **Conclusion**
- **References**

## **Overview**

Both Intel and AMD support virtualization in their modern CPUs. Intel introduced **(VT-x technology)** that was previously codenamed "**Vanderpool**" on November 13, 2005, in Pentium 4 series. The CPU flag for **VT-x** capability is "**VMX**" which stands for **V**irtual **M**achine e**X**tension.

AMD, on the other hand, developed its first generation of virtualization extensions under the codename "**Pacifica**" and initially published them as AMD **Secure Virtual Machine (SVM)**, but later marketed them under the trademark _AMD Virtualization_, abbreviated **_AMD-V_**.

There are two types of hypervisors. The "type 1" hypervisor is called a "bare-metal hypervisor" or "native" because it runs directly on a bare-metal physical server. A type 1 hypervisor has direct access to the hardware. With a type 1 hypervisor, there is no operating system to load as the hypervisor itself has the necessary functions to manage the system boot and startup.

Contrary to a type 1 hypervisor, a type 2 hypervisor loads inside an operating system, just like any other application. Because the type 2 hypervisor has to go through the operating system and is managed by the OS, the type 2 hypervisor (and its virtual machines) will run less efficiently (slower) than type 1 hypervisors.

Even though most of the concepts about the virtualization in Intel and AMD processors are the same, but there are some differences between **Intel VT-x** and **AMD-V**. For example, Intel and AMD use different instruction sets for virtualization.

The rest of these tutorials mainly focus on **VT-x** because Intel CPUs are more popular and widely used.

## **Hypervisors and Platforms** 

These concepts are platform independent, which means you can easily run the same code routine in both Linux or Windows and expect the same behavior from the CPU, but I prefer to use Windows as its more easily debuggable (at least for me.), but I try to give some examples for Linux systems whenever needed. 

Linux kernel manages faults like #GP and other exceptions and tries to avoid the kernel panic and keep the system up; thus, it's better to test something like a hypervisor or any CPU-related programs. In contrast, Windows never tries to manage any unexpected exception and shows a Blue Screen Of Death whenever an unexpected exception occurs; therefore, you might get lots of BSODs while testing your hypervisor. 

At last, I might (and will) make mistakes like wrong implementation or misinformation or forget about mentioning some essential explanations in these series. Because of that, I should say sorry in advance if I make any mistakes, and I'll be glad for every comment that tells me my mistakes in the technical information or misinformation.

That's enough. Let's get started!

## **Installing Tools**

First, we need to install Visual Studio with WDK (Windows Driver Kit).

You can download the community (free) version of the Visual Studio:
[\[https://visualstudio.microsoft.com/vs/community\]](https://visualstudio.microsoft.com/vs/community).

After installing Visual Studio, you can get the WDK from the below link:
[\[https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk\]](https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk).

We'll use **WinDbg** to debug our hypervisor. We can use WinDbg and WinDbg Preview to debug our hypervisor.

WinDbg is available in Windows SDK:

[\[https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/\]](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk).

Afterward, we should connect to debug the Windows kernel using WinDbg. You can read the following links to connect WinDbg to debug the kernel using KDNET.

[Setting Up KDNET Network Kernel Debugging Manually](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-a-network-debugging-connection)
[Setting Up KDNET Network Kernel Debugging Automatically](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-a-network-debugging-connection-automatically)

The next step is downloading **OSR Driver Loader**. We use this tool to load our driver. You can download it using the below link:

[\[https://www.osronline.com/article.cfm?article=157\]](https://www.osronline.com/article.cfm?article=157). 


[SysInternals DebugView](https://docs.microsoft.com/en-us/sysinternals/downloads/debugview) for printing the **DbgPrint()** results.

![Chameleon](../../assets/images/chameleon-1.jpg)

## **Creating A Testing Environment**

Most of the codes in this tutorial have to run at the kernel-level, and we must set up a Linux Kernel Module or a Windows Driver for this purpose.

As configuring a Virtual Machine Monitor (VMM) involves lots of assembly codes, we should be able to embed inline assemblies within our kernel project. 

WDK (and also user-mode applications) no longer support inline assembly in an x64 environment, so we should be able to create a simple x64 project with the support for inline assembly codes.

I explained it step by step in one of my posts, so I highly recommend reading [this topic](https://rayanfam.com/topics/inline-assembly-in-x64) to create a project with inline assembly support before continuing the rest of this part.

Now it's time to create a driver!

## Creating A Driver
There is a good article [here](https://resources.infosecinstitute.com/writing-a-windows-kernel-driver/) if you want to start with Windows Driver Kit (WDK).

```
#include <ntddk.h>
#include <wdf.h>
#include <wdm.h>

extern void inline AssemblyFunc1(void);
extern void inline AssemblyFunc2(void);

VOID DrvUnload(PDRIVER_OBJECT  DriverObject);
NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING  pRegistryPath);

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, Example_Unload)

NTSTATUS DriverEntry(PDRIVER_OBJECT  pDriverObject, PUNICODE_STRING  pRegistryPath)
{
	NTSTATUS NtStatus = STATUS_SUCCESS;
	UINT64 uiIndex = 0;
	PDEVICE_OBJECT pDeviceObject = NULL;
	UNICODE_STRING usDriverName, usDosDeviceName;

	DbgPrint("DriverEntry Called.");

	RtlInitUnicodeString(&usDriverName, L"\\Device\\MyHypervisor");
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\MyHypervisor");

	NtStatus = IoCreateDevice(pDriverObject, 0, &usDriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);

	if (NtStatus == STATUS_SUCCESS)
	{
		pDriverObject->DriverUnload = DrvUnload;
		pDeviceObject->Flags |= IO_TYPE_DEVICE;
		pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
		IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);
	}
	return NtStatus;
}

VOID DrvUnload(PDRIVER_OBJECT  DriverObject)
{
	UNICODE_STRING usDosDeviceName;
	DbgPrint("DrvUnload Called rn");
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\MyHypervisor");
	IoDeleteSymbolicLink(&usDosDeviceName);
	IoDeleteDevice(DriverObject->DeviceObject);
}
```

**AssemblyFunc1** and **AssemblyFunc2** are two external functions defined as inline x64 assembly code.

Our driver needs to register a device so we can communicate with our virtual environment from the user-mode. On the other hand, I defined **DrvUnload**, which uses the PnP Windows driver feature, and we can easily unload our driver and remove the device, then reload and create a new one.

The following code is responsible for creating a new device :

```
	RtlInitUnicodeString(&usDriverName, L"\\Device\\MyHypervisor");
	RtlInitUnicodeString(&usDosDeviceName, L"\\DosDevices\\MyHypervisor");

	NtStatus = IoCreateDevice(pDriverObject, 0, &usDriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);

	if (NtStatus == STATUS_SUCCESS)
	{
		pDriverObject->DriverUnload = DrvUnload;
		pDeviceObject->Flags |= IO_TYPE_DEVICE;
		pDeviceObject->Flags &= (~DO_DEVICE_INITIALIZING);
		IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);
	}
```
### **Disabling The Driver Signature Enforcement (DSE)**
If you use Windows, you should disable Driver Signature Enforcement to load our driver. That's because Microsoft prevents any not verified code from running in Windows Kernel (Ring 0).

To do this, press and hold the shift key and restart your computer. You should see a new window.

1. Click **Advanced options**.
2. On the new Window, Click **Startup Settings**.
3. Click on **Restart**.
4. On the Startup Settings screen, press 7 or F7 to disable driver signature enforcement.

![Disable DSE](../../assets/images/driver-signature-enforcement-boot-menu.png)

The latest thing I remember is enabling Windows Debugging messages through the registry. This way we can get **DbgPrint()** results through **SysInternals DebugView**.

Just perform the following steps:

In the **Regedit**, add a key:

```
HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Debug Print Filter
```

Under that, add a DWORD value named IHVDRIVER with a value of 0xFFFF.

Reboot the machine, and it's good to go.

## **Nested-virtualization**

What if you don't have access to a separate physical machine? 

You can use VMware's (or any other virtualization product) **nested-virtualization**.

### **VMware Workstation's Nested-Virtualization**

In order to set up a nested virtualization environment, make sure to enable the following features in your VM.

![VMWare Nested Virtualization](../../assets/images/nested-virtualization-vmware-2.png)

All the drivers are tested on both physical machines and VMware's nested virtualization.

### **Hyper-V's Nested-Virtualization**

Hyper-V differs from VMWare in many aspects. Therefore you can't test your hypervisor on Hyper-V's nested virtualization. In part 8, I'll describe how to modify your hypervisor in a way that can be used in Hyper-V, so after part 8, you'll be able to test your hypervisor on Hyper-V's nested virtualization.

## **Concepts**

We will frequently use some keywords in the rest of these series, and you should know about them (Most of the definitions are derived from **Intel software developer's manual, volume 3C**).

**Virtual Machine Monitor (VMM)**: VMM acts as a host and has full control of the processor(s) and other platform hardware. A VMM is able to retain selective control of processor resources, physical memory, interrupt management, and I/O.

**Guest Software**: Each virtual machine (VM) is a guest software environment.

**VMX Root Operation and VMX Non-root Operation**: A VMM will run in VMX root operation, and guest software will run in VMX non-root operation.

**VMX transitions**: Transitions between VMX root operation and VMX non-root operation.

**VM entries**: Transitions into VMX non-root operation.

**Extended Page Table (EPT)**: A mechanism that uses a second layer for converting the guest's physical address to the host's physical address.

**VM exits**: Transitions from VMX non-root operation to VMX root operation.

**Virtual machine control structure (VMCS)**: is a data structure in memory that exists exactly once per VM (or more precisely, one per virtual CPU) while the VMM manages it. With every change in the execution context between different VMs, the VMCS is restored for the current VM, defining the state of the VM's virtual processor and VMM control Guest software using VMCS.

The VMCS consists of six logical groups:

-  Guest-state area: Processor state saved into the guest state area on VM exits and loaded on VM entries.
-  Host-state area: Processor state loaded from the host state area on VM exits.
-  VM-execution control fields: Fields controlling processor operation in VMX non-root operation.
-  VM-exit control fields: Fields that control VM exits.
-  VM-entry control fields: Fields that control VM entries.
-  VM-exit information fields: Read-only fields to receive information on VM exits describing the cause and the nature of the VM exit.

I found a great work illustrating the VMCS. The PDF version is also available [here](../../assets/files/VMCS.pdf). 

![VMCS](../../assets/images/VMCS-page-layout-1.jpeg)

![VMCS](../../assets/images/VMCS-page-layout-2.jpg)

Don't worry about the fields. I'll explain most of them clearly in the latter parts. Just remember, VMCS Structure varies between different versions of a processor.

## **VMX Instructions** 

VMX introduces the following new instructions.


| Intel Mnemonic |                     Description                    |
|:--------------:|:--------------------------------------------------:|
| INVEPT         | Invalidate Translations Derived from EPT           |
| INVVPID        | Invalidate Translations Based on VPID              |
| VMCALL         | Call to VM Monitor                                 |
| VMCLEAR        | Clear Virtual-Machine Control Structure            |
| VMFUNC         | Invoke VM function                                 |
| VMLAUNCH       | Launch Virtual Machine                             |
| VMRESUME       | Resume Virtual Machine                             |
| VMPTRLD        | Load Pointer to Virtual-Machine Control Structure  |
| VMPTRST        | Store Pointer to Virtual-Machine Control Structure |
| VMREAD         | Read Field from Virtual-Machine Control Structure  |
| VMWRITE        | Write Field to Virtual-Machine Control Structure   |
| VMXOFF         | Leave VMX Operation                                |
| VMXON          | Enter VMX Operation                                |


### **VMM Life Cycle**

![VM Cycle](../../assets/images/vmm-life-cycle.png)

- The following items summarize the life cycle of a VMM and its guest software, as well as the interactions between them:
    - Software enters VMX operation by executing a VMXON instruction.
    - Using VM entries, a VMM can turn guests into VMs (one at a time). The VMM affects a VM entry using instructions VMLAUNCH and VMRESUME; it regains control using VM exits.
    - VM exits transfer control to an entry point specified by the VMM. The VMM can take action appropriate to the cause of the VM exit and then return to the VM using a VM entry.
    - Eventually, the VMM may decide to shut itself down and leave VMX operation. It does so by executing the VMXOFF instruction.

That's enough for now!

## **Related Work**
Other hypervisor-related works and materials.

Awesome virtualization (Introducing books, papers, projects, courses, CVEs, and other hypervisor hypervisor-related works) - [](https://github.com/Wenzel/awesome-virtualization)[https://github.com/Wenzel/awesome-virtualization](https://github.com/Wenzel/awesome-virtualization)

7 Days to Virtualization: A Series on Hypervisor Development - ([https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/](https://revers.engineering/7-days-to-virtualization-a-series-on-hypervisor-development/))

## **Conclusion**
In this part, we study general keywords we should be aware of and create a simple testing environment for our future tests. In the next part, I will explain how to enable VMX on your machine using the driver we made above. Then we survey the rest of the virtualization, so see you in the next part.

The second part is also available [here](https://rayanfam.com/topics/hypervisor-from-scratch-part-2/).

## **References**

\[1\] Intel® 64 and IA-32 architectures software developer's manual combined volumes 3 ([https://software.intel.com/en-us/articles/intel-sdm](https://software.intel.com/en-us/articles/intel-sdm)) 

\[2\] Hardware-assisted Virtualization ([http://www.cs.cmu.edu/~412/lectures/L04\_VTx.pdf](http://www.cs.cmu.edu/~412/lectures/L04_VTx.pdf))

\[3\] Writing Windows Kernel Driver ([https://resources.infosecinstitute.com/writing-a-windows-kernel-driver/](https://resources.infosecinstitute.com/writing-a-windows-kernel-driver/))

\[4\] What Is a Type 1 Hypervisor? ([http://www.virtualizationsoftware.com/type-1-hypervisors/](http://www.virtualizationsoftware.com/type-1-hypervisors/))

\[5\] Intel / AMD CPU Internals ([https://github.com/LordNoteworthy/cpu-internals](https://github.com/LordNoteworthy/cpu-internals))

\[6\] Windows 10: Disable Signed Driver Enforcement ([https://ph.answers.acer.com/app/answers/detail/a\_id/38288/~/windows-10%3A-disable-signed-driver-enforcement](https://ph.answers.acer.com/app/answers/detail/a_id/38288/~/windows-10%3A-disable-signed-driver-enforcement))

\[7\] Instruction Set Mapping » VMX Instructions ([https://docs.oracle.com/cd/E36784\_01/html/E36859/gntbx.html](https://docs.oracle.com/cd/E36784_01/html/E36859/gntbx.html))
