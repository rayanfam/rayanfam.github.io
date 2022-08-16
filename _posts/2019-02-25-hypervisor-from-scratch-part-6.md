---
title: "Hypervisor From Scratch – Part 6: Virtualizing An Already Running System"
date: "2019-02-25"
categories: 
  - "cpu"
  - "hypervisor"
  - "tutorials"
tags: 
  - "hypervisor"
  - "control-registers-modification"
  - "cpuid-modification"
  - "hypervisor-from-scratch"
  - "hypervisor-logging"
  - "msr-modification-detection"
  - "virtualize-all-logical-cores"
  - "virtualize-current-system"
  - "vmfunc"
  - "vmx-0-settings-and-1-settings"
coverImage: "../../assets/images/hypervisor-from-scratch-6-cover.png"
comments: true
author:
  name: Mohammad Sina Karvandi
  link: https://twitter.com/Intel80x86
---

![](../../assets/images/hypervisor-from-scratch-6-cover.png)

## Introduction

Hello and welcome to the 6th part of the tutorial Hypervisor From Scratch. In this part, I try to explain how to virtualize an already running system using the hypervisor. Like other parts, this part depends on the previous parts, so make sure to read them first.

## Overview

In the 6th part, we'll see how we can virtualize our currently running system by configuring VMCS. We use monitoring features of VMX to detect the execution of important instructions like CPUID (and change the result of CPUID from user-mode and kernel-mode), detect modifications on different control registers, and describe VMX capabilities on different microarchitectures, talking about MSR Bitmaps and lots of other cool things.

Before starting, I should give my special thanks to my friend [Petr Benes](https://twitter.com/PetrBenes) as he always solves my problems, explains to me patiently, and gives me ideas to implement a hypervisor from scratch.

The full source code of this tutorial is available on GitHub :

\[[https://github.com/SinaKarvandi/Hypervisor-From-Scratch](https://github.com/SinaKarvandi/Hypervisor-From-Scratch)\]

**Note:** Please keep in mind that hypervisors change during the time because new features are added to the operating systems or using new technologies. For example, updates to Meltdown & Spectre have made a lot of changes to the hypervisors, so if you want to use Hypervisor From Scratch in your projects, research, or whatever, you have to use the driver from the latest parts of these tutorial series as this tutorial is actively updated and changes are applied to the newer parts (earlier parts keep untouched) so you might encounter errors and instability problems in the earlier parts thus make sure to use the latest parts in real-world projects.

Please make sure to have your own lab to test your hypervisor. I tested my hypervisor on the 7th generation of Intel processors, so if you use an older processor, it might not support some features on your processor, and without a remote kernel debugger (not the local kernel debugger), you might see your system halting or BSODs without understanding the actual error. By the way, it's time to see our hypervisor.

## Table of contents

- **Introduction**
- **Overview**
- **Table of contents**
- **VMX 0-settings and 1-settings**
- **VMX-Fixed Bits in CR0 and CR4**
- **Capturing the State of the Current Machine**
    - Configuring VMCS Fields
    - Changing IRQL on all Cores
- **Changing the User-mode App**
    - Getting a handle using CreateFile
- **Using VMX Monitoring Features**  
    - CR3-Target Controls  
    - Handling guest CPUID execution
    - Instructions That Cause VM Exits Conditionally
    - Control Registers Modification Detection
    - **MSR Bitmaps**
        - Handling MSRs Read
        - Handling MSRs Write
- **Turning off VMX and Exit from Hypervisor**
- **VM-Exit Handler**
- **Let's Test it!**
    - Virtualizing all the cores
    - Changing CPUID using Hypervisor
    - Detecting MSR Read & Write (MSRBitmap)
- **Conclusion**
- **References**

## VMX 0-settings and 1-settings

In the previous parts, we implemented a function called **AdjustControl**. This is an essential part of each hypervisor as you might want to run your hypervisor on many different processors with different microarchitectures. You should be aware of your processor capabilities to avoid undefined behaviors and VM-Entry errors.

```
ULONG
AdjustControls(ULONG Ctl, ULONG Msr)
{
    MSR MsrValue = {0};

    MsrValue.Content = __readmsr(Msr);
    Ctl &= MsrValue.High; /* bit == 0 in high word ==> must be zero */
    Ctl |= MsrValue.Low;  /* bit == 1 in low word  ==> must be one  */
    return Ctl;
}
```

If you remember from the previous part, we used the above function in 4 situations.

```
    __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));
    __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_CTL2_RDTSCP | CPU_BASED_CTL2_ENABLE_INVPCID | CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS, MSR_IA32_VMX_PROCBASED_CTLS2));

    __vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
    __vmx_vmwrite(VM_EXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE /* | VM_EXIT_ACK_INTR_ON_EXIT */, MSR_IA32_VMX_EXIT_CTLS));
    __vmx_vmwrite(VM_ENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));
```

A brief look at **APPENDIX A -VMX CAPABILITY REPORTING FACILITY** shows the explanation about **RESERVED CONTROLS AND DEFAULT SETTINGS**. In Intel VMX, certain controls are reserved and must be set to a specific value (0 or 1) determined by the processor. The specific value to which a reserved control must be set is its **default setting**. These kinds of settings vary for each processor and microarchitecture, but in general, there are three types of classes :

• **Always-flexible**: These have never been reserved.  
• **Default0**: These are (or have been) reserved with a default setting of 0. 
• **Default1**: They are (or have been) reserved with a default setting of 1.

Now, There are separate capability MSRs for the **pin-based VM-execution controls**, **the primary processor-based VM-execution controls**, **VM-Entry Controls**, **VM-Exit Controls** and **the secondary processor-based VM-execution controls**.

We have these MSRs :

- MSR\_IA32\_VMX\_PROCBASED\_CTLS
- MSR\_IA32\_VMX\_PROCBASED\_CTLS2
- MSR\_IA32\_VMX\_EXIT\_CTLS
- MSR\_IA32\_VMX\_ENTRY\_CTLS
- MSR\_IA32\_VMX\_PINBASED\_CTLS

In all of the above MSRs, bits 31:0 indicate the allowed 0-settings of these controls. VM entry allows control X (bit X) to be 0 if bit X in the MSR is cleared to 0; if bit X in the MSR is set to 1, VM entry fails if control X is 0. Meanwhile, bits 63:32 indicate the allowed 1-settings of these controls. VM entry allows control X to be 1 if bit 32+X in the MSR is set to 1; if bit 32+X in the MSR is cleared to 0, VM entry fails if control X is 1.

Although there are some exceptions, now, you should understand the purpose of **AdjustControls** as it first reads the MSR corresponding to the VM-execution control, then adjusts the 0-settings and 1-settings, and return the final result.

I recommend seeing the result of **AdjustControls** specifically for **MSR\_IA32\_VMX\_PROCBASED\_CTLS** and **MSR\_IA32\_VMX\_PROCBASED\_CTLS2** as you might unintentionally set some of the bits to 1 so, you should have a plan for handling some VM-Exits based on your specific processor.

![](../../assets/images/anime-girl-bloom.jpg)

## VMX-Fixed Bits in CR0 and CR4

For CR0, **IA32\_VMX\_CR0\_FIXED0** MSR (index 486H) and **IA32\_VMX\_CR0\_FIXED1** MSR (index 487H) and for CR4 **IA32\_VMX\_CR4\_FIXED0** MSR (index 488H) and **IA32\_VMX\_CR4\_FIXED1** MSR (index 489H) indicate how bits in CR0 and CR4 may be set in VMX operation. If bit X is 1 in **IA32\_VMX\_CRx\_FIXED0**, then that bit of CRx is fixed to 1 in VMX operation. Similarly, if bit X is 0 in **IA32\_VMX\_CRx\_FIXED1**, then that bit of CRx is fixed to 0 in VMX operation. It is always the case that if bit X is 1 in **IA32\_VMX\_CRx\_FIXEDx**, then that bit is also 1 in **IA32\_VMX\_CRx\_FIXED1**.

## Capturing the State of the Current Machine

In the 5th part, we saw how to configure different VMCS fields and finally execute our instruction (HLT) under the guest state. This part is similar to the last part, with some minor changes in some VMCS attributes. Let's review and see the differences.

The first thing you need to know is that you have to create different stacks for each core as we're going to virtualize all the cores simultaneously. These stacks will be used whenever a VM-Exit occurs.

```
    //
    // Allocate stack for the VM Exit Handler
    //
    UINT64 VmmStackVa                  = ExAllocatePoolWithTag(NonPagedPool, VMM_STACK_SIZE, POOLTAG);
    g_GuestState[ProcessorID].VmmStack = VmmStackVa;

    if (g_GuestState[ProcessorID].VmmStack == NULL)
    {
        DbgPrint("[*] Error in allocating VMM Stack\n");
        return FALSE;
    }
    RtlZeroMemory(g_GuestState[ProcessorID].VmmStack, VMM_STACK_SIZE);

    DbgPrint("[*] VMM Stack for logical processor %d : %llx\n", ProcessorID, g_GuestState[ProcessorID].VmmStack);
```

As you can see from the above code, we use VMM\_Stack for each core separately (defined in **\_VirtualMachineState** structure).

All the other things like Clearing VMCS State, loading VMCS, and executing VMLAUNCH are exactly the same as the previous part, so I don't want to describe them again but see the function responsible for preparing our current core to be virtualized.

```
VOID
VirtualizeCurrentSystem(int ProcessorID, PEPTP EPTP, PVOID GuestStack)
{
    DbgPrint("\n======================== Virtualizing Current System (Logical Core 0x%x) =============================\n", ProcessorID);

    //
    // Clear the VMCS State
    //
    if (!ClearVmcsState(&g_GuestState[ProcessorID]))
    {
        goto ErrorReturn;
    }

    //
    // Load VMCS (Set the Current VMCS)
    //
    if (!LoadVmcs(&g_GuestState[ProcessorID]))
    {
        goto ErrorReturn;
    }

    DbgPrint("[*] Setting up VMCS for current system.\n");
    SetupVmcsAndVirtualizeMachine(&g_GuestState[ProcessorID], EPTP, GuestStack);

    //
    // Change this hook (detect modification of MSRs using RDMSR & WRMSR)
    //
    // DbgPrint("[*] Setting up MSR bitmaps.\n");

    DbgPrint("[*] Executing VMLAUNCH.\n");
    __vmx_vmlaunch();

    //
    // if VMLAUNCH succeeds will never be here!
    //
    ULONG64 ErrorCode = 0;
    __vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
    __vmx_off();
    DbgPrint("[*] VMLAUNCH Error : 0x%llx\n", ErrorCode);
    DbgBreakPoint();

    DbgPrint("\n===================================================================\n");

ReturnWithoutError:

    __vmx_off();
    DbgPrint("[*] VMXOFF Executed Successfully!\n");

    return TRUE;

    //
    // Return With Error
    //
ErrorReturn:
    DbgPrint("[*] Fail to setup VMCS!\n");

    return FALSE;
}
```

From the above code, **Setup\_VMCS\_Virtualizing \_Current\_Machine** is new, so let's see what's inside this function.

### Configuring VMCS Fields

VMCS Fields are nothing new. We should configure these fields to manage the state of the virtualized core.

All the VMCS fields are the same as the last part, except :

```
    DbgPrint("[*] MSR_IA32_VMX_PROCBASED_CTLS : 0x%llx\n", AdjustControls(CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));
    DbgPrint("[*] MSR_IA32_VMX_PROCBASED_CTLS2 : 0x%llx\n", AdjustControls(CPU_BASED_CTL2_RDTSCP | CPU_BASED_CTL2_ENABLE_INVPCID | CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS, MSR_IA32_VMX_PROCBASED_CTLS2));

    __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_ACTIVATE_MSR_BITMAP | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS , MSR_IA32_VMX_PROCBASED_CTLS));
    __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_CTL2_RDTSCP | CPU_BASED_CTL2_ENABLE_INVPCID | CPU_BASED_CTL2_ENABLE_XSAVE_XRSTORS, MSR_IA32_VMX_PROCBASED_CTLS2));
```

For the **CPU\_BASED\_VM\_EXEC\_CONTROL**, we set **CPU\_BASED\_ACTIVATE\_MSR\_BITMAP**; this way, we can enable the MSR BITMAP filter (described later in this part). Setting this field is somehow mandatory. As you might guess, Windows accesses lots of MSRs during a simple kernel execution, so if you don't set this bit, then you'll exit on each MSR access, and of course, your VMX Exit-Handler is called, hence clearing this bit to zero makes the system notably slower.

For the **SECONDARY\_VM\_EXEC\_CONTROL**, we use **CPU\_BASED\_CTL2\_RDTSCP** to enable **RDTSCP**, **CPU\_BASED\_CTL2\_ENABLE\_INVPCID** to enable **INVPCID** and the **CPU\_BASED\_CTL2\_ENABLE\_XSAVE\_XRSTORS** to enable **XSAVE** and **XRSTORS**.

It's because I run the above code in my Windows 10 1809 and see Windows uses INVPCID and XSAVE for its internal use (in the processors that support these features), so if you didn't enable them before virtualizing the core, then it probably leads to error.

Note that **RDTSCP** reads the current value of the processor's time-stamp counter (a 64-bit MSR) into the **EDX:EAX** registers and also reads the value of the **IA32\_TSC\_AUX** MSR (address C0000103H) into the **ECX** register. This instruction adds ordering to RDTSC and makes performance measures more accurate than RDTSC. INVPCID, Invalidates mappings in the translation lookaside buffers (TLBs) and paging-structure caches based on the process-context identifier (PCID), and XSAVE Performs a full or partial save of processor state components to the XSAVE area located at the memory address specified by the destination operand.

Please ensure to review the final value that you put on these fields as your processor might not support all these features, so you have to implement some additional functions or ignore some of them.

Nothing is left in this function except **GuestStack**, which is used as the **GUEST\_RSP**. I'll tell you what to put in this argument later.

```
__vmx_vmwrite(GUEST_RSP, (ULONG64)GuestStack);     //setup guest sp
```

OK, now the problem is from where we can start our hypervisor. I mean, how to save the state of a particular core, then execute VMLAUNCH on it, and then continue the rest of the execution.

For this purpose, I've changed the `DrvCreate` routine, so you must change `CreateFile` from the user-mode application (I will discuss it later). In fact, `DrvCreate` is the function responsible for putting all the cores in the VMX state.

```
NTSTATUS
DrvCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    DbgPrint("[*] DrvCreate Called !\n");

    //
    // *** Start Virtualizing Current System ***
    //

    //
    // Initiating EPTP and VMX
    //
    PEPTP EPTP = InitializeEptp();
    InitializeVmx();

    int LogicalProcessorsCount = KeQueryActiveProcessorCount(0);

    for (size_t i = 0; i < LogicalProcessorsCount; i++)
    {
        // Launching VM for Test (in the all logical processor)
        int ProcessorID = i;

        // Allocating VMM Stack
        AllocateVmmStack(ProcessorID);

        // Allocating MSR Bit
        AllocateMsrBitmap(ProcessorID);

        RunOnProcessor(i, EPTP, VmxSaveState);
        DbgPrint("\n======================================================================================================\n", ProcessorID);
    }

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}
```

Our tiny driver is designed to be used simultaneously in just one core, two, three, and even all the cores. As you can see from the code below, it gets the logical processor count.

```
    int LogicalProcessorsCount = KeQueryActiveProcessorCount(0);
```

You can edit this line to virtualize a certain number of cores or just a specific core, but the above code virtualizes all the cores by default.

### Changing IRQL on all Cores

There is a function called **RunOnProcessor**. This function takes processor ID as its first parameter, initialized EPTP pointer (explained in the 4th part) as the second parameter, and a particular routine called **VMXSaveState** as the third. **RunOnProcessor** set the processor affinity to a special core, then it raises the IRQL to Dispatch Level so the Windows Scheduler can't kick in to change the context; thus, it runs our routine, and when it returns from **VMXSaveState**, the currently running core is virtualized so it can lower the IRQL to what it was before. Now Windows can continue its normal execution while under the hypervisor's governance. IRQL stands for **I**nterrupt **R**e**q**uest **L**evel, a Windows-specific mechanism to manage interrupts or give priority by their level, so raising IRQL means your routine will execute with higher priority than normal Windows codes (PASSIVE LEVEL & APC LEVEL ). For more information, you can visit [here](https://blogs.msdn.microsoft.com/doronh/2010/02/02/what-is-irql/).

```
BOOLEAN
RunOnProcessor(ULONG ProcessorNumber, PEPTP EPTP, PFUNC Routine)
{
    KIRQL OldIrql;

    KeSetSystemAffinityThread((KAFFINITY)(1 << ProcessorNumber));

    OldIrql = KeRaiseIrqlToDpcLevel();

    Routine(ProcessorNumber, EPTP);

    KeLowerIrql(OldIrql);

    KeRevertToUserAffinityThread();

    return TRUE;
}
```

**VMXSaveState** has to save the state and call our already implemented function **VirtualizeCurrentSystem**.

We have to EXTERN this function in our assembly file (VMXState.asm) as all **VMXSaveState** is implemented in assembly.

```
EXTERN VirtualizeCurrentSystem:PROC
```

**VMXSaveState** implemented like this :

```
VmxSaveState PROC

	PUSH RAX
	PUSH RCX
	PUSH RDX
	PUSH RBX
	PUSH RBP
	PUSH RSI
	PUSH RDI
	PUSH R8
	PUSH R9
	PUSH R10
	PUSH R11
	PUSH R12
	PUSH R13
	PUSH R14
	PUSH R15

	SUB RSP, 28h

	; It a x64 FastCall function but as long as the definition of SaveState is the same
	; as VirtualizeCurrentSystem, so we RCX & RDX both have a correct value
	; But VirtualizeCurrentSystem also has a stack, so it's the third argument
	; and according to FastCall, it should be in R8

	MOV R8, RSP

	CALL VirtualizeCurrentSystem

	RET

VmxSaveState ENDP
```

It first saves a backup from all the registers, subtracts the stack because of Shadow Space for fast call functions, and then puts RSP to r8 and calls the **VirtualizeCurrentSystem**. RSP should be moved into the R8 (as I told you for **GuestStack** ) because the x64 fastcall parameter should be passed in this order: RCX, RDX, R8, R9 + Stack. This means that our third argument to this function is current RSP, and this value will be used as GUEST\_RSP in our VMCS fields.

If the above function runs without error, we should never reach to "**ret**" instruction as the state will later continue in another function called "**VMXRestoreState**".

As you can see in the **VirtualizeCurrentSystem** which eventually calls **Setup\_VMCS\_Virtualizing\_Current\_Machine**, the **GUEST\_RIP** is pointing to **VMXRestoreState** so the first function (routine) that executes in current core is **VMXRestoreState**. This function is defined like this :

```
VmxRestoreState PROC

	ADD RSP, 28h
	POP R15
	POP R14
	POP R13
	POP R12
	POP R11
	POP R10
	POP R9
	POP R8
	POP RDI
	POP RSI
	POP RBP
	POP RBX
	POP RDX
	POP RCX
	POP RAX
	
	RET
	
VmxRestoreState ENDP
```

In the above function, first, we remove the Shadow Space and restore the registers state. When we return to **RunOnProcessor**, it's time to lower the IRQL.

This function will be called many times (based on your logical cores count), and eventually, all of your cores are under VMX operation, and now you are in **VMX non-root operation**.

## Changing the User-mode App

Based on the above assumptions, we have to make some trivial changes to our user-mode application so after loading the driver, it can be used to notify kernel-mode code to start and end of loading the hypervisor.

### Getting a handle using CreateFile

After some checks for the vendor and presence of hypervisor, now we have to call **DrvCreate**, and it's through the **CreateFile** user-mode function.

```
    HANDLE Handle = CreateFile("\\\\.\\MyHypervisorDevice",
                               GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ |
                                   FILE_SHARE_WRITE,
                               NULL, /// lpSecurityAttirbutes
                               OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL |
                                   FILE_FLAG_OVERLAPPED,
                               NULL); /// lpTemplateFile

    if (Handle == INVALID_HANDLE_VALUE)
    {
        DWORD ErrNum = GetLastError();
        printf("[*] CreateFile failed : %d\n", ErrNum);
        return 1;
    }
```

**CreateFile** API gives us a handle that can be used in our future functions, but whenever you close the application or call **CloseHandle**, then **DrvClose** is automatically called. **DrvClose** turns off the hypervisor and restores the state to what it was before (not virtualized).

## Using VMX Monitoring Features

After configuring all the above fields, it's time to use the monitoring features using VMX. You'll see how these features are unique in the case of security applications.

### CR3-Target Controls

The VM-execution control fields include a set of 4 CR3-target values and a CR3-target count. If you see the VMCS I presented in the **Setup\_VMCS\_Virtualizing\_ Current\_Machine**, then you can see the following lines :

```
    __vmx_vmwrite(CR3_TARGET_COUNT, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE0, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE1, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE2, 0);
    __vmx_vmwrite(CR3_TARGET_VALUE3, 0);
```

Intel defines CR3-Target Controls as "An execution of MOV to CR3 in VMX non-root operation does not cause a VM exit if its source operand matches one of these values. If the CR3-target count is n, only the first n CR3-target values are considered."

Future processors might extend the Cr3-Target counts; the implementation of using this feature is like this :

```
BOOLEAN
SetTargetControls(UINT64 CR3, UINT64 Index)
{
    //
    // Index starts from 0 , not 1
    //
    if (Index >= 4)
    {
        //
        // Not supported for more than 4 , at least for now :(
        //
        return FALSE;
    }

    UINT64 temp = 0;

    if (CR3 == 0)
    {
        if (g_Cr3TargetCount <= 0)
        {
            //
            // Invalid command as g_Cr3TargetCount cannot be less than zero
            // s
            return FALSE;
        }
        else
        {
            g_Cr3TargetCount -= 1;
            if (Index == 0)
            {
                __vmx_vmwrite(CR3_TARGET_VALUE0, 0);
            }
            if (Index == 1)
            {
                __vmx_vmwrite(CR3_TARGET_VALUE1, 0);
            }
            if (Index == 2)
            {
                __vmx_vmwrite(CR3_TARGET_VALUE2, 0);
            }
            if (Index == 3)
            {
                __vmx_vmwrite(CR3_TARGET_VALUE3, 0);
            }
        }
    }
    else
    {
        if (Index == 0)
        {
            __vmx_vmwrite(CR3_TARGET_VALUE0, CR3);
        }
        if (Index == 1)
        {
            __vmx_vmwrite(CR3_TARGET_VALUE1, CR3);
        }
        if (Index == 2)
        {
            __vmx_vmwrite(CR3_TARGET_VALUE2, CR3);
        }
        if (Index == 3)
        {
            __vmx_vmwrite(CR3_TARGET_VALUE3, CR3);
        }
        g_Cr3TargetCount += 1;
    }

    __vmx_vmwrite(CR3_TARGET_COUNT, g_Cr3TargetCount);
    return TRUE;
}
```

I don't have any good example of how this control might be helpful in a regular Windows as there are thousands of CR3 changes for each process. Still, one of my friends told me that it's used in some special cases in scientific projects to improve the overall performance.

### Handling guest CPUID execution

CPUID is one of the main instructions that cause the VM-Exit. As you know, CPUID is used because it allows the software to discover details of the processor. \[If you want to know additional usage, I saw software use CPUID for flushing the pipeline for processors that don't support instruction like RDTSCP so they can use CPUID + RDTSC and somehow gain a better result.\]

Whenever any software in any privilege level executes a CPUID instruction, your handler is called, and now you can decide whatever you want to show to the software. For example, previously, I published an article "[Defeating malware's Anti-VM techniques (CPUID-Based Instructions)](https://rayanfam.com/topics/defeating-malware-anti-vm-techniques-cpuid-based-instructions/)". This article describes how to configure VMWare in a way that changes the CPUID instruction results so that the malware with anti-vm techniques can't understand that they're executing in a virtualized environment by executing the CPUID. VMWare (and other virtual environments) perform the same mechanism for handling CPUID. In the following example, I just passed the state of registers (state of registered after a VM-exits occurs) to the **HandleCPUID**. This function decides whether the requested CPUID should have a modified result or just execute CPUID and return the original results.

Let's implement our handler,

The default behavior for handling every VM-Exit (caused by execution of CPUID in VMX non-root) is to get the original result by using **\_cpuidex**, which is the intrinsic function for CPUID.

```
    __cpuidex(CpuInfo, (INT32)state->rax, (INT32)state->rcx);
```

So you can see that VMX non-root by itself isn't able to execute a CPUID, and we can execute CPUID in VMX Root Mode and give back the results to the VMX Non-root mode.

We need to check if RAX (CPUID Index) was 1. It's because there is an indicator bit that shows whether the current machine is running under a hypervisor or not. Like many other virtual machines, we set the **HYPERV\_HYPERVISOR\_PRESENT\_BIT** to show that we're running under a hypervisor.

There is a second check about the hypervisor provider. We set it to '**HVFS**' to show that our hypervisor is \[H\]yper\[V\]isor \[F\]rom \[S\]cratch.

```
    //
    // Check if this was CPUID 1h, which is the features request
    //
    if (state->rax == 1)
    {
        //
        // Set the Hypervisor Present-bit in RCX, which Intel and AMD have both
        // reserved for this indication
        //
        CpuInfo[2] |= HYPERV_HYPERVISOR_PRESENT_BIT;
    }

    else if (state->rax == HYPERV_CPUID_INTERFACE)
    {
        //
        // Return our interface identifier
        //
        CpuInfo[0] = 'HVFS'; // [H]yper[V]isor [F]rom [S]cratch
    }
```

Now you can easily add more checks to the above code and customize your CPUID filter, for instance, changing your computer vendor string, etc.

Here is the definition of hypervisor-related constants :

```
#define HYPERV_CPUID_VENDOR_AND_MAX_FUNCTIONS   0x40000000
#define HYPERV_CPUID_INTERFACE                  0x40000001
#define HYPERV_CPUID_VERSION                    0x40000002
#define HYPERV_CPUID_FEATURES                   0x40000003
#define HYPERV_CPUID_ENLIGHTMENT_INFO           0x40000004
#define HYPERV_CPUID_IMPLEMENT_LIMITS           0x40000005
#define HYPERV_HYPERVISOR_PRESENT_BIT           0x80000000
#define HYPERV_CPUID_MIN                        0x40000005
#define HYPERV_CPUID_MAX                        0x4000ffff
```

Finally, we put them into registers so that the guest has a proper result every time our routine is executed.

```
    //
    // Copy the values from the logical processor registers into the VP GPRs
    //
    state->rax = CpuInfo[0];
    state->rbx = CpuInfo[1];
    state->rcx = CpuInfo[2];
    state->rdx = CpuInfo[3];
```

Putting all the above codes together, we have the following function :

```
BOOLEAN
HandleCPUID(PGUEST_REGS state)
{
    INT32 CpuInfo[4];
    ULONG Mode = 0;

    //
    // Check for the magic CPUID sequence, and check that it is coming from
    // Ring 0. Technically we could also check the RIP and see if this falls
    // in the expected function, but we may want to allow a separate "unload"
    // driver or code at some point
    //

    __vmx_vmread(GUEST_CS_SELECTOR, &Mode);
    Mode = Mode & RPL_MASK;

    if ((state->rax == 0x41414141) && (state->rcx == 0x42424242) && Mode == DPL_SYSTEM)
    {
        return TRUE; // Indicates we have to turn off VMX
    }

    //
    // Otherwise, issue the CPUID to the logical processor based on the indexes
    // on the VP's GPRs
    //
    __cpuidex(CpuInfo, (INT32)state->rax, (INT32)state->rcx);

    //
    // Check if this was CPUID 1h, which is the features request
    //
    if (state->rax == 1)
    {
        //
        // Set the Hypervisor Present-bit in RCX, which Intel and AMD have both
        // reserved for this indication
        //
        CpuInfo[2] |= HYPERV_HYPERVISOR_PRESENT_BIT;
    }

    else if (state->rax == HYPERV_CPUID_INTERFACE)
    {
        //
        // Return our interface identifier
        //
        CpuInfo[0] = 'HVFS'; // [H]yper[V]isor [F]rom [S]cratch
    }

    //
    // Copy the values from the logical processor registers into the VP GPRs
    //
    state->rax = CpuInfo[0];
    state->rbx = CpuInfo[1];
    state->rcx = CpuInfo[2];
    state->rdx = CpuInfo[3];

    return FALSE; // Indicates we don't have to turn off VMX
}
```

It's somehow like instruction level hooking for CPUID. Also, you can have the same handling functions for many other important instructions by configuring the primary and secondary processor-based controls. Below is a list of these instructions.

### Instructions That Cause VM Exits Conditionally

Thanks to my friend, [@LordNoteworthy](https://twitter.com/LordNoteworthy), the following list is available.

- Instructions cause VM exits in VMX non-root operation depending on the setting of the VM-execution controls.
    - CLTS
    - ENCLS
    - HLT
    - IN, INS/INSB/INSW/INSD, OUT, OUTS/OUTSB/OUTSW/OUTSD.
    - INVLPG
    - INVPCID
    - LGDT, LIDT, LLDT, LTR, SGDT, SIDT, SLDT, STR
    - LMSW
    - MONITOR
    - MOV from CR3/CR8, MOV to CR0/1/3/4/8
    - MOV DR
    - MWAIT
    - PAUSE
    - RDMSR, WRMSR
    - RDPMC
    - RDRAND, RDSEED
    - RDTSC, RDTSCP
    - RSM
    - VMREAD, VMWRITE
    - WBINVD
    - XRSTORS, XSAVES

### Control Registers Modification Detection

Detecting and Handling Control Registers' modifications is one of the great security features provided by hypervisors. Imagine if someone exploits the Windows Kernel (or any other OSs) and wants to unset one of the control register bits (let's say Write Protected or SMEP); then the hypervisor detects this modification and prevents further execution.

These kinds of features are the reason why using a hypervisor as a security mechanism is better than anything like using separate rings (1, 2).

> Note that SMEP stands for Supervisor Mode Execution Protection. **CR4.SMEP** allows pages to be protected from supervisor-mode instruction fetches. If **CR4.SMEP = 1**, software operating in supervisor mode cannot fetch instructions from linear addresses that are accessible in user mode, and **WP** stands for **W**rite **P**rotect. **CR0.WP** allows pages to be protected from supervisor-mode writes. If **CR0.WP = 0**, supervisor-mode write accesses are allowed to linear addresses with read-only access rights; if **CR0.WP = 1**, they are not (User-mode write accesses are never allowed to linear addresses with read-only access rights, regardless of the value of CR0.WP).

Now it's time to implement our functions.

First, let's read the **GUEST\_CRs** and **EXIT\_QUALIFICATION** of the VMCS.

```
    __vmx_vmread(EXIT_QUALIFICATION , &ExitQualification);
    __vmx_vmread(GUEST_CR0 , &GuestCR0);
    __vmx_vmread(GUEST_CR3 , &GuestCR3);
    __vmx_vmread(GUEST_CR4,  &GuestCR4);
```

As you can see, the following picture shows how we can interpret Exit Qualifications.

Note that **EXIT\_QUALIFCATION** is somehow a general VMCS field that, in some situations like VM-Exits caused by Invalid VMCS Layout, Control Register Modifications, I/O Bitmaps, and other events, gives additional information about the reason for VM-Exit; this is an essential part of managing VM-Exits.

![](../../assets/images/control-register-access.png)

As you can see from the above picture, let's make some variables to describe the situation based on **EXIT\_QUALIFICATION**.
---------------------------------------------------------
```
movcrControlRegister = (ULONG)(ExitQualification & 0x0000000F);
movcrAccessType = (ULONG)((ExitQualification & 0x00000030) >> 4);
movcrOperandType = (ULONG)((ExitQualification & 0x00000040) >> 6);
movcrGeneralPurposeRegister = (ULONG)((ExitQualification & 0x00000F00) >> 8);
```

Whenever a VM-Exit occurs caused by some instructions like **MOV CRx, REG**, we have to manually modify the **CRx** of GUEST VMCS from VMX Root Operation. The following code shows how to change the **GUEST\_CRx** field of VMCS using VMWRITE.
-------------------------------------------
```
 if (movcrAccessType == 0)
 {
 
 /* CRx <-- reg32 */
 
 if (movcrControlRegister == 0)
 x = GUEST_CR0;
 else if (movcrControlRegister == 3)
 x = GUEST_CR3;
 else
 x = GUEST_CR4;
 
 switch (movcrGeneralPurposeRegister)
 {
 
 case 0:  __vmx_vmwrite(x, GuestRegs->rax); break;
 case 1:  __vmx_vmwrite(x, GuestRegs->rcx); break;
 case 2:  __vmx_vmwrite(x, GuestRegs->rdx); break;
 case 3:  __vmx_vmwrite(x, GuestRegs->rbx); break;
 case 4:  __vmx_vmwrite(x, GuestRegs->rsp); break;
 case 5:  __vmx_vmwrite(x, GuestRegs->rbp); break;
 case 6:  __vmx_vmwrite(x, GuestRegs->rsi); break;
 case 7:  __vmx_vmwrite(x, GuestRegs->rdi); break;
 }
 
```

Otherwise, we have to read the **CRx** from our guest VMCS (not host Control Register as it might be different), then put it into the corresponding registers (in registers that we saved when the VM-Exit handler called), then continue with **VMRESUME**. This way, the guest thinks as if it executed the **MOV reg, CRx** successfully.

Putting it all together, we have a function like this :

```
VOID
HandleControlRegisterAccess(PGUEST_REGS GuestState)
{
    ULONG ExitQualification = 0;

    __vmx_vmread(EXIT_QUALIFICATION, &ExitQualification);

    PMOV_CR_QUALIFICATION data = (PMOV_CR_QUALIFICATION)&ExitQualification;

    PULONG64 RegPtr = (PULONG64)&GuestState->rax + data->Fields.Register;

    //
    // Because its RSP and as we didn't save RSP correctly (because of pushes)
    // so we have to make it points to the GUEST_RSP
    //
    if (data->Fields.Register == 4)
    {
        INT64 RSP = 0;
        __vmx_vmread(GUEST_RSP, &RSP);
        *RegPtr = RSP;
    }

    switch (data->Fields.AccessType)
    {
    case TYPE_MOV_TO_CR:
    {
        switch (data->Fields.ControlRegister)
        {
        case 0:
            __vmx_vmwrite(GUEST_CR0, *RegPtr);
            __vmx_vmwrite(CR0_READ_SHADOW, *RegPtr);
            break;
        case 3:

            __vmx_vmwrite(GUEST_CR3, (*RegPtr & ~(1ULL << 63)));
            /*
            if (g_Data->Features.VPID)
                __invvpid(INV_ALL_CONTEXTS, &ctx);
                */
            break;
        case 4:
            __vmx_vmwrite(GUEST_CR4, *RegPtr);
            __vmx_vmwrite(CR4_READ_SHADOW, *RegPtr);
            break;
        default:
            DbgPrint("[*] Unsupported register %d\n", data->Fields.ControlRegister);
            break;
        }
    }
    break;

    case TYPE_MOV_FROM_CR:
    {
        switch (data->Fields.ControlRegister)
        {
        case 0:
            __vmx_vmread(GUEST_CR0, RegPtr);
            break;
        case 3:
            __vmx_vmread(GUEST_CR3, RegPtr);
            break;
        case 4:
            __vmx_vmread(GUEST_CR4, RegPtr);
            break;
        default:
            DbgPrint("[*] Unsupported register %d\n", data->Fields.ControlRegister);
            break;
        }
    }
    break;

    default:
        DbgPrint("[*] Unsupported operation %d\n", data->Fields.AccessType);
        break;
    }
}
```

The reason why implementing functions like **HandleControlRegisterAccess** is mandatory is because processors (even the recent Intel processor) have 1-settings of some processor-based VM-execution controls like CR3-Load Exiting & CR3-Store Existing, so you have to manage these kinds of VM-Exits by yourself, but if your processor can continue without these settings, it's strongly recommended to reduce the amounts of VM-Exits because modern OSs access control registers a lot; thus, it has a significant performance penalty.

### MSR Bitmaps

Everything here is based on whether you set the 28th bit of Primary Processor Based controls or not.

On processors that support the 1-setting of the "**use MSR bitmaps**" VM-execution control, the VM-execution control fields include the 64-bit physical address of four contiguous MSR bitmaps, which are each 1-KByte in size. This field does not exist on processors that do not support the 1-setting of that control.

The definition of MSR bitmap is pretty clear in Intel SDM, so I just copied them from the original manual. After reading them, we'll start to implement them and put them into our hypervisor.

- Read bitmap for low MSRs (located at the MSR-bitmap address). This contains one bit for each MSR address in the range 00000000H to 00001FFFH. The bit determines whether the execution of RDMSR applied to that MSR causes a VM exit.

- Read bitmap for high MSRs (located at the MSR-bitmap address plus 1024). This contains one bit for each MSR address in the range C0000000H toC0001FFFH. The bit determines whether the execution of RDMSR applied to that MSR causes a VM exit.

- Write bitmap for low MSRs (located at the MSR-bitmap address plus 2048). This contains one bit for each MSR address in the range 00000000H to 00001FFFH. The bit determines whether the execution of WRMSR applied to that MSR causes a VM exit.

- Write bitmap for high MSRs (located at the MSR-bitmap address plus 3072). This contains one bit for each MSR address in the range C0000000H toC0001FFFH. The bit determines whether the execution of WRMSR applied to that MSR causes a VM exit.

OK, let's implement the above sentences. If any of the RDMSR or WRMSR caused a VM-Exit, then we have to manually execute RDMSR or WRMSR and set the results into the registers. Because of this, we have a function to manage our RDMSRs like :

#### Handling MSRs Read**

```
VOID
HandleMSRRead(PGUEST_REGS GuestRegs)
{
    MSR msr = {0};

    //
    // RDMSR. The RDMSR instruction causes a VM exit if any of the following are true:
    //
    // The "use MSR bitmaps" VM-execution control is 0.
    // The value of ECX is not in the ranges 00000000H - 00001FFFH and C0000000H - C0001FFFH
    // The value of ECX is in the range 00000000H - 00001FFFH and bit n in read bitmap for low MSRs is 1,
    //   where n is the value of ECX.
    // The value of ECX is in the range C0000000H - C0001FFFH and bit n in read bitmap for high MSRs is 1,
    //   where n is the value of ECX & 00001FFFH.
    //

    /*if (((GuestRegs->rcx <= 0x00001FFF)) || ((0xC0000000 <= GuestRegs->rcx) && (GuestRegs->rcx <= 0xC0001FFF)))
    {*/

    msr.Content = MSRRead((ULONG)GuestRegs->rcx);

    /*}
    else
    {
        msr.Content = 0;
    }*/

    GuestRegs->rax = msr.Low;
    GuestRegs->rdx = msr.High;
}
```

You can see that it just checks for the sanity of MSR and then executes the RDMSR and finally put the results into RAX and RDX (because a non-virtualized RDMSR does the same thing).

#### Handling MSRs Writes

There is another function for handling WRMSR VM-Exits :

```
VOID
HandleMSRWrite(PGUEST_REGS GuestRegs)
{
    MSR msr = {0};

    //
    // Check for the sanity of MSR
    //
    /*if ((GuestRegs->rcx <= 0x00001FFF) || ((0xC0000000 <= GuestRegs->rcx) && (GuestRegs->rcx <= 0xC0001FFF)))
    {*/

    msr.Low  = (ULONG)GuestRegs->rax;
    msr.High = (ULONG)GuestRegs->rdx;
    MSRWrite((ULONG)GuestRegs->rcx, msr.Content);

    /*}*/
}
```

The functionality of the function is simple. By now, you should probably understand that all the hooked RDMSRs and WRMSRs should finally call this function. Still, one thing that is worth experimenting by yourself is to avoid setting **CPU\_BASED\_ACTIVATE\_MSR\_BITMAP** in **CPU\_BASED\_VM\_EXEC\_CONTROL**, you'll see that all of the MSR reads and modifications will cause a VM-Exit with these reasons :

- EXIT\_REASON\_MSR\_READ
- EXIT\_REASON\_MSR\_WRITE

This time, you have to pass everything to the above functions and log these VM-Exits, so you can see what are MSRs that Windows use while running in the hypervisor. As I told you above, Windows executes a vast amount of MSR instructions, so it can make your system much slower than you can bear it.

OK, let's get back to our MSR Bitmap. We need two functions to Set bits of our MSR Bitmap,

```
VOID
SetBit(PVOID Addr, UINT64 Bit, BOOLEAN Set)
{
    PAGED_CODE();

    UINT64 Byte = Bit / 8;
    UINT64 Temp = Bit % 8;
    UINT64 N    = 7 - Temp;

    BYTE * Addr2 = Addr;
    if (Set)
    {
        Addr2[Byte] |= (1 << N);
    }
    else
    {
        Addr2[Byte] &= ~(1 << N);
    }
}
```

The other function is for retrieving a particular bit.

```
VOID
GetBit(PVOID Addr, UINT64 Bit)
{
    UINT64 Byte = 0, K = 0;
    Byte         = Bit / 8;
    K            = 7 - Bit % 8;
    BYTE * Addr2 = Addr;

    return Addr2[Byte] & (1 << K);
}

```

Now it's time to gather everything in one function based on the above descriptions about MSR Bitmaps. The following function first checks for the sanity of MSR; then, it changes the MSR Bitmap of the target logical core (this is why we hold both the Physical Address and the Virtual Address of MSR Bitmap, the physical address for VMCS fields, and the virtual address to ease the modification). If it's a read (**rdmsr**) for low MSRs, then set the corresponding bit in MSRBitmap Virtual Address, if it's a write (**wrmsr**) for the low MSRs then modify the MSRBitmap + 2048 (as noted in Intel manual) and exact the same thing for high MSRs (between 0xC0000000 and 0xC0001FFF) but don't forget the subtraction (0xC0000000) because 0xC000nnnn is not a valid bit :d.

```
BOOLEAN
SetMsrBitmap(ULONG64 Msr, int ProcessID, BOOLEAN ReadDetection, BOOLEAN WriteDetection)
{
    if (!ReadDetection && !WriteDetection)
    {
        //
        // Invalid Command
        //
        return FALSE;
    }

    if (Msr <= 0x00001FFF)
    {
        if (ReadDetection)
        {
            SetBit(g_GuestState[ProcessID].MsrBitmap, Msr, TRUE);
        }
        if (WriteDetection)
        {
            SetBit(g_GuestState[ProcessID].MsrBitmap + 2048, Msr, TRUE);
        }
    }
    else if ((0xC0000000 <= Msr) && (Msr <= 0xC0001FFF))
    {
        if (ReadDetection)
        {
            SetBit(g_GuestState[ProcessID].MsrBitmap + 1024, Msr - 0xC0000000, TRUE);
        }
        if (WriteDetection)
        {
            SetBit(g_GuestState[ProcessID].MsrBitmap + 3072, Msr - 0xC0000000, TRUE);
        }
    }
    else
    {
        return FALSE;
    }
    return TRUE;
}
```

Just one more thing to remember, only the above MSR ranges are currently valid in Intel processors, so even any other RDMSRs and WRMSRs cause a VM-Exit. Still, the sanity check here is mandatory as the guest might send invalid MSRs and cause the whole system to crash (in VMX Root mode) !!!

## Turning off VMX and Exit from Hypervisor

It's time to turn off our hypervisor and restore the processor state to what it was before running the hypervisor.

Like how we enter hypervisor (VMLAUNCH), we have to combine our C functions with Assembly routines to save the state, execute VMXOFF, free all of our previously allocated pools, and finally restore the state.

The VMXOFF part of this routine should be executed in the VMX Root operation. You can't just execute **\_\_vmx\_vmxoff** in one of your driver functions and expect it turns off the hypervisor as Windows and all its drivers are currently running in VMX non-root, so executing any of the VMX instructions is like a VM-Exit with one of the following reasons.

```
EXIT_REASON_VMCLEAR
EXIT_REASON_VMPTRLD
EXIT_REASON_VMPTRST
EXIT_REASON_VMREAD
EXIT_REASON_VMRESUME
EXIT_REASON_VMWRITE
EXIT_REASON_VMXOFF
EXIT_REASON_VMXON
EXIT_REASON_VMLAUNCH
```

For turning off the hypervisor, it's better to use one of our IRP Major functions. In our case, we used **DrvClose** as it always gets notified whenever a handle to our device is closed. If you remember from the above, we create a handle from our device using **CreateFile** (**DrvCreate**), and now it's time to close our handle using **DrvClose**.

```
NTSTATUS
DrvClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
    DbgPrint("[*] DrvClose Called !\n");

    // executing VMXOFF (From CPUID) on every logical processor
    TerminateVmx();

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}
```

Nothing special for the above function, just **Terminate\_VMX()**.

This function is similar to the routine of executing VMLAUNCH, except it runs VMXOFF instead.

```
VOID
TerminateVmx()
{
    DbgPrint("\n[*] Terminating VMX...\n");

    int LogicalProcessorsCount = KeQueryActiveProcessorCount(0);

    for (size_t i = 0; i < LogicalProcessorsCount; i++)
    {
        DbgPrint("\t\t + Terminating VMX on processor %d\n", i);
        RunOnProcessorForTerminateVMX(i);

        //
        // Free the destination memory
        //
        MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[i].VmxonRegion));
        MmFreeContiguousMemory(PhysicalToVirtualAddress(g_GuestState[i].VmcsRegion));
        ExFreePoolWithTag(g_GuestState[i].VmmStack, POOLTAG);
        ExFreePoolWithTag(g_GuestState[i].MsrBitmap, POOLTAG);
    }

    DbgPrint("[*] VMX Operation turned off successfully. \n");
}

```

As you can see, it executes **RunOnProcessorForTerminateVMX** on all the running logical cores and then frees the allocated buffers for **VMXON\_REGION, VMCS\_REGION,** **VMM\_Stack**, and **MSRBitMap** using Mm**FreeContiguousMemory.** (of course, convert physicals to virtuals whenever needed)

Note that you have to modify this function if you virtualized a portion of cores (not all).

In **RunOnProcessorForTerminateVMX**, we must tell our VMX Root Operation about turning off the hypervisor. As I told you, it's because we can't execute any VMX instruction here, and it's pretty clear that VMX Root Operation can prevent us from this operation if there isn't any mechanism for handling this situation.

You can use many ways to tell your VMX Root Operation about VMXOFF, but in our case, I used CPUID.

By now, you definitely know that executing CPUID will cause VM-Exit. Now in our CPUID exit handler routine, we manage that whenever a CPUID with `RAX = 0x41414141` and `RCX = 0x42424242` is executed, then you have to return **true**, and it shows the caller that the hypervisor needs to be off.

```
    if ((state->rax == 0x41414141) && (state->rcx == 0x42424242) && Mode == DPL_SYSTEM)
    {
        return TRUE; // Indicates we have to turn off VMX
    }
```

There is also another check for DPL.

```
    ULONG Mode = 0;
    __vmx_vmread(GUEST_CS_SELECTOR, &Mode);
    Mode = Mode & RPL_MASK;
```

This check makes sure that CPUID with RAX = 0x41414141 and RCX = 0x42424242 is executed in system privilege level (kernel mode), so none of the user-mode applications are able to perform this task.

Even if this check is performed, the absence of this check doesn't mean that user-mode applications can turn off the hypervisor, it's because we didn't change CR3 to target the user-mode process and change the current privilege level to user-mode, so if you want to let user-mode applications be able to perform this task, then you have to consider these cases.

Now our **RunOnProcessorForTerminateVMX** executes CPUID on all of the cores separately.

```
BOOLEAN
RunOnProcessorForTerminateVMX(ULONG ProcessorNumber)
{
    KIRQL OldIrql;
    INT32 CpuInfo[4];

    KeSetSystemAffinityThread((KAFFINITY)(1 << ProcessorNumber));

    OldIrql = KeRaiseIrqlToDpcLevel();

    //
    // Our routine is VMXOFF
    //
    __cpuidex(CpuInfo, 0x41414141, 0x42424242);

    KeLowerIrql(OldIrql);

    KeRevertToUserAffinityThread();

    return TRUE;
}
```

In our **EXIT\_REASON\_CPUID**, we know that if the handler returns true, then we have to turn it off, so you should think about some other things. For example, Windows expects to run **GUEST\_RIP** and **GUEST\_RSP** whenever the VM-exit handler returns; thus, we have to save them in some locations and use them later to restore the Windows state.

Also, we have to increase **GUEST\_RIP** because we want to restore the state after the CPUID.

```
    case EXIT_REASON_CPUID:
    {
        Status = HandleCPUID(GuestRegs); // Detect whether we have to turn off VMX or Not
        if (Status)
        {
            // We have to save GUEST_RIP & GUEST_RSP somewhere to restore them directly

            ULONG ExitInstructionLength = 0;
            g_GuestRIP                  = 0;
            g_GuestRSP                  = 0;
            __vmx_vmread(GUEST_RIP, &g_GuestRIP);
            __vmx_vmread(GUEST_RSP, &g_GuestRSP);
            __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength);

            g_GuestRIP += ExitInstructionLength;
        }
        break;
    }
```

From the 5th part, you probably know **MainVMExitHandler** is called **VMExitHandler** (Assembly function from **VMExitHandler.asm**)

Let's see it in detail.

First, we have to extern some previously defined variables.

```
EXTERN g_GuestRIP:QWORD
EXTERN g_GuestRSP:QWORD
```

Now our **VMExitHandler** works like this, whenever a VM-exit occurs, our logical core executes **VMExitHandler** as it's defined in **HOST\_RIP**, and our **RSP** is set to **HOST\_RSP**, then we have to save all the registers. It means we must create a structure that allows us to read and modify registers in a C-like structure.

```
typedef struct _GUEST_REGS
{
    ULONG64 rax; // 0x00         // NOT VALID FOR SVM
    ULONG64 rcx;
    ULONG64 rdx; // 0x10
    ULONG64 rbx;
    ULONG64 rsp; // 0x20         // rsp is not stored here on SVM
    ULONG64 rbp;
    ULONG64 rsi; // 0x30
    ULONG64 rdi;
    ULONG64 r8; // 0x40
    ULONG64 r9;
    ULONG64 r10; // 0x50
    ULONG64 r11;
    ULONG64 r12; // 0x60
    ULONG64 r13;
    ULONG64 r14; // 0x70
    ULONG64 r15;
} GUEST_REGS, *PGUEST_REGS;
```

Just push all the registers in **\_GUEST\_REGS** order and push the RSP as the first argument to **MainVMExitHandle**r (Fastcall RCX), then some subtraction for Shadow space.

You can see the **VMExitHandler** here :

```
VmexitHandler PROC

    PUSH R15
    PUSH R14
    PUSH R13
    PUSH R12
    PUSH R11
    PUSH R10
    PUSH R9
    PUSH R8        
    PUSH RDI
    PUSH RSI
    PUSH RBP
    PUSH RBP	; RSP
    PUSH RBX
    PUSH RDX
    PUSH RCX
    PUSH RAX	


	MOV RCX, RSP		; Fast CALL argument to PGUEST_REGS
	SUB	RSP, 28h		; Free some space for Shadow Section

	CALL	MainVmexitHandler

	ADD	RSP, 28h		; Restore the state

	; Check whether we have to turn off VMX or Not (the result is in RAX)

	CMP	AL, 1
	JE		VmxoffHandler

	; Restore the state
	POP RAX
    POP RCX
    POP RDX
    POP RBX
    POP RBP		; RSP
    POP RBP
    POP RSI
    POP RDI 
    POP R8
    POP R9
    POP R10
    POP R11
    POP R12
    POP R13
    POP R14
    POP R15

	SUB RSP, 0100h ; to avoid error in future functions

	JMP VmResumeInstruction
	

VmexitHandler ENDP
```

From the above code, when we return from the **MainVMExitHandler**, we have to check whether the return result of **MainVMExitHandler** (in RAX) tells us to turn off the hypervisor or just continue.

If it needs to be continued, restore the registers state and jump to our **VM\_Resumer** function.

**VM\_Resumer** executes **\_\_vmx\_vmresume** and the processor sets the RIP register to **GUEST\_RIP**.

```
VOID
VmResumeInstruction()
{
    ULONG64 ErrorCode = 0;

    __vmx_vmresume();

    //
    // if VMRESUME succeeds will never be here!
    //
    __vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
    __vmx_off();
    DbgPrint("[*] VMRESUME Error : 0x%llx\n", ErrorCode);

    //
    // It's such a bad error because we don't where to go
    // prefer to break
    //
    DbgBreakPoint();
}
```

But what if it needs to be turned off?

Then based on **AL**, it jumps to another function called **VMXOFFHandler**. This simple function executes **VMXOFF**, turns off the hypervisor (in the current logical core), and then restores the registers to their previous state as we saved them in **VMExitHandler**.

The only thing we have to do here is changing the stack pointer to **GUEST\_RSP** (We saved them in **gGuestRSP**) and jump to the **GUEST\_RIP** (saved in **gGuestRIP**).

```
VmxoffHandler PROC

	; Turn VMXOFF
	VMXOFF

	; Restore the state

	POP RAX
    POP RCX
    POP RDX
    POP RBX
    POP RBP		; RSP
    POP RBP
    POP RSI
    POP RDI 
    POP R8
    POP R9
    POP R10
    POP R11
    POP R12
    POP R13
    POP R14
    POP R15

	; Set guest RIP and RSP

	MOV		RSP, g_GuestRSP

	JMP		g_GuestRIP

VmxoffHandler ENDP
```

Now everything is done, we executed our normal Windows (driver) routine; I mean, start the execution after the last CPUID that was executed from **RunOnProcessorForTerminateVMX** but now we're not in VMX operation.

## VM-Exit Handler

Putting all the above codes together, now we have to manage different kinds of VM-Exits, so we need to modify our previously explained (in the 5th part) **MainVMExitHandler**; if you forget about it, please review the 5th part (**VM-Exit Handler**), it's exactly the same but with different actions for different exit reasons.

The first thing we need to manage is to detect every VMX instructions that are executed in VMX non-root operation; it can be done using the following code :

```
    //
    // 25.1.2  Instructions That Cause VM Exits Unconditionally
    // The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC,
    // INVD, and XSETBV. This is also true of instructions introduced with VMX, which include: INVEPT, INVVPID,
    // VMCALL, VMCLEAR, VMLAUNCH, VMPTRLD, VMPTRST, VMRESUME, VMXOFF, and VMXON.
    //
    case EXIT_REASON_VMCLEAR:
    case EXIT_REASON_VMPTRLD:
    case EXIT_REASON_VMPTRST:
    case EXIT_REASON_VMREAD:
    case EXIT_REASON_VMRESUME:
    case EXIT_REASON_VMWRITE:
    case EXIT_REASON_VMXOFF:
    case EXIT_REASON_VMXON:
    case EXIT_REASON_VMLAUNCH:
    {
        // DbgBreakPoint();

        /*	DbgPrint("\n [*] Target guest tries to execute VM Instruction ,"
                "it probably causes a fatal error or system halt as the system might"
                " think it has VMX feature enabled while it's not available due to our use of hypervisor.\n");
                */

        ULONG RFLAGS = 0;
        __vmx_vmread(GUEST_RFLAGS, &RFLAGS);
        __vmx_vmwrite(GUEST_RFLAGS, RFLAGS | 0x1); // cf=1 indicate vm instructions fail
        break;
    }
```

As I tell you in **DbgPrint**, executing these kinds of VMX instructions will eventually cause BSOD because there might be some checks for the presence of a hypervisor before our hypervisor comes. Hence, the routine that executes these instructions (of course, it's from the kernel) probably thinks it can execute these instructions. If it didn't manage them well (which is common), you'll see BSOD. Thus, you have to discover the cause of invoking these kinds of instructions and manually disable them.

If you configured any CPU-based controls or your processor support 1-settings of any of CR Access Exit controls, then you can manage them using the function I described above,

```
    case EXIT_REASON_CR_ACCESS:
    {
        HandleControlRegisterAccess(GuestRegs);
        break;
    }
```

The same thing is true for MSRs access. If we didn't set any MSR Bit, every RDMSR and WRMSR cause to exit, or if we set any bits in **MSRBitMaps**, then we have to manage them using the following function for RDMSR :

```
    case EXIT_REASON_MSR_READ:
    {
        ULONG ECX = GuestRegs->rcx & 0xffffffff;

        // DbgPrint("[*] RDMSR (based on bitmap) : 0x%llx\n", ECX);
        HandleMSRRead(GuestRegs);

        break;
    }
```

Then this code for managing WRMSR :

```
    case EXIT_REASON_MSR_WRITE:
    {
        ULONG ECX = GuestRegs->rcx & 0xffffffff;

        DbgPrint("[*] WRMSR (based on bitmap) : 0x%llx\n", ECX);
        HandleMSRWrite(GuestRegs);

        break;
    }
```

And if you want to detect I/O instruction execution, then :

```
    case EXIT_REASON_IO_INSTRUCTION:
    {
        UINT64 RIP = 0;
        __vmx_vmread(GUEST_RIP, &RIP);

        DbgPrint("[*] RIP executed IO instruction : 0x%llx\n", RIP);
        DbgBreakPoint();

        break;
    }
```

Don't forget to set adequate CPU-based control fields if you want to use the above functionalities.

The last thing that is important for us is CPUID Handler. It calls **HandleCPUID** (described above), and if the result is true, then it saves the **GUEST\_RSP** and **GUEST\_RIP** so that these values can be used to restore the state after VMXOFF is executed in our core.

```
    case EXIT_REASON_CPUID:
    {
        Status = HandleCPUID(GuestRegs); // Detect whether we have to turn off VMX or Not
        if (Status)
        {
            // We have to save GUEST_RIP & GUEST_RSP somewhere to restore them directly

            ULONG ExitInstructionLength = 0;
            g_GuestRIP                  = 0;
            g_GuestRSP                  = 0;
            __vmx_vmread(GUEST_RIP, &g_GuestRIP);
            __vmx_vmread(GUEST_RSP, &g_GuestRSP);
            __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength);

            g_GuestRIP += ExitInstructionLength;
        }
        break;
    }
```

## Let's Test it!

Now it's time to test our hypervisor.

### Virtualizing all the cores

First, we have to load our driver.

![](../../assets/images/running-HVFS-1.png)

Running Driver

Then our **DriverEntry** is called, so we have to run our user-mode application to virtualize all the cores.

![](../../assets/images/running-HVFS-2.png)

Hypervisor From Scratch App

You can see that if you press any key or close this window, you call **DrvClose** and restore the state **(VMXOF**F).

![](../../assets/images/running-HVFS-3.png)

Driver log

All the cores are now under the hypervisor.

### Changing CPUID using Hypervisor

Now let's test the presence of the hypervisor. For this case, I used Immunity Debugger to execute CPUID with custom EAX. You can use any other debugger or any custom application.

![](../../assets/images/cpuid-handle-1.png)

Setting 0x40000001 as RAX

You have to set the EAX to **HYPERV\_CPUID\_INTERFACE manually** (**0x40000001**). Then execute **CPUID**.

![](../../assets/images/cpuid-handle-2.png)

HVFS is in RAX

As you can see, **HVFS** (0x48564653) is on **EAX**, so we successfully hooked the CPUID execution using our hypervisor.

![](../../assets/images/cpuid-handle-3.png)

The above picture shows the HYPERV\_CPUID\_INTERFACE without the hypervisor.

Now you have to close the user-mode app window, so it executes VMXOFF on all cores. Let's test the above example again.

![](../../assets/images/cpuid-handle-4.png)

You can see that the actual results have appeared.

### Detecting MSR Read & Write (MSRBitmap)

In order to test MSR Bitmaps, I create a local kernel debugger (using Windbg). In WinDbg, you can execute RDMSR & WRMSR to read and write MSRs. It's exactly like executing RDMSR and WRMSR using a system driver.

In our **VirtualizeCurrentSystem** function, the following line is added.

```
    SetMSRBitmap(0xc0000082, ProcessorID, TRUE, TRUE);
```

![](../../assets/images/MSR-bitmap-1.png)

Windbg Local Debugger (RDMSR & WRMSR)

In the remote debugger system, you can see the result as follows,

![](../../assets/images/MSR-bitmap-2.png)


As you can see, the execution of RDMSR is detected.

That's it all, folks.

![](../../assets/images/anime-girl-reading-book.jpg)

## Conclusion

In this part, we saw how we could virtualize an already running system by configuring the VMCS fields separately for each logical core. Then we use our hypervisor to change the result of CPUID instruction and monitor every access to control registers or MSRs. After this part, our hypervisor is almost ready to be used for a practical project. The future part is about using the Extended Page Table (as described previously in the 4th part). I believe most of the exciting works in hypervisor can be performed using EPT because it has a special logging mechanism, e.g., page read/write access detection and many other cool things you'll see in the next part.

Before finishing, I have to say. I'm neither a System Programmer nor a Hypervisor Developer, so please tell me about the mistakes in the comments section, this way, you can help me and many other readers to reduce the misconceptions.

See you in the next part.

The seventh part is also available [here](https://rayanfam.com/topics/hypervisor-from-scratch-part-7/).

## References

\[1\] Vol 3C – Chapter 24 – (VIRTUAL MACHINE CONTROL STRUCTURES ([https://software.intel.com/en-us/articles/intel-sdm](https://software.intel.com/en-us/articles/intel-sdm))  

\[2\] cpu-internals ([https://github.com/LordNoteworthy/cpu-internals](https://github.com/LordNoteworthy/cpu-internals))

\[3\] RDTSCP — Read Time-Stamp Counter and Processor ID ([https://www.felixcloutier.com/x86/rdtscp](https://www.felixcloutier.com/x86/rdtscp))

\[4\] INVPCID — Invalidate Process-Context Identifier ([https://www.felixcloutier.com/x86/invpcid](https://www.felixcloutier.com/x86/invpcid))

\[5\] XSAVE — Save Processor Extended States ([https://www.felixcloutier.com/x86/xsave](https://www.felixcloutier.com/x86/xsave))

\[6\] XRSTORS — Restore Processor Extended States Supervisor ([https://www.felixcloutier.com/x86/xrstors](https://www.felixcloutier.com/x86/xrstors))

\[7\] What is IRQL ? ([https://blogs.msdn.microsoft.com/doronh/2010/02/02/what-is-irql/](https://blogs.msdn.microsoft.com/doronh/2010/02/02/what-is-irql/))
