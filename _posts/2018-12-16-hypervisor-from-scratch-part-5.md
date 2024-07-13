---
title: "Hypervisor From Scratch – Part 5: Setting up VMCS & Running Guest Code"
date: "2018-12-16"
categories: 
  - "cpu"
  - "hypervisor"
  - "tutorials"
tags: 
  - "hypervisor"
  - "building-vmcs"
  - "configuring-vmcs"
  - "start-virtual-machine"
  - "virtual-machine-control-structure"
  - "vmcs"
  - "vmcs-configuration"
  - "vmlaunch"
  - "vmlaunch-0x7"
  - "vmlaunch-0x8"
  - "vmlaunch-error"
coverImage: "../../assets/images/hypervisor-from-scratch-part-5-cover.png"
comments: true
author:
  name: Sina Karvandi
  link: https://twitter.com/Intel80x86
---

![](../../assets/images/hypervisor-from-scratch-part-5-cover.png)

## **Introduction**

Hello and welcome to the fifth part of the "**Hypervisor From Scratch**" tutorial series. Today we will spend our time studying different parts of Virtual Machine Control Structure (VMCS), implementing additional VMX instructions, creating a restore point, setting different VMCS control structures, and at last, we execute **VMLAUNCH** and enter the hardware virtualization world! 

## **Table of contents**

- **Introduction**
- **Table of contents**
- **Overview**
- **VMX Instructions**  
    - VMPTRST
    - VMCLEAR
    - VMPTRLD
- **Enhancing VM State Structure**
- **Preparing to launch VM**
- **Saving a return point**
- **Returning to the previous state**
- **VMLAUNCH Instruction**
- **VMX Controls**
    - VM-Execution Controls
    - VM-entry Control Bits
    - VM-exit Control Bits
    - PIN-Based Execution Control
- **Configuring VMCS**
    - Gathering machine state for VMCS
    - Setting up VMCS
    - Checking VMCS layout
- **VM-Exit Handler**
    - Resume to next instruction
- **VMRESUME Instruction**
- **Let's Test it!**
- **Conclusion**
- **References**

## **Overview**

Most of this topic is derived from **Chapter 24 – (VIRTUAL MACHINE CONTROL STRUCTURES) & Chapter 26** – (**VM ENTRIES**) available at Intel 64 and IA-32 architectures software developer's manual (Intel SDM) combined volumes 3.

This part is highly inspired by [Hypervisor For Beginner](https://github.com/rohaaan/hypervisor-for-beginners).

Before reading the rest of this part, make sure to read the [previous parts](https://rayanfam.com/tutorials) as it gives you the necessary knowledge to understand the rest of this topic thoroughly.

The full source code of this tutorial is available on GitHub :

\[[https://github.com/SinaKarvandi/Hypervisor-From-Scratch](https://github.com/SinaKarvandi/Hypervisor-From-Scratch)\]

**Note**: Remember that hypervisors change over time because new features are added to the operating systems or using new technologies. For example, updates to Meltdown & Spectre have made a lot of changes to the hypervisors, so if you want to use Hypervisor From Scratch in your projects, research, or whatever, you have to use the driver from the latest parts of these tutorial series as this tutorial is actively updated and changes are applied to the newer parts (earlier parts keep untouched) so you might encounter errors and instability problems in the earlier parts thus make sure to use the latest parts in real-world projects.

![](../../assets/images/anime-girl-in-city.png)

## **VMX Instructions**

In [part 3](https://rayanfam.com/topics/hypervisor-from-scratch-part-3), we implemented **VMXOFF** function now let's implement other VMX instructions function. I also make some changes in calling **VMXON** and **VMPTRLD** functions to make it more modular.

### **VMPTRST**

**VMPTRST** instruction stores the current-VMCS pointer into a specified memory address. The operand of this instruction is always 64 bits, and it's always a location in memory.

The following function is the implementation of **VMPTRST**:

```
UINT64
VmptrstInstruction()
{
    PHYSICAL_ADDRESS vmcspa;
    vmcspa.QuadPart = 0;
    __vmx_vmptrst((unsigned __int64 *)&vmcspa);

    DbgPrint("[*] VMPTRST %llx\n", vmcspa);

    return 0;
}
```

### **VMCLEAR**

This instruction applies to the VMCS, where the VMCS region resides at the physical address contained in the instruction operand. The instruction ensures that VMCS data for that VMCS (some of these data may be currently maintained on the processor) are copied to the VMCS region in memory. It also initializes some parts of the VMCS region (for example, it sets the launch state of that VMCS to clear).

```
BOOLEAN
ClearVmcsState(VIRTUAL_MACHINE_STATE * GuestState)
{
    // Clear the state of the VMCS to inactive
    int status = __vmx_vmclear(&GuestState->VmcsRegion);

    DbgPrint("[*] VMCS VMCLAEAR Status is : %d\n", status);
    if (status)
    {
        // Otherwise, terminate the VMX
        DbgPrint("[*] VMCS failed to clear with status %d\n", status);
        __vmx_off();
        return FALSE;
    }
    return TRUE;
}
```

### **VMPTRLD**

This instruction marks the current-VMCS pointer valid and loads it with the physical address in the instruction operand. The instruction fails if its operand is not properly aligned, sets unsupported physical-address bits, or is equal to the **VMXON** pointer. In addition, this instruction fails if the 32 bits in memory referenced by the operand do not match the VMCS revision identifier supported by the processor.

```
BOOLEAN
LoadVmcs(VIRTUAL_MACHINE_STATE * GuestState)
{
    int status = __vmx_vmptrld(&GuestState->VmcsRegion);
    if (status)
    {
        DbgPrint("[*] VMCS failed with status %d\n", status);
        return FALSE;
    }
    return TRUE;
}
```

In order to implement **VMRESUME**, you need to know about some VMCS fields, so the explanation of the **VMRESUME** instruction is left after we implement **VMLAUNCH**. (Later in this topic)

## **Enhancing VM State Structure**

As I told you earlier, we need a structure to save the state of our virtual machine in each core separately. The following structure is used in the newest version of our hypervisor. We will describe each field in the rest of this topic.

```
typedef struct _VIRTUAL_MACHINE_STATE
{
    UINT64 VmxoRegion;        // VMXON region
    UINT64 VmcsRegion;        // VMCS region
    UINT64 Eptp;              // Extended-Page-Table Pointer
    UINT64 VmmStack;          // Stack for VMM in VM-Exit State
    UINT64 MsrBitmap;         // MSR Bitmap Virtual Address
    UINT64 MsrBitmapPhysical; // MSR Bitmap Physical Address

} VIRTUAL_MACHINE_STATE, *PVIRTUAL_MACHINE_STATE;
```

Note that it's not the final **VIRTUAL\_MACHINE\_STATE** structure; we'll enhance it in the future.

## **Preparing to launch VM**

In this part, we're just trying to enhance our hypervisor driver. In the future parts, we will add some user-mode interactions with our driver but for now, let's start with modifying our **DriverEntry** as it's the first function that executes when our driver is loaded.

Besides all the preparation from [part 2](https://rayanfam.com/topics/hypervisor-from-scratch-part-2/), we added the following lines to use our [part 4](https://rayanfam.com/topics/hypervisor-from-scratch-part-2/) (EPT) structures:

```
        //
        // Initiating EPTP and VMX
        //
        PEPTP EPTP = InitializeEptp();

        InitiateVmx();
```

We also added an export to a global variable called "**g_VirtualGuestMemoryAddress**" that holds the address of where our guest code starts.

Now let's fill our allocated pages with **\\xf4**, which is the hex representation of the **HLT** instruction. I choose **HLT** because, with some special configuration (described below), it'll cause VM-exit and return the code to the host handler; so, it would be an excellent example for this part.

After that, we start creating a function called `LaunchVm`, which is responsible for running our virtual machine on a specific core. We will only test our hypervisor in the **0th** logical processor in this part. In the future part, we'll extend our hypervisor to virtualize the entire system.

Keep in mind that every logical core has its own VMCS, and if we want our guest code to run in other logical processors, we should configure each of them separately.

To run our codes in a certain logical core, we should set the affinity by using the Windows **KeSetSystemAffinityThread** function and choose the specific core's **VIRTUAL\_MACHINE\_STATE** as each core has its own separate VMXON and VMCS regions.

The following code describes how we can run our code in different logical cores.

```
VOID
LaunchVm(int ProcessorID, PEPTP EPTP)
{
    DbgPrint("\n======================== Launching VM =============================\n");

    KAFFINITY AffinityMask;
    AffinityMask = MathPower(2, ProcessorID);
    KeSetSystemAffinityThread(AffinityMask);

    DbgPrint("[*]\t\tCurrent thread is executing in %d th logical processor.\n", ProcessorID);

    PAGED_CODE();

...
```

Now that we can specify a core number and execute codes in the target core, it's time should allocate a specific **stack** so that whenever a VM-exit occurs, we can save the registers and call other host functions in vmx-root mode.

A quick reminder, whenever a vm-exit occurs, the host handler is called in vmx-root mode. When we run the **VMRESUME** instruction, the processor switches to the VMX non-root; thus, every kernel-mode driver and user-mode application are running in **VMX non-root** mode. Only the portion of our driver responsible for handling the host is executed in the VMX root-mode.

Here we need a stack for host routines. We have two options, the first option is using the current **RSP**, and the second one is using a separated stack. We used a separate location for the stack instead of using the current **RSP** of the driver, but you can use the current stack (RSP) too.

The following lines are written for allocating and zeroing the stack of our VM-exit handler.

```
    //
    // Allocate stack for the VM Exit Handler
    //
    UINT64 VMM_STACK_VA                = ExAllocatePoolWithTag(NonPagedPool, VMM_STACK_SIZE, POOLTAG);
    g_GuestState[ProcessorID].VmmStack = VMM_STACK_VA;

    if (g_GuestState[ProcessorID].VmmStack == NULL)
    {
        DbgPrint("[*] Error in allocating VMM Stack.\n");
        return;
    }
    RtlZeroMemory(g_GuestState[ProcessorID].VmmStack, VMM_STACK_SIZE);
```

Same as above, we'll allocate a page for the MSR Bitmap and add it to **GuestState**. I'll describe them later in this topic.

```
    //
    // Allocate memory for MSRBitMap
    //
    g_GuestState[ProcessorID].MsrBitmap = MmAllocateNonCachedMemory(PAGE_SIZE); // should be aligned
    if (g_GuestState[ProcessorID].MsrBitmap == NULL)
    {
        DbgPrint("[*] Error in allocating MSRBitMap.\n");
        return;
    }
    RtlZeroMemory(g_GuestState[ProcessorID].MsrBitmap, PAGE_SIZE);
    g_GuestState[ProcessorID].MsrBitmapPhysical = VirtualToPhysicalAddress(g_GuestState[ProcessorID].MsrBitmap);
```

The next step is clearing the VMCS state and loading it as the current VMCS in the specific processor (in our case, the 0th logical processor).

The `ClearVmcsState` and `LoadVmcs` functions are used as described above:

```
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
```

Now it's time to set up VMCS. We will thoroughly discuss how to configure the VMCS later in this topic, but for now, assume that there is a function called `SetupVmcs`, which configures the VMCS structure.

```
    DbgPrint("[*] Setting up VMCS.\n");
    SetupVmcs(&g_GuestState[ProcessorID], EPTP);
```

The last step is to execute the **VMLAUNCH** instruction. Yet we shouldn't forget to save the current state of the stack (**RSP** & **RBP** registers). It's because after executing the **VMLAUNCH** instruction, the **RIP** register is changed to the **GUEST_RIP**; thus, we need to save the previous system state so we can return to the normal system routines after returning from VM functions. If we leave the driver with the wrong **RSP** & **RBP** registers, we'll see a BSOD. For this purpose, the `AsmSaveStateForVmxoff` function is used.

## **Saving a return point**

For `AsmSaveStateForVmxoff`, we declare two global variables called **g\_StackPointerForReturning**, and **g\_BasePointerForReturning**. There is no need to save the **RIP** register as the stack's return address is always available. Just EXTERN it in the assembly file :

```
EXTERN g_StackPointerForReturning:QWORD
EXTERN g_BasePointerForReturning:QWORD
```

The implementation of `AsmSaveStateForVmxoff` :

```
AsmSaveStateForVmxoff PROC PUBLIC

	MOV g_StackPointerForReturning, RSP
	MOV g_BasePointerForReturning, RBP

	RET

AsmSaveStateForVmxoff ENDP 
```

## **Returning to the previous state**

That last step in our hypervisor is returning to the previous system state and turning off the hypervisor. 

We previously saved the system state. Now, we can restore it (**RSP**and **RBP** registers) and clear the stack position.

Before that, the **VMXOFF** instruction is executed to turn off the hypervisor.

Take a look at the following code.

```
AsmVmxoffAndRestoreState PROC PUBLIC

	VMXOFF  ; turn it off before existing
	
	MOV RSP, g_StackPointerForReturning
	MOV RBP, g_BasePointerForReturning
	
	; make rsp point to a correct return point
	ADD RSP, 8
	
	; return True

	XOR RAX, RAX
	MOV RAX, 1
	
	; return section
	
	MOV     RBX, [RSP+28h+8h]
	MOV     RSI, [RSP+28h+10h]
	ADD     RSP, 020h
	POP     RDI
	
	RET
	
AsmVmxoffAndRestoreState ENDP 
```

At last, we need to precisely clear the stack. Previously we called the `LaunchVm` function and ended up in a new **RIP**.
To continue the execution normally, we need to clear the stack and return to the location where we called the `LaunchVm` function. Therefore, in the last part of the above assembly code, which is the "return section", I used IDA Pro to see the disassembly of the `LaunchVm`, so we can see how this function clears the stack, and we perform the same so we can return the previous system state gracefully. Hence, the "return section" is copied from the disassemblies of the `LaunchVm` in IDA Pro.

![LaunchVm Return Frame](../../assets/images/launch-vm-return.png)

## **VMLAUNCH Instruction**

It's time to talk about the **VMLAUNCH** instruction.

Take a look at the following code.

```
    __vmx_vmlaunch();

    //
    // if VMLAUNCH succeeds will never be here!
    //
    ULONG64 ErrorCode = 0;
    __vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
    __vmx_off();
    DbgPrint("[*] VMLAUNCH Error : 0x%llx\n", ErrorCode);
    DbgBreakPoint();
```

The `__vmx_vmlaunch()` is the intrinsic function for the **VMLAUNCH** instruction and `__vmx_vmread` is for the **VMREAD** instruction.

As the comment describes, if **VMLAUNCH** succeeds, we'll never execute the other lines. If there is an error in the state of VMCS (which is a common problem), we have to run **VMREAD ** and read the error code from the **VM\_INSTRUCTION\_ERROR** field of VMCS. It's also necessary to run VMXOFF to turn off the hypervisor in the case of an error, and finally, we can print the error code. 

**DbgBreakPoint** is just a debug breakpoint (int 3), and it can be helpful only if we're working on a remote kernel WinDbg Debugger. It's clear that you can't test it in your local debugging system because executing an **int 3** in the kernel will freeze your system as long as there is no debugger to catch it, so it's highly recommended to create a remote Kernel Debugging machine and test your codes for possible errors.

You can also use VMware Workstation's nested-virtualization to create a remote kernel debugging connection. Intel doesn't have such a thing as "nested-virtualization" but provides some hardware facilities so vendors can support and implement nested virtualization on their own. For example, you can test your driver on VMware Workstation with nested-virtualization support (I also explained how to debug your hypervisor driver on VMware in the first part.) However, supporting Hyper-V nested virtualization needs extra things to be considered in implementing a hypervisor, so we can't test our driver on Hyper-V nested virtualization, at least for this part. I'll explain Hyper-V support in the 8th part.

The drivers are tested on both physical machines and VMware Workstation's nested-virtualization.

Now it's time to read some theories before digging into the configuration of the VMCS.

## **VMX Controls**

Let's talk about different controls in VMCS that govern the guest's behavior. We will use some of these bits in this part, and some will be used in future parts. So, don't worry about it. Just take a look at the descriptions of these bits and be aware of them.

### **VM-Execution Controls**

In order to control our guest features, we have to set some fields in our VMCS. The following tables represent the Primary Processor-Based VM-Execution Controls and the Secondary Processor-Based VM-Execution Controls.

![Primary-Processor-Based-VM-Execution-Controls](../../assets/images/primary-processor-based-vm-execution-controls-fields.png)

We define the above table like this:

```
#define CPU_BASED_VIRTUAL_INTR_PENDING        0x00000004
#define CPU_BASED_USE_TSC_OFFSETING           0x00000008
#define CPU_BASED_HLT_EXITING                 0x00000080
#define CPU_BASED_INVLPG_EXITING              0x00000200
#define CPU_BASED_MWAIT_EXITING               0x00000400
#define CPU_BASED_RDPMC_EXITING               0x00000800
#define CPU_BASED_RDTSC_EXITING               0x00001000
#define CPU_BASED_CR3_LOAD_EXITING            0x00008000
#define CPU_BASED_CR3_STORE_EXITING           0x00010000
#define CPU_BASED_CR8_LOAD_EXITING            0x00080000
#define CPU_BASED_CR8_STORE_EXITING           0x00100000
#define CPU_BASED_TPR_SHADOW                  0x00200000
#define CPU_BASED_VIRTUAL_NMI_PENDING         0x00400000
#define CPU_BASED_MOV_DR_EXITING              0x00800000
#define CPU_BASED_UNCOND_IO_EXITING           0x01000000
#define CPU_BASED_ACTIVATE_IO_BITMAP          0x02000000
#define CPU_BASED_MONITOR_TRAP_FLAG           0x08000000
#define CPU_BASED_ACTIVATE_MSR_BITMAP         0x10000000
#define CPU_BASED_MONITOR_EXITING             0x20000000
#define CPU_BASED_PAUSE_EXITING               0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS 0x80000000
```

In the earlier versions of VMX, there was nothing like Secondary Processor-Based VM-Execution Controls. Now, if we want to use the secondary table, we have to set the 31st bit of the first table; otherwise, it's like the secondary table field with zeros.

![Secondary-Processor-Based-VM-Execution-Controls](../../assets/images/secondary-processor-based-vm-execution-controls-fields.png)

The definition of the above table is this (we ignore some bits, you can define them if you want to use them in your hypervisor):

```
#define CPU_BASED_CTL2_ENABLE_EPT            0x2
#define CPU_BASED_CTL2_RDTSCP                0x8
#define CPU_BASED_CTL2_ENABLE_VPID            0x20
#define CPU_BASED_CTL2_UNRESTRICTED_GUEST    0x80
#define CPU_BASED_CTL2_ENABLE_VMFUNC        0x2000
```

### **VM-entry Control Bits**

The VM-entry controls constitute a 32-bit vector that governs the basic operation of VM entries.

![VM-Entry-Controls](../../assets/images/vm-entry-controls-fields.png)

```
// VM-entry Control Bits 
#define VM_ENTRY_IA32E_MODE             0x00000200
#define VM_ENTRY_SMM                    0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR     0x00000800
#define VM_ENTRY_LOAD_GUEST_PAT         0x00004000
```

### **VM-exit Control Bits**

The VM-exit controls constitute a 32-bit vector that governs the essential operation of VM-exits.

![VM-Exit-Controls](../../assets/images/vm-exit-controls-fields.png)

```
// VM-exit Control Bits 
#define VM_EXIT_IA32E_MODE              0x00000200
#define VM_EXIT_ACK_INTR_ON_EXIT        0x00008000
#define VM_EXIT_SAVE_GUEST_PAT          0x00040000
#define VM_EXIT_LOAD_HOST_PAT           0x00080000
```

### **PIN-Based Execution Control**

The pin-based VM-execution controls constitute a 32-bit vector that governs the handling of asynchronous events (for example, interrupts). We'll use it in the future parts, but for now, let's define it in our hypervisor.

![Pin-Based-VM-Execution-Controls](../../assets/images/pin-based-vm-execution-controls-fields.png)

```
#define PIN_BASED_VM_EXECUTION_CONTROLS_EXTERNAL_INTERRUPT        0x00000001
#define PIN_BASED_VM_EXECUTION_CONTROLS_NMI_EXITING               0x00000008
#define PIN_BASED_VM_EXECUTION_CONTROLS_VIRTUAL_NMI               0x00000020
#define PIN_BASED_VM_EXECUTION_CONTROLS_ACTIVE_VMX_TIMER          0x00000040
#define PIN_BASED_VM_EXECUTION_CONTROLS_PROCESS_POSTED_INTERRUPTS 0x00000080
```

## **Configuring VMCS**

Now that we have a basic idea about some of the VMCS fields and controls, it's time to configure the VMCS structure fully to make our virtualized guest ready.

### **Gathering machine state for VMCS**

In order to configure our **Guest-State** and **Host-State**, we need to have details about the current system state, e.g., **G**lobal **D**escriptor **T**able Address (GDT), **I**nterrupt **D**escriptor **T**able (IDT) Address and read all the Segment Registers.

These functions describe how all of these registers and segments can be gathered.

GDT Base :

```
GetGdtBase PROC

	LOCAL	GDTR[10]:BYTE
	SGDT	GDTR
	MOV		RAX, QWORD PTR GDTR[2]

	RET

GetGdtBase ENDP
```

CS segment register:

```
GetCs PROC

	MOV		RAX, CS
	RET

GetCs ENDP
```

DS segment register:

```
GetDs PROC

	MOV		RAX, DS
	RET

GetDs ENDP
```

ES segment register:

```
GetEs PROC

	MOV		RAX, ES
	RET

GetEs ENDP
```
SS segment register:

```
GetSs PROC

	MOV		RAX, SS
	RET

GetSs ENDP
```

FS segment register:

```
GetFs PROC

	MOV		RAX, FS
	RET

GetFs ENDP
```

GS segment register:

```
GetGs PROC

	MOV		RAX, GS
	RET

GetGs ENDP
```

LDT:

```
GetLdtr PROC

	SLDT	RAX
	RET

GetLdtr ENDP
```

TR (task register):

```
GetTr PROC

	STR		RAX
	RET

GetTr ENDP
```

Interrupt Descriptor Table:

```
GetIdtBase PROC

	LOCAL	IDTR[10]:BYTE
	
	SIDT	IDTR
	MOV		RAX, QWORD PTR IDTR[2]
	RET

GetIdtBase ENDP
```

GDT Limit:

```
GetGdtLimit PROC

	LOCAL	GDTR[10]:BYTE

	SGDT	GDTR
	MOV		AX, WORD PTR GDTR[0]

	RET

GetGdtLimit ENDP
```

IDT Limit:

```
GetIdtLimit PROC

	LOCAL	IDTR[10]:BYTE
	
	SIDT	IDTR
	MOV		AX, WORD PTR IDTR[0]

	RET

GetIdtLimit ENDP
```

RFLAGS:

```
GetRflags PROC

	PUSHFQ
	POP		RAX
	RET

GetRflags ENDP
```

### **Setting up VMCS**

Let's get down to business (we have a long way to go).

This section starts with defining a function called `SetupVmcs`.

```
BOOLEAN
SetupVmcs(VIRTUAL_MACHINE_STATE * GuestState, PEPTP EPTP);
```

This function is responsible for configuring all of the options related to VMCS and, of course, the Guest & Host state.

Configuring and modifying VMCS is done by using a special instruction called "**VMWRITE**".

**VMWRITE** writes the contents of a primary source operand (register or memory) to a specified field in a VMCS. In VMX-root operation, the instruction writes to the current VMCS. If executed in VMX non-root operation, the instruction writes to the VMCS referenced by the VMCS link pointer field in the current VMCS.

The VMCS field is specified by the VMCS-field encoding contained in the register secondary source operand. 

The following **enum** contains most of the VMCS fields needed for **VMWRITE** & **VMREAD** instructions. (newer processors add newer fields.)

```
enum VMCS_FIELDS {
    GUEST_ES_SELECTOR = 0x00000800,
    GUEST_CS_SELECTOR = 0x00000802,
    GUEST_SS_SELECTOR = 0x00000804,
    GUEST_DS_SELECTOR = 0x00000806,
    GUEST_FS_SELECTOR = 0x00000808,
    GUEST_GS_SELECTOR = 0x0000080a,
    GUEST_LDTR_SELECTOR = 0x0000080c,
    GUEST_TR_SELECTOR = 0x0000080e,
    HOST_ES_SELECTOR = 0x00000c00,
    HOST_CS_SELECTOR = 0x00000c02,
    HOST_SS_SELECTOR = 0x00000c04,
    HOST_DS_SELECTOR = 0x00000c06,
    HOST_FS_SELECTOR = 0x00000c08,
    HOST_GS_SELECTOR = 0x00000c0a,
    HOST_TR_SELECTOR = 0x00000c0c,
    IO_BITMAP_A = 0x00002000,
    IO_BITMAP_A_HIGH = 0x00002001,
    IO_BITMAP_B = 0x00002002,
    IO_BITMAP_B_HIGH = 0x00002003,
    MSR_BITMAP = 0x00002004,
    MSR_BITMAP_HIGH = 0x00002005,
    VM_EXIT_MSR_STORE_ADDR = 0x00002006,
    VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,
    VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
    VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,
    VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
    VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,
    TSC_OFFSET = 0x00002010,
    TSC_OFFSET_HIGH = 0x00002011,
    VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
    VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,
    VMFUNC_CONTROLS = 0x00002018,
    VMFUNC_CONTROLS_HIGH = 0x00002019,
    EPT_POINTER = 0x0000201A,
    EPT_POINTER_HIGH = 0x0000201B,
    EPTP_LIST = 0x00002024,
    EPTP_LIST_HIGH = 0x00002025,
    GUEST_PHYSICAL_ADDRESS = 0x2400,
    GUEST_PHYSICAL_ADDRESS_HIGH = 0x2401,
    VMCS_LINK_POINTER = 0x00002800,
    VMCS_LINK_POINTER_HIGH = 0x00002801,
    GUEST_IA32_DEBUGCTL = 0x00002802,
    GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,
    PIN_BASED_VM_EXEC_CONTROL = 0x00004000,
    CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
    EXCEPTION_BITMAP = 0x00004004,
    PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
    PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
    CR3_TARGET_COUNT = 0x0000400a,
    VM_EXIT_CONTROLS = 0x0000400c,
    VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
    VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
    VM_ENTRY_CONTROLS = 0x00004012,
    VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
    VM_ENTRY_INTR_INFO_FIELD = 0x00004016,
    VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
    VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
    TPR_THRESHOLD = 0x0000401c,
    SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
    VM_INSTRUCTION_ERROR = 0x00004400,
    VM_EXIT_REASON = 0x00004402,
    VM_EXIT_INTR_INFO = 0x00004404,
    VM_EXIT_INTR_ERROR_CODE = 0x00004406,
    IDT_VECTORING_INFO_FIELD = 0x00004408,
    IDT_VECTORING_ERROR_CODE = 0x0000440a,
    VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
    VMX_INSTRUCTION_INFO = 0x0000440e,
    GUEST_ES_LIMIT = 0x00004800,
    GUEST_CS_LIMIT = 0x00004802,
    GUEST_SS_LIMIT = 0x00004804,
    GUEST_DS_LIMIT = 0x00004806,
    GUEST_FS_LIMIT = 0x00004808,
    GUEST_GS_LIMIT = 0x0000480a,
    GUEST_LDTR_LIMIT = 0x0000480c,
    GUEST_TR_LIMIT = 0x0000480e,
    GUEST_GDTR_LIMIT = 0x00004810,
    GUEST_IDTR_LIMIT = 0x00004812,
    GUEST_ES_AR_BYTES = 0x00004814,
    GUEST_CS_AR_BYTES = 0x00004816,
    GUEST_SS_AR_BYTES = 0x00004818,
    GUEST_DS_AR_BYTES = 0x0000481a,
    GUEST_FS_AR_BYTES = 0x0000481c,
    GUEST_GS_AR_BYTES = 0x0000481e,
    GUEST_LDTR_AR_BYTES = 0x00004820,
    GUEST_TR_AR_BYTES = 0x00004822,
    GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
    GUEST_ACTIVITY_STATE = 0x00004826,
    GUEST_SM_BASE = 0x00004828,
    GUEST_SYSENTER_CS = 0x0000482A,
    HOST_IA32_SYSENTER_CS = 0x00004c00,
    CR0_GUEST_HOST_MASK = 0x00006000,
    CR4_GUEST_HOST_MASK = 0x00006002,
    CR0_READ_SHADOW = 0x00006004,
    CR4_READ_SHADOW = 0x00006006,
    CR3_TARGET_VALUE0 = 0x00006008,
    CR3_TARGET_VALUE1 = 0x0000600a,
    CR3_TARGET_VALUE2 = 0x0000600c,
    CR3_TARGET_VALUE3 = 0x0000600e,
    EXIT_QUALIFICATION = 0x00006400,
    GUEST_LINEAR_ADDRESS = 0x0000640a,
    GUEST_CR0 = 0x00006800,
    GUEST_CR3 = 0x00006802,
    GUEST_CR4 = 0x00006804,
    GUEST_ES_BASE = 0x00006806,
    GUEST_CS_BASE = 0x00006808,
    GUEST_SS_BASE = 0x0000680a,
    GUEST_DS_BASE = 0x0000680c,
    GUEST_FS_BASE = 0x0000680e,
    GUEST_GS_BASE = 0x00006810,
    GUEST_LDTR_BASE = 0x00006812,
    GUEST_TR_BASE = 0x00006814,
    GUEST_GDTR_BASE = 0x00006816,
    GUEST_IDTR_BASE = 0x00006818,
    GUEST_DR7 = 0x0000681a,
    GUEST_RSP = 0x0000681c,
    GUEST_RIP = 0x0000681e,
    GUEST_RFLAGS = 0x00006820,
    GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
    GUEST_SYSENTER_ESP = 0x00006824,
    GUEST_SYSENTER_EIP = 0x00006826,
    HOST_CR0 = 0x00006c00,
    HOST_CR3 = 0x00006c02,
    HOST_CR4 = 0x00006c04,
    HOST_FS_BASE = 0x00006c06,
    HOST_GS_BASE = 0x00006c08,
    HOST_TR_BASE = 0x00006c0a,
    HOST_GDTR_BASE = 0x00006c0c,
    HOST_IDTR_BASE = 0x00006c0e,
    HOST_IA32_SYSENTER_ESP = 0x00006c10,
    HOST_IA32_SYSENTER_EIP = 0x00006c12,
    HOST_RSP = 0x00006c14,
    HOST_RIP = 0x00006c16,
};
```

OK, let's continue with our configuration.

The next step is configuring **host** Segment Registers.

```
    __vmx_vmwrite(HOST_ES_SELECTOR, GetEs() & 0xF8);
    __vmx_vmwrite(HOST_CS_SELECTOR, GetCs() & 0xF8);
    __vmx_vmwrite(HOST_SS_SELECTOR, GetSs() & 0xF8);
    __vmx_vmwrite(HOST_DS_SELECTOR, GetDs() & 0xF8);
    __vmx_vmwrite(HOST_FS_SELECTOR, GetFs() & 0xF8);
    __vmx_vmwrite(HOST_GS_SELECTOR, GetGs() & 0xF8);
    __vmx_vmwrite(HOST_TR_SELECTOR, GetTr() & 0xF8);
```

Keep in mind that those fields that start with "**HOST\_**" are related to the state in which the hypervisor sets whenever a VM-exit occurs, and those which begin with "**GUEST\_**" are related to the state in which the hypervisor sets for guest when a **VMLAUNCH** executed.

The purpose of `& 0xF8` is that Intel mentioned that the three less significant bits must be cleared; otherwise, it leads to an error as the **VMLAUNCH** is executed with an _Invalid Host State_ error.

Next, we set the `VMCS_LINK_POINTER`, which should be '0xffffffffffffffff'. As we don't have an additional VMCS. This field is mainly used for hypervisors that want to implement a nested-virtualization behavior (like VMware Nested Virtualization or KVM's nVMX).

```
    //
    // Setting the link pointer to the required value for 4KB VMCS
    //
    __vmx_vmwrite(VMCS_LINK_POINTER, ~0ULL);
```

The rest of this topic intends to virtualize the machine's current state, so the guest and host configurations must be the same. 

Let's configure **GUEST\_IA32\_DEBUGCTL**. This field works the same as the **IA32\_DEBUGCTL** MSR in a physical machine, and we can use it if we want to use separate **IA32\_DEBUGCTL** for each guest. It provides bit field controls to enable debug trace interrupts, debug trace stores, trace messages enable, single stepping on branches, last branch record recording, and control freezing of LBR stack.

We don't use it in our hypervisor, but we should configure it to the current machine's **MSR\_IA32\_DEBUGCTL**. We use `__readmsr()` intrinsic to read this MSR (RDMSR) and put the value of the physical machine to the guest's `GUEST_IA32_DEBUGCTL`.

```
    __vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
    __vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);
```

Note that values we put zero on them can be ignored; if you don't modify them, it's like you put zero on them.

For example, configuring TSC is not important for our hypervisor in the current state, so we put zero on it.

```
    /* Time-stamp counter offset */
    __vmx_vmwrite(TSC_OFFSET, 0);
    __vmx_vmwrite(TSC_OFFSET_HIGH, 0);

    __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MASK, 0);
    __vmx_vmwrite(PAGE_FAULT_ERROR_CODE_MATCH, 0);

    __vmx_vmwrite(VM_EXIT_MSR_STORE_COUNT, 0);
    __vmx_vmwrite(VM_EXIT_MSR_LOAD_COUNT, 0);

    __vmx_vmwrite(VM_ENTRY_MSR_LOAD_COUNT, 0);
    __vmx_vmwrite(VM_ENTRY_INTR_INFO_FIELD, 0);
```

This time, we'll configure Segment Registers based on the GDT base address for our Host (When VM-Exit occurs).

```
    GdtBase = GetGdtBase();

    FillGuestSelectorData((PVOID)GdtBase, ES, GetEs());
    FillGuestSelectorData((PVOID)GdtBase, CS, GetCs());
    FillGuestSelectorData((PVOID)GdtBase, SS, GetSs());
    FillGuestSelectorData((PVOID)GdtBase, DS, GetDs());
    FillGuestSelectorData((PVOID)GdtBase, FS, GetFs());
    FillGuestSelectorData((PVOID)GdtBase, GS, GetGs());
    FillGuestSelectorData((PVOID)GdtBase, LDTR, GetLdtr());
    FillGuestSelectorData((PVOID)GdtBase, TR, GetTr());
```

`GetGdtBase` is defined above in the process of gathering information for our VMCS.

`FillGuestSelectorData` is responsible for setting the GUEST selector, attributes, limit, and base for VMCS. It is implemented as below:

```
VOID
FillGuestSelectorData(
    PVOID  GdtBase,
    ULONG  Segreg,
    USHORT Selector)
{
    SEGMENT_SELECTOR SegmentSelector = {0};
    ULONG            AccessRights;

    GetSegmentDescriptor(&SegmentSelector, Selector, GdtBase);
    AccessRights = ((PUCHAR)&SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)&SegmentSelector.ATTRIBUTES)[1] << 12);

    if (!Selector)
        AccessRights |= 0x10000;

    __vmx_vmwrite(GUEST_ES_SELECTOR + Segreg * 2, Selector);
    __vmx_vmwrite(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.LIMIT);
    __vmx_vmwrite(GUEST_ES_AR_BYTES + Segreg * 2, AccessRights);
    __vmx_vmwrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.BASE);
}
```

The function body for **GetSegmentDescriptor** :

```
BOOLEAN
GetSegmentDescriptor(PSEGMENT_SELECTOR SegmentSelector,
                     USHORT            Selector,
                     PUCHAR            GdtBase)
{
    PSEGMENT_DESCRIPTOR SegDesc;

    if (!SegmentSelector)
        return FALSE;

    if (Selector & 0x4)
    {
        return FALSE;
    }

    SegDesc = (PSEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

    SegmentSelector->SEL               = Selector;
    SegmentSelector->BASE              = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
    SegmentSelector->LIMIT             = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
    SegmentSelector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;

    if (!(SegDesc->ATTR0 & 0x10))
    { // LA_ACCESSED
        ULONG64 Tmp;
        // this is a TSS or callgate etc, save the base high part
        Tmp                   = (*(PULONG64)((PUCHAR)SegDesc + 8));
        SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (Tmp << 32);
    }

    if (SegmentSelector->ATTRIBUTES.Fields.G)
    {
        // 4096-bit granularity is enabled for this segment, scale the limit
        SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
    }

    return TRUE;
}
```

Another MSR called `IA32_KERNEL_GS_BASE` is used to set the kernel GS base. Whenever instructions like **SYSCALL** are executed, and the processor enters ring 0, we need to change the current GS register, which can be done using [**SWAPGS**](https://www.felixcloutier.com/x86/SWAPGS.html) instruction. This instruction copies the content of **IA32\_KERNEL\_GS\_BASE** into the **IA32\_GS\_BASE**, and now it's used in the kernel when it wants to re-enter the user-mode.

**MSR\_FS\_BASE** on the other hand, doesn't have a kernel base because it is used in 32-Bit mode while we have a 64-bit (long mode) kernel.

Like the above MSR, we'll configure the **IA32\_GS\_BASE** and **IA32\_FS\_BASE** MSRs based on the current system's MSRs.

```
    __vmx_vmwrite(GUEST_FS_BASE, __readmsr(MSR_FS_BASE));
    __vmx_vmwrite(GUEST_GS_BASE, __readmsr(MSR_GS_BASE));
```

The **GUEST\_INTERRUPTIBILITY\_INFO** and **GUEST\_ACTIVITY\_STATE** are set to zero (we'll describe them in the future parts).

```
    __vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
    __vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);   //Active state 
```

Now we reach an essential part of the VMCS, and it's the configuration of **CPU\_BASED\_VM\_EXEC\_CONTROL** and **SECONDARY\_VM\_EXEC\_CONTROL** controls.

These fields enable and disable some essential features of the guest, e.g., we can configure VMCS to cause a VM-Exit whenever execution of **HLT** instruction is detected (in guest). You can read the description of each bit in the **VM-Execution Controls** section on this topic.

```
    __vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));
    __vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_CTL2_RDTSCP /* | CPU_BASED_CTL2_ENABLE_EPT*/, MSR_IA32_VMX_PROCBASED_CTLS2));
```

As you can see, we set `CPU_BASED_HLT_EXITING` that will cause the VM-Exit on **HLT** and activate secondary controls using the `CPU_BASED_ACTIVATE_SECONDARY_CONTROLS` bit.

In the secondary controls, we used `CPU_BASED_CTL2_RDTSCP`, and for now, comment `CPU_BASED_CTL2_ENABLE_EPT` because we don't need to deal with EPT in this part. In the 7th part, I thoroughly describe about EPT.

The description of `PIN_BASED_VM_EXEC_CONTROL`, `VM_EXIT_CONTROLS`*, and `VM_ENTRY_CONTROLS` is available above. We don't have any special configuration for these controls in this part; hence, let us put zero on them.

```
    __vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
    __vmx_vmwrite(VM_EXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
    __vmx_vmwrite(VM_ENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));
```

Also, the `AdjustControls` is a function for configuring the 0-settings and 1-settings of these fields (we will describe them in the future parts) but for now; it's defined like this:

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

The next step is setting Control Registers and Debug Registers (DR7) for the guest and the host. We set them to the same values as the current machine's state using intrinsic functions.

```
    __vmx_vmwrite(GUEST_CR0, __readcr0());
    __vmx_vmwrite(GUEST_CR3, __readcr3());
    __vmx_vmwrite(GUEST_CR4, __readcr4());

    __vmx_vmwrite(HOST_CR0, __readcr0());
    __vmx_vmwrite(HOST_CR3, __readcr3());
    __vmx_vmwrite(HOST_CR4, __readcr4());
```

The next part is setting up IDT and GDT's **Base** and **Limit** for our guest. Generally, it's [not a good idea](https://github.com/SinaKarvandi/Misc/tree/master/HypervisorBypassWithNMI) to use the same IDT (and GDT) for the guest and host, but in order to keep our hypervisor simple, we'll configure them to the same value.

```
    __vmx_vmwrite(GUEST_GDTR_BASE, GetGdtBase());
    __vmx_vmwrite(GUEST_IDTR_BASE, GetIdtBase());
    __vmx_vmwrite(GUEST_GDTR_LIMIT, GetGdtLimit());
    __vmx_vmwrite(GUEST_IDTR_LIMIT, GetIdtLimit());
```

Next, set the RFLAGS.

```
    __vmx_vmwrite(GUEST_RFLAGS, GetRflags());
```

If you want to use SYSENTER in your guest, you should configure the following MSRs. It's not important to set these values in x64 Windows because Windows doesn't support SYSENTER in x64 versions of Windows; instead, it uses SYSCALL. 

The same instruction works for 32-bit processes too. In 32-bit processes, Windows first changes the execution mode to long-mode (using [Heaven's Gate technique](http://rce.co/knockin-on-heavens-gate-dynamic-processor-mode-switching/)), and then executes the SYSCALL instruction.

```
    __vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    __vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
    __vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
    __vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
    __vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
```

Don't forget to configure **HOST\_FS\_BASE**, **HOST\_GS\_BASE**, **HOST\_GDTR\_BASE**, **HOST\_IDTR\_BASE**, **HOST\_TR\_BASE** for the host in the VMCS.

```
    GetSegmentDescriptor(&SegmentSelector, GetTr(), (PUCHAR)GetGdtBase());
    __vmx_vmwrite(HOST_TR_BASE, SegmentSelector.BASE);

    __vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
    __vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));

    __vmx_vmwrite(HOST_GDTR_BASE, GetGdtBase());
    __vmx_vmwrite(HOST_IDTR_BASE, GetIdtBase());
```

The next important part is to set the **RIP** and **RSP** registers of the guest when a **VMLAUNCH** is executed. It starts with the **RIP** you configured in this part and **RIP** and **RSP** of the host when a VM-exit occurs. It's pretty clear that host **RIP** should point to a function responsible for managing VMX events based on the VM-exit code and whether decide to execute a **VMRESUME** or turn off the hypervisor using **VMXOFF**.

```
    __vmx_vmwrite(GUEST_RSP, (ULONG64)g_VirtualGuestMemoryAddress); // setup guest sp
    __vmx_vmwrite(GUEST_RIP, (ULONG64)g_VirtualGuestMemoryAddress); // setup guest ip

    __vmx_vmwrite(HOST_RSP, ((ULONG64)GuestState->VmmStack + VMM_STACK_SIZE - 1));
    __vmx_vmwrite(HOST_RIP, (ULONG64)AsmVmexitHandler);
```

**HOST\_RSP** points to **VmmStack** that we allocated before, and **HOST\_RIP** points to **AsmVmexitHandler** (an assembly written function described below). **GUEST\_RIP** points to **g_VirtualGuestMemoryAddress** (the global variable we configured during EPT initialization) and **GUEST\_RSP** to the same address (**g_VirtualGuestMemoryAddress**) because we don't put any instruction that uses the stack, so for a real-world example, it should point to a different writeable address.

Done! Our VMCS is almost ready.

### **Checking VMCS Layout**

Unfortunately, checking VMCS Layout is not as straight as the other parts. We have to control all the checklists described in **\[CHAPTER 26\] VM ENTRIES** from **Intel's 64 and IA-32 Architectures Software Developer's Manual**, including the following sections:

- **26.2 CHECKS ON VMX CONTROLS AND HOST-STATE AREA**
- **26.3 CHECKING AND LOADING GUEST STATE** 
- **26.4 LOADING MSRS**
- **26.5 EVENT INJECTION**
- **26.6 SPECIAL FEATURES OF VM ENTRY**
- **26.7 VM-ENTRY FAILURES DURING OR AFTER LOADING GUEST STATE**
- **26.8 MACHINE-CHECK EVENTS DURING VM ENTRY**

The hardest part of this process is when we have no idea about the incorrect part of your VMCS layout or, on the other hand, when you miss something that eventually causes the failure.

This is because Intel just gives an error number without any further details about what's exactly wrong in n our VMCS Layout.

The errors are shown below.

![VM Errors](../../assets/images/vm-error.png)

To solve this problem, I created a user-mode application called **VmcsAuditor**. As its name describes, it can be a choice if you have any error and don't have any idea about solving the problem. 

Remember that [VmcsAuditor](https://rayanfam.com/topics/vmcsauditor-a-bochs-based-hypervisor-layout-checker) is a tool based on Bochs emulator support for VMX, so all the checks come from Bochs, and it's not a 100% reliable tool that solves all the problem as we don't know what exactly happens inside the processor. Still, it can be handy and a time saver.

The source code and executable files are available on GitHub :

\[[https://github.com/SinaKarvandi/VMCS-Auditor](https://github.com/SinaKarvandi/VMCS-Auditor)\] 

Further description available [here](https://rayanfam.com/topics/vmcsauditor-a-bochs-based-hypervisor-layout-checker/).

As a better alternative, you can use [Satoshi Tanda](https://github.com/tandasat)'s **[code](https://github.com/SinaKarvandi/Hypervisor-From-Scratch/tree/master/Part%205%20-%20Setting%20up%20VMCS%20%26%20Running%20Guest%20Code/VMCS-Checks)** for checking the guest state.

## **VM-Exit Handler**

When our guest software exits and gives the handle back to the host, the following VM-exit reasons might happen.

```
#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXTERNAL_INTERRUPT  1
#define EXIT_REASON_TRIPLE_FAULT        2
#define EXIT_REASON_INIT                3
#define EXIT_REASON_SIPI                4
#define EXIT_REASON_IO_SMI              5
#define EXIT_REASON_OTHER_SMI           6
#define EXIT_REASON_PENDING_VIRT_INTR   7
#define EXIT_REASON_PENDING_VIRT_NMI    8
#define EXIT_REASON_TASK_SWITCH         9
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_GETSEC              11
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVD                13
#define EXIT_REASON_INVLPG              14
#define EXIT_REASON_RDPMC               15
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_RSM                 17
#define EXIT_REASON_VMCALL              18
#define EXIT_REASON_VMCLEAR             19
#define EXIT_REASON_VMLAUNCH            20
#define EXIT_REASON_VMPTRLD             21
#define EXIT_REASON_VMPTRST             22
#define EXIT_REASON_VMREAD              23
#define EXIT_REASON_VMRESUME            24
#define EXIT_REASON_VMWRITE             25
#define EXIT_REASON_VMXOFF              26
#define EXIT_REASON_VMXON               27
#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_DR_ACCESS           29
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32
#define EXIT_REASON_INVALID_GUEST_STATE 33
#define EXIT_REASON_MSR_LOADING         34
#define EXIT_REASON_MWAIT_INSTRUCTION   36
#define EXIT_REASON_MONITOR_TRAP_FLAG   37
#define EXIT_REASON_MONITOR_INSTRUCTION 39
#define EXIT_REASON_PAUSE_INSTRUCTION   40
#define EXIT_REASON_MCE_DURING_VMENTRY  41
#define EXIT_REASON_TPR_BELOW_THRESHOLD 43
#define EXIT_REASON_APIC_ACCESS         44
#define EXIT_REASON_ACCESS_GDTR_OR_IDTR 46
#define EXIT_REASON_ACCESS_LDTR_OR_TR   47
#define EXIT_REASON_EPT_VIOLATION       48
#define EXIT_REASON_EPT_MISCONFIG       49
#define EXIT_REASON_INVEPT              50
#define EXIT_REASON_RDTSCP              51
#define EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED     52
#define EXIT_REASON_INVVPID             53
#define EXIT_REASON_WBINVD              54
#define EXIT_REASON_XSETBV              55
#define EXIT_REASON_APIC_WRITE          56
#define EXIT_REASON_RDRAND              57
#define EXIT_REASON_INVPCID             58
#define EXIT_REASON_RDSEED              61
#define EXIT_REASON_PML_FULL            62
#define EXIT_REASON_XSAVES              63
#define EXIT_REASON_XRSTORS             64
#define EXIT_REASON_PCOMMIT             65
```

VMX-exit handler should be an assembly function because calling a compiled function needs some preparation and some register modification. The necessary thing in the VM-exit handler is saving the registers' state so we can continue the guest later.

I create a sample function for saving and restoring registers. In this function, we call another C function to extend the vm-exit handler.

```
PUBLIC AsmVmexitHandler

EXTERN MainVmexitHandler:PROC
EXTERN VmResumeInstruction:PROC

.code _text

AsmVmexitHandler PROC

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

	MOV RCX, RSP		; GuestRegs
	SUB	RSP, 28h

	CALL	MainVmexitHandler
	ADD	RSP, 28h	

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
	
AsmVmexitHandler ENDP

END
```

The main VM-exit handler is a switch-case function with different decisions over the VMCS **VM\_EXIT\_REASON** and **EXIT\_QUALIFICATION**.

In this part, we're just performing an action over **EXIT\_REASON\_HLT** and just print the result and restore the guest state normally.

From the following code, you can see what event cause the VM-exit. Just keep in mind that some reasons only lead to Vm-exit if the VMCS's control execution fields (described above) configure it. For instance, the execution of **HLT** instruction in guest will cause VM-exit if the **7**th bit of the Primary Processor-Based VM-Execution Controls allows it.

```
VOID
MainVmexitHandler(PGUEST_REGS GuestRegs)
{
    ULONG ExitReason = 0;
    __vmx_vmread(VM_EXIT_REASON, &ExitReason);

    ULONG ExitQualification = 0;
    __vmx_vmread(EXIT_QUALIFICATION, &ExitQualification);

    DbgPrint("\nVM_EXIT_REASION 0x%x\n", ExitReason & 0xffff);
    DbgPrint("\EXIT_QUALIFICATION 0x%x\n", ExitQualification);

    switch (ExitReason)
    {
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
        break;
    }
    case EXIT_REASON_HLT:
    {
        DbgPrint("[*] Execution of HLT detected... \n");

        //
        // that's enough for now ;)
        //
        AsmVmxoffAndRestoreState();

        break;
    }
    case EXIT_REASON_EXCEPTION_NMI:
    {
        break;
    }

    case EXIT_REASON_CPUID:
    {
        break;
    }

    case EXIT_REASON_INVD:
    {
        break;
    }

    case EXIT_REASON_VMCALL:
    {
        break;
    }

    case EXIT_REASON_CR_ACCESS:
    {
        break;
    }

    case EXIT_REASON_MSR_READ:
    {
        break;
    }

    case EXIT_REASON_MSR_WRITE:
    {
        break;
    }

    case EXIT_REASON_EPT_VIOLATION:
    {
        break;
    }

    default:
    {
        // DbgBreakPoint();
        break;
    }
    }
}
```

### **Resume to next instruction**

If a VM-exit occurs (e.g., the guest executed a **CPUID** instruction), the guest **RIP** remains constant, and it's up to VMM to change the Guest's **RIP** or not, so if we don't have a certain function for managing this situation, then the processor executes an infinite loop of **CPUID** instructions because we didn't increment the **RIP**.

In order to solve this problem, we have to read a VMCS field called **VM\_EXIT\_INSTRUCTION\_LEN** that stores the length of the instruction that caused the VM-exit.

First, we have to read the guest's current **RIP** from the **GUEST_RIP**. Second, read the **VM\_EXIT\_INSTRUCTION\_LEN** using **VMREAD**, and third the length of the instruction to the guest's **RIP**. Now the guest will continue its execution from the next instruction, and we're good to go.

The following function is for this purpose.

```
VOID
ResumeToNextInstruction()
{
    PVOID ResumeRIP             = NULL;
    PVOID CurrentRIP            = NULL;
    ULONG ExitInstructionLength = 0;

    __vmx_vmread(GUEST_RIP, &CurrentRIP);
    __vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength);

    ResumeRIP = (PCHAR)CurrentRIP + ExitInstructionLength;

    __vmx_vmwrite(GUEST_RIP, (ULONG64)ResumeRIP);
}
```

## **VMRESUME Instruction**

Now that we handled the VM-exit, it's time to continue the guest. We could continue the execution by using the **VMRESUME** instruction.

**VMRESUME** is like **VMLAUNCH**, but it's used in order to resume the guest.

To compare these instructions,

- VMLAUNCH fails if the launch state of the current VMCS is not "clear". If the instruction is successful, it sets the launch state to "launched."

- VMRESUME fails if the launch state of the current VMCS is not "launched."

So it's clear that if we executed the **VMLAUNCH** instruction before, we can't use it anymore to resume the guest code, and in this condition, **VMRESUME** is used.

The following code is the implementation of **VMRESUME**.

```
VOID
VmResumeInstruction()
{
    __vmx_vmresume();

    // if VMRESUME succeeds will never be here !

    ULONG64 ErrorCode = 0;
    __vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
    __vmx_off();
    DbgPrint("[*] VMRESUME Error : 0x%llx\n", ErrorCode);

    //
    // It's such a bad error because we don't where to go!
    // prefer to break
    //
    DbgBreakPoint();
}
```

## **Let's Test it!**

Well, we have done with the configuration, and now it's time to run our driver using **OSR Driver Loader**. As always, we should disable the driver signature enforcement and run our driver.

![](../../assets/images/hlt-execution.png)

As you can see from the above picture (in the launching VM area), first, we set the current logical processor to 0. Next, we clear our VMCS status using the **VMCLEAR** instruction, set up our VMCS layout and execute the **VMLAUNCH** instruction.

Now, our guest code is executed, and as we configured our VMCS to cause a VM-exit in the case of the execution of the **HLT** **(CPU\_BASED\_HLT\_EXITING)** instruction.

After running the guest, the VM-exit handler is called, then it calls the main VM-exit handler, and as the VMCS exit reason is **0xc (EXIT\_REASON\_HLT)**, we successfully detected the execution of **HLT** in the guest.

After that, our machine state saving mechanism is executed, and we successfully turn off the hypervisor using the **VMXOFF** instruction and return to the first caller with a successful **(RAX = 1) status.

That's it! Wasn't it easy? 

![:)](../../assets/images/anime-girls-drinking-tea.jpg)

## **Conclusion**

In this part, we got familiar with configuring the Virtual Machine Control Structure and finally ran our guest code. The future parts would be an enhancement to this configuration like entering **protected-mode,** **interrupt injection**, **page modification logging,** **virtualizing the current machine**, and so on. You can use the comments section below if you have any questions or problems.

See you in the next part.

The sixth part is also available [here](https://rayanfam.com/topics/hypervisor-from-scratch-part-6).

## **References**

\[1\] Vol 3C - Chapter 24 – (VIRTUAL MACHINE CONTROL STRUCTURES ([https://software.intel.com/en-us/articles/intel-sdm](https://software.intel.com/en-us/articles/intel-sdm))

\[2\] Vol 3C - Chapter 26 – (VM ENTRIES) ([https://software.intel.com/en-us/articles/intel-sdm](https://software.intel.com/en-us/articles/intel-sdm))

\[3\] Segmentation ([https://wiki.osdev.org/Segmentation](https://wiki.osdev.org/Segmentation))

\[4\] x86 memory segmentation ([https://en.wikipedia.org/wiki/X86\_memory\_segmentation](https://en.wikipedia.org/wiki/X86_memory_segmentation))

\[5\] VmcsAuditor – A Bochs-Based Hypervisor Layout Checker ([https://rayanfam.com/topics/vmcsauditor-a-bochs-based-hypervisor-layout-checker/](https://rayanfam.com/topics/vmcsauditor-a-bochs-based-hypervisor-layout-checker/))

\[6\] Rohaaan/Hypervisor For Beginners ([https://github.com/rohaaan/hypervisor-for-beginners](https://github.com/rohaaan/hypervisor-for-beginners))

\[7\] SWAPGS — Swap GS Base Register ([https://www.felixcloutier.com/x86/SWAPGS.html](https://www.felixcloutier.com/x86/SWAPGS.html))

\[8\] Knockin' on Heaven's Gate - Dynamic Processor Mode Switching ([](http://rce.co/knockin-on-heavens-gate-dynamic-processor-mode-switching/)[http://rce.co/knockin-on-heavens-gate-dynamic-processor-mode-switching/](http://rce.co/knockin-on-heavens-gate-dynamic-processor-mode-switching/))
