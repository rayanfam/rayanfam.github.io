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
coverImage: "../../assets/images/fifth-part.png"
author:
  name: Mohammad Sina Karvandi
  link: https://twitter.com/Intel80x86
---

![](../../assets/images/fifth-part.png)

# **Introduction**

Hello and welcome back to the fifth part of the "Hypervisor From Scratch" tutorial series. Today we will be configuring our previously allocated Virtual Machine Control Structure (VMCS) and in the last, we execute VMLAUNCH and enter to our hardware-virtualized world! Before reading the rest of this part, you have to read the [previous parts](https://rayanfam.com/tutorials/) as they are really dependent.

The full source code of this tutorial is available on GitHub :

\[[https://github.com/SinaKarvandi/Hypervisor-From-Scratch](https://github.com/SinaKarvandi/Hypervisor-From-Scratch)\]

Note: Please keep in mind that hypervisors change during the time because new features added to the operating systems or using new technologies, for example, updates to Meltdown & Spectre have made a lot of changes to the hypervisors, so if you want to use Hypervisor From Scratch in your projects, researches or whatever, you have to use the driver from the latest parts of these tutorial series as this tutorial is actively updated and changes are applied to the newer parts (earlier parts keep untouched) so you might encounter errors and instability problems in the earlier parts thus make sure to use the latest parts in real-world projects.

Most of this topic derived from **Chapter 24 – (VIRTUAL MACHINE CONTROL STRUCTURES) & Chapter 26** – (**VM ENTRIES**) available at Intel 64 and IA-32 architectures software developer’s manual combined volumes 3. Of course, for more information, you can read the manual as well.

# **Table of contents**

- **Introduction**
- **Table of contents**
- **VMX Instructions**  
    - VMPTRST
    - VMCLEAR
    - VMPTRLD
- **Enhancing VM State Structure**
- **Preparing to launch VM**
- **VMX Configurations**
- **Saving a return point**
- **Returning to the previous state**
- **VMLAUNCH**
- **VMX Controls**
    - VM-Execution Controls
    - VM-entry Control Bits
    - VM-exit Control Bits
    - PIN-Based Execution Control
    - Interruptibility State
- **Configuring VMCS**
    - Gathering Machine state for VMCS
    - Setting up VMCS
    - Checking VMCS Layout
- **VM-Exit Handler**
    - Resume to next instruction
- **VMRESUME**
- **Let's Test it!**
- **Conclusion**
- **References**

This part is highly inspired from [Hypervisor For Beginner](https://github.com/rohaaan/hypervisor-for-beginners) and some of methods are exactly like what implemented in that project.

![](../../assets/images/animeeey.png)

# **VMX Instructions**

In [part 3](https://rayanfam.com/topics/hypervisor-from-scratch-part-3/), we implemented VMXOFF function now let's implement other VMX instructions function. I also make some changes in calling VMXON and VMPTRLD functions to make it more modular.

# **VMPTRST**

VMPTRST stores the current-VMCS pointer into a specified memory address. The operand of this instruction is always 64 bits and it's always a location in memory.

The following function is the implementation of VMPTRST:

UINT64 VMPTRST()
{
    PHYSICAL\_ADDRESS vmcspa;
    vmcspa.QuadPart = 0;
    \_\_vmx\_vmptrst((unsigned \_\_int64 \*)&vmcspa);

    DbgPrint("\[\*\] VMPTRST %llx\\n", vmcspa);

    return 0;
}

# **VMCLEAR**

This instruction applies to the VMCS which VMCS region resides at the physical address contained in the instruction operand. The instruction ensures that VMCS data for that VMCS (some of these data may be currently maintained on the processor) are copied to the VMCS region in memory. It also initializes some parts of the VMCS region (for example, it sets the launch state of that VMCS to clear).

BOOLEAN Clear\_VMCS\_State(IN PVirtualMachineState vmState) {

    // Clear the state of the VMCS to inactive
    int status = \_\_vmx\_vmclear(&vmState->VMCS\_REGION);

    DbgPrint("\[\*\] VMCS VMCLAEAR Status is : %d\\n", status);
    if (status)
    {
        // Otherwise terminate the VMX
        DbgPrint("\[\*\] VMCS failed to clear with status %d\\n", status);
        \_\_vmx\_off();
        return FALSE;
    }
    return TRUE;
}

# **VMPTRLD**

It marks the current-VMCS pointer valid and loads it with the physical address in the instruction operand. The instruction fails if its operand is not properly aligned, sets unsupported physical-address bits, or is equal to the VMXON pointer. In addition, the instruction fails if the 32 bits in memory referenced by the operand do not match the VMCS revision identifier supported by this processor.

BOOLEAN Load\_VMCS(IN PVirtualMachineState vmState) {

    int status = \_\_vmx\_vmptrld(&vmState->VMCS\_REGION);
    if (status)
    {
        DbgPrint("\[\*\] VMCS failed with status %d\\n", status);
        return FALSE;
    }
    return TRUE;
}

In order to implement VMRESUME you need to know about some VMCS fields so the implementation of VMRESUME is after we implement VMLAUNCH. (Later in this topic)

# **Enhancing VM State Structure**

As I told you in earlier parts, we need a structure to save the state of our virtual machine in each core separately. The following structure is used in the newest version of our hypervisor, each field will be described in the rest of this topic.

typedef struct \_VirtualMachineState
{
    UINT64 VMXON\_REGION;                    // VMXON region
    UINT64 VMCS\_REGION;                     // VMCS region
    UINT64 EPTP;                            // Extended-Page-Table Pointer
    UINT64 VMM\_Stack;                       // Stack for VMM in VM-Exit State
    UINT64 MSRBitMap;                       // MSRBitMap Virtual Address
    UINT64 MSRBitMapPhysical;               // MSRBitMap Physical Address
} VirtualMachineState, \*PVirtualMachineState;

Note that its not the final **\_VirtualMachineState** structure and we'll enhance it in future parts.

# **Preparing to launch VM**

In this part, we're just trying to test our hypervisor in our driver, in the future parts we add some user-mode interactions with our driver so let's start with modifying our **DriverEntry** as it's the first function that executes when our driver is loaded.

Below all the preparation from [Part 2](https://rayanfam.com/topics/hypervisor-from-scratch-part-2/), we add the following lines to use our [Part 4](https://rayanfam.com/topics/hypervisor-from-scratch-part-2/) (EPT) structures :

		// Initiating EPTP and VMX
		PEPTP EPTP = Initialize\_EPTP();
		Initiate\_VMX();

I added an export to a global variable called "VirtualGuestMemoryAddress" that holds the address of where our guest code starts.

Now let's fill our allocated pages with **\\xf4** which stands for **HLT** instruction. I choose **HLT** because with some special configuration (described below) it'll cause VM-Exit and return the code to the Host handler.

Let's create a function which is responsible for running our virtual machine on a specific core.

void LaunchVM(int ProcessorID , PEPTP EPTP);

I set the ProcessorID to 0, so we're in the 0th logical processor.

Keep in mind that every logical core has its own VMCS and if you want your guest code to run in other logical processor, you should configure them separately.

Now we should set the affinity to the specific logical processor using Windows **KeSetSystemAffinityThread** function and make sure to choose the specific core's **vmState** as each core has its own separate VMXON and VMCS region.

    KAFFINITY kAffinityMask;
        kAffinityMask = ipow(2, ProcessorID);
        KeSetSystemAffinityThread(kAffinityMask);

        DbgPrint("\[\*\]\\t\\tCurrent thread is executing in %d th logical processor.\\n", ProcessorID);

        PAGED\_CODE();

Now, we should allocate a specific stack so that every time a VM-Exit occurs then we can save the registers and calling other Host functions.

I prefer to allocate a separate location for stack instead of using current RSP of the driver but you can use current stack (RSP) too.

The following lines are for allocating and zeroing the stack of our VM-Exit handler.

 	// Allocate stack for the VM Exit Handler.
	UINT64 VMM\_STACK\_VA = ExAllocatePoolWithTag(NonPagedPool, VMM\_STACK\_SIZE, POOLTAG);
	vmState\[ProcessorID\].VMM\_Stack = VMM\_STACK\_VA;

	if (vmState\[ProcessorID\].VMM\_Stack == NULL)
	{
		DbgPrint("\[\*\] Error in allocating VMM Stack.\\n");
		return;
	}
	RtlZeroMemory(vmState\[ProcessorID\].VMM\_Stack, VMM\_STACK\_SIZE);

Same as above, allocating a page for MSR Bitmap and adding it to **vmState**, I'll describe about them later in this topic.

```
	// Allocate memory for MSRBitMap
	vmState[ProcessorID].MSRBitMap = MmAllocateNonCachedMemory(PAGE_SIZE);  // should be aligned
	if (vmState[ProcessorID].MSRBitMap == NULL)
	{
		DbgPrint("[*] Error in allocating MSRBitMap.\n");
		return;
	}
	RtlZeroMemory(vmState[ProcessorID].MSRBitMap, PAGE_SIZE);
	
vmState[ProcessorID].MSRBitMapPhysical = VirtualAddress_to_PhysicalAddress(vmState[ProcessorID].MSRBitMap);
```

Now it's time to clear our VMCS state and load it as the current VMCS in the specific processor (in our case the 0th logical processor).

The **Clear\_VMCS\_State** and **Load\_VMCS** are described above :

```

	// Clear the VMCS State
	if (!Clear_VMCS_State(&vmState[ProcessorID])) {
		goto ErrorReturn;
	}

	// Load VMCS (Set the Current VMCS)
	if (!Load_VMCS(&vmState[ProcessorID]))
	{
		goto ErrorReturn;
	}
```

Now it's time to setup VMCS, A detailed explanation of VMCS setup is available later in this topic.

```

	DbgPrint("[*] Setting up VMCS.\n");
	Setup_VMCS(&vmState[ProcessorID], EPTP);
```

The last step is to execute the VMLAUNCH but we shouldn't forget about saving the current state of the stack (RSP & RBP) because during the execution of Guest code and after returning from VM-Exit, we have to know the current state and return from it. It's because if you leave the driver with wrong RSP & RBP then you definitely see a BSOD.

```

	Save_VMXOFF_State();
```

# **Saving a return point**

For **Save\_VMXOFF\_State()** , I declared two global variables called **g\_StackPointerForReturning**, **g\_BasePointerForReturning**. No need to save RIP as the return address is always available in the stack. Just EXTERN it in the assembly file :

```

EXTERN g_StackPointerForReturning:QWORD
EXTERN g_BasePointerForReturning:QWORD
```

The implementation of **Save\_VMXOFF\_State** :

```
Save_VMXOFF_State PROC PUBLIC
MOV g_StackPointerForReturning,rsp
MOV g_BasePointerForReturning,rbp
ret

Save_VMXOFF_State ENDP 
```

# **Returning to the previous state**

As we saved the current state, if we want to return to the previous state, we have to restore RSP & RBP and clear the stack position and eventually a RET instruction. (I Also add a VMXOFF because it should be executed before return.)

```
Restore_To_VMXOFF_State PROC PUBLIC

VMXOFF  ; turn it off before existing

MOV rsp, g_StackPointerForReturning
MOV rbp, g_BasePointerForReturning

; make rsp point to a correct return point
ADD rsp,8

; return True
xor rax,rax
mov rax,1

; return section

mov     rbx, [rsp+28h+8h]
mov     rsi, [rsp+28h+10h]
add     rsp, 020h
pop     rdi

ret

Restore_To_VMXOFF_State ENDP 
```

The "return section" is defined like this because I saw the return section of **LaunchVM** in IDA Pro.

![](../../assets/images/launch-vm-return.png)

LaunchVM Return Frame

# **VMLAUNCH**

Now it's time to executed the VMLAUNCH.

```

	__vmx_vmlaunch();

	// if VMLAUNCH succeed will never be here !
	ULONG64 ErrorCode = 0;
	__vmx_vmread(VM_INSTRUCTION_ERROR, &ErrorCode);
	__vmx_off();
	DbgPrint("[*] VMLAUNCH Error : 0x%llx\n", ErrorCode);
	DbgBreakPoint();
```

As the comment describes, if we VMLAUNCH succeed we'll never execute the other lines. If there is an error in the state of VMCS (which is a common problem) then we have to run VMREAD and read the error code from **VM\_INSTRUCTION\_ERROR** field of VMCS, also VMXOFF and print the error. **DbgBreakPoint** is just a debug breakpoint (int 3) and it can be useful only if you're working with a remote kernel Windbg Debugger. It's clear that you can't test it in your system because executing a **cc** in the kernel will freeze your system as long as there is no debugger to catch it so it's highly recommended to create a remote Kernel Debugging machine and test your codes.

Also, It can't be tested on a remote VMWare debugging (and other virtual machine debugging tools) because nested VMX is not supported in current Intel processors. By not supporting nested virtualization, I mean Intel doesn't have such thing "nested-virtualization" but it provides some hardware facilities so vendors can support and implement nested virtualization on their own. For example, you can test your driver on VMWare with nested virtualization (I also added some explanation about how to debug your hypervisor driver on VMWare to the first part.) However supporting Hyper-V nested virtualization needs extra things to be considered in implementing hypervisor so you can't test your driver on Hyper-V nested virtualization at least for this part, I'll explain about HyperV support on the 8th part.

I'll the drivers are tested on both physical machines and VMWare's nested virtualization.

Remember we're still in **LaunchVM** function and **\_\_vmx\_vmlaunch()** is the intrinsic function for VMLAUNCH & **\_\_vmx\_vmread** is for VMREAD instruction.

Now it's time to read some theories before configuring VMCS.

# **VMX Controls**

# **VM-Execution Controls**

In order to control our guest features, we have to set some fields in our VMCS. The following tables represent the Primary Processor-Based VM-Execution Controls and Secondary Processor-Based VM-Execution Controls.

![Primary-Processor-Based-VM-Execution-Controls](../../assets/images/Primary-Processor-Based-VM-Execution-Controls.png)

We define the above table like this:

#define CPU\_BASED\_VIRTUAL\_INTR\_PENDING        0x00000004
#define CPU\_BASED\_USE\_TSC\_OFFSETING           0x00000008
#define CPU\_BASED\_HLT\_EXITING                 0x00000080
#define CPU\_BASED\_INVLPG\_EXITING              0x00000200
#define CPU\_BASED\_MWAIT\_EXITING               0x00000400
#define CPU\_BASED\_RDPMC\_EXITING               0x00000800
#define CPU\_BASED\_RDTSC\_EXITING               0x00001000
#define CPU\_BASED\_CR3\_LOAD\_EXITING            0x00008000
#define CPU\_BASED\_CR3\_STORE\_EXITING           0x00010000
#define CPU\_BASED\_CR8\_LOAD\_EXITING            0x00080000
#define CPU\_BASED\_CR8\_STORE\_EXITING           0x00100000
#define CPU\_BASED\_TPR\_SHADOW                  0x00200000
#define CPU\_BASED\_VIRTUAL\_NMI\_PENDING         0x00400000
#define CPU\_BASED\_MOV\_DR\_EXITING              0x00800000
#define CPU\_BASED\_UNCOND\_IO\_EXITING           0x01000000
#define CPU\_BASED\_ACTIVATE\_IO\_BITMAP          0x02000000
#define CPU\_BASED\_MONITOR\_TRAP\_FLAG           0x08000000
#define CPU\_BASED\_ACTIVATE\_MSR\_BITMAP         0x10000000
#define CPU\_BASED\_MONITOR\_EXITING             0x20000000
#define CPU\_BASED\_PAUSE\_EXITING               0x40000000
#define CPU\_BASED\_ACTIVATE\_SECONDARY\_CONTROLS 0x80000000

In the earlier versions of VMX, there is nothing like Secondary Processor-Based VM-Execution Controls. Now if you want to use the secondary table you have to set the 31st bit of the first table otherwise it's like the secondary table field with zeros.

![Secondary-Processor-Based-VM-Execution-Controls](../../assets/images/Secondary-Processor-Based-VM-Execution-Controls.png)

The definition of the above table is this (we ignore some bits, you can define them if you want to use them in your hypervisor):

#define CPU\_BASED\_CTL2\_ENABLE\_EPT            0x2
#define CPU\_BASED\_CTL2\_RDTSCP                0x8
#define CPU\_BASED\_CTL2\_ENABLE\_VPID            0x20
#define CPU\_BASED\_CTL2\_UNRESTRICTED\_GUEST    0x80
#define CPU\_BASED\_CTL2\_ENABLE\_VMFUNC        0x2000

# **VM-entry Control Bits**

The VM-entry controls constitute a 32-bit vector that governs the basic operation of VM entries.

![VM-Entry-Controls](../../assets/images/VM-Entry-Controls.png)

// VM-entry Control Bits 
#define VM\_ENTRY\_IA32E\_MODE             0x00000200
#define VM\_ENTRY\_SMM                    0x00000400
#define VM\_ENTRY\_DEACT\_DUAL\_MONITOR     0x00000800
#define VM\_ENTRY\_LOAD\_GUEST\_PAT         0x00004000

# **VM-exit Control Bits**

The VM-exit controls constitute a 32-bit vector that governs the basic operation of VM exits.

![VM-Exit-Controls](../../assets/images/VM-Exit-Controls.png)

// VM-exit Control Bits 
#define VM\_EXIT\_IA32E\_MODE              0x00000200
#define VM\_EXIT\_ACK\_INTR\_ON\_EXIT        0x00008000
#define VM\_EXIT\_SAVE\_GUEST\_PAT          0x00040000
#define VM\_EXIT\_LOAD\_HOST\_PAT           0x00080000

# **PIN-Based Execution Control**

The pin-based VM-execution controls constitute a 32-bit vector that governs the handling of asynchronous events (for example: interrupts). We'll use it in the future parts, but for now let define it in our Hypervisor.

![Pin-Based-VM-Execution-Controls](../../assets/images/Pin-Based-VM-Execution-Controls.png)

```
#define PIN_BASED_VM_EXECUTION_CONTROLS_EXTERNAL_INTERRUPT        0x00000001
#define PIN_BASED_VM_EXECUTION_CONTROLS_NMI_EXITING               0x00000008
#define PIN_BASED_VM_EXECUTION_CONTROLS_VIRTUAL_NMI               0x00000020
#define PIN_BASED_VM_EXECUTION_CONTROLS_ACTIVE_VMX_TIMER          0x00000040
#define PIN_BASED_VM_EXECUTION_CONTROLS_PROCESS_POSTED_INTERRUPTS 0x00000080
```

# **Interruptibility State**

The guest-state area includes the following fields that characterize guest state but which do not correspond to processor registers:  
Activity state (32 bits). This field identifies the logical processor’s activity state. When a logical processor is executing instructions normally, it is in the active state. Execution of certain instructions and the occurrence of certain events may cause a logical processor to transition to an inactive state in which it ceases to execute instructions.  
The following activity states are defined:  
— 0: Active. The logical processor is executing instructions normally.

— 1: HLT. The logical processor is inactive because it executed the HLT instruction.  
— 2: Shutdown. The logical processor is inactive because it incurred a triple fault1 or some other serious error.  
— 3: Wait-for-SIPI. The logical processor is inactive because it is waiting for a startup-IPI (SIPI).  

• Interruptibility state (32 bits). The IA-32 architecture includes features that permit certain events to be blocked for a period of time. This field contains information about such blocking. Details and the format of this field are given in Table below.

![Interruptibility-State](../../assets/images/Interruptibility-State.png)

# **Configuring VMCS**

# **Gathering Machine state for VMCS**

In order to configure our Guest-State & Host-State we need to have details about current system state, e.g Global Descriptor Table Address, Interrupt Descriptor Table Address and Read all the Segment Registers.

These functions describe how all of these data can be gathered.

GDT Base :

Get\_GDT\_Base PROC
    LOCAL   gdtr\[10\]:BYTE
    sgdt    gdtr
    mov     rax, QWORD PTR gdtr\[2\]
    ret
Get\_GDT\_Base ENDP

CS segment register:

GetCs PROC
    mov     rax, cs
    ret
GetCs ENDP

DS segment register:

GetDs PROC
    mov     rax, ds
    ret
GetDs ENDP

ES segment register:

GetEs PROC
    mov     rax, es
    ret
GetEs ENDP

SS segment register:

GetSs PROC
    mov     rax, ss
    ret
GetSs ENDP

FS segment register:

GetFs PROC
    mov     rax, fs
    ret
GetFs ENDP

GS segment register:

GetGs PROC
    mov     rax, gs
    ret
GetGs ENDP

LDT:

GetLdtr PROC
    sldt    rax
    ret
GetLdtr ENDP

TR (task register):

GetTr PROC
    str rax
    ret
GetTr ENDP

Interrupt Descriptor Table:

Get\_IDT\_Base PROC
    LOCAL   idtr\[10\]:BYTE

    sidt    idtr
    mov     rax, QWORD PTR idtr\[2\]
    ret
Get\_IDT\_Base ENDP

GDT Limit:

Get\_GDT\_Limit PROC
    LOCAL   gdtr\[10\]:BYTE

    sgdt    gdtr
    mov     ax, WORD PTR gdtr\[0\]
    ret
Get\_GDT\_Limit ENDP

IDT Limit:

Get\_IDT\_Limit PROC
    LOCAL   idtr\[10\]:BYTE

    sidt    idtr
    mov     ax, WORD PTR idtr\[0\]
    ret
Get\_IDT\_Limit ENDP

RFLAGS:

Get\_RFLAGS PROC
    pushfq
    pop     rax
    ret
Get\_RFLAGS ENDP

# **Setting up VMCS**

Let's get down to business (We have a long way to go).

This section starts with defining a function called **Setup\_VMCS**.

```
BOOLEAN Setup_VMCS(IN PVirtualMachineState vmState, IN PEPTP EPTP);
```

This function is responsible for configuring all of the options related to VMCS and of course the Guest & Host state.

These task needs a special instruction called **"VMWRITE"**.

VMWRITE, writes the contents of a primary source operand (register or memory) to a specified field in a VMCS. In VMX root operation, the instruction writes to the current VMCS. If executed in VMX non-root operation, the instruction writes to the VMCS referenced by the VMCS link pointer field in the current VMCS.

The VMCS field is specified by the VMCS-field encoding contained in the register secondary source operand. 

The following **enum** contains most of the VMCS field need for **VMWRITE** & **VMREAD** instructions. (newer processors add newer fields.)

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

Ok, let's continue with our configuration.

The next step is configuring host Segment Registers.

```
	__vmx_vmwrite(HOST_ES_SELECTOR, GetEs() & 0xF8);
	__vmx_vmwrite(HOST_CS_SELECTOR, GetCs() & 0xF8);
	__vmx_vmwrite(HOST_SS_SELECTOR, GetSs() & 0xF8);
	__vmx_vmwrite(HOST_DS_SELECTOR, GetDs() & 0xF8);
	__vmx_vmwrite(HOST_FS_SELECTOR, GetFs() & 0xF8);
	__vmx_vmwrite(HOST_GS_SELECTOR, GetGs() & 0xF8);
	__vmx_vmwrite(HOST_TR_SELECTOR, GetTr() & 0xF8);
```

Keep in mind, those fields that start with **HOST\_** are related to the state in which the hypervisor sets whenever a VM-Exit occurs and those which start with **GUEST\_** are related to to the state in which the hypervisor sets for guest when a VMLAUNCH executed.

The purpose of **& 0xF8** is that Intel mentioned that the three less significant bits must be cleared and otherwise it leads to error when you execute VMLAUNCH with Invalid Host State error.

VMCS\_LINK\_POINTER should be 0xffffffffffffffff.

```
	// Setting the link pointer to the required value for 4KB VMCS.
	__vmx_vmwrite(VMCS_LINK_POINTER, ~0ULL);
```

The rest of this topic, intends to perform the VMX instructions in the current state of machine, so must of the guest and host configurations should be the same. In the future parts we'll configure them to a separate guest layout.

Let's configure GUEST\_IA32\_DEBUGCTL.

The **IA32\_DEBUGCTL** MSR provides bit field controls to enable debug trace interrupts, debug trace stores, trace messages enable, single stepping on branches, last branch record recording, and to control freezing of LBR stack.

In short : LBR is a mechanism that provides processor with some recording of registers.

We don't use them but let's configure them to the current machine's MSR\_IA32\_DEBUGCTL and you can see that **\_\_readmsr** is the intrinsic function for RDMSR.

```

	__vmx_vmwrite(GUEST_IA32_DEBUGCTL, __readmsr(MSR_IA32_DEBUGCTL) & 0xFFFFFFFF);
	__vmx_vmwrite(GUEST_IA32_DEBUGCTL_HIGH, __readmsr(MSR_IA32_DEBUGCTL) >> 32);
```

For configuring TSC you should modify the following values, I don't have a precise explanation about it, so let them be zeros.

Note that, values that we put Zero on them can be ignored and if you don't modify them, it's like you put zero on them.

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

This time, we'll configure Segment Registers and other GDT for our Host (When VM-Exit occurs).

```
	GdtBase = Get_GDT_Base();

	FillGuestSelectorData((PVOID)GdtBase, ES, GetEs());
	FillGuestSelectorData((PVOID)GdtBase, CS, GetCs());
	FillGuestSelectorData((PVOID)GdtBase, SS, GetSs());
	FillGuestSelectorData((PVOID)GdtBase, DS, GetDs());
	FillGuestSelectorData((PVOID)GdtBase, FS, GetFs());
	FillGuestSelectorData((PVOID)GdtBase, GS, GetGs());
	FillGuestSelectorData((PVOID)GdtBase, LDTR, GetLdtr());
	FillGuestSelectorData((PVOID)GdtBase, TR, GetTr());
```

**Get\_GDT\_Base** is defined above, in the process of gathering information for our VMCS.

**FillGuestSelectorData** is responsible for setting the GUEST selector, attributes, limit, and base for VMCS. It implemented as below :

```
void FillGuestSelectorData(
	__in PVOID GdtBase,
	__in ULONG Segreg,
	__in USHORT Selector
)
{
	SEGMENT_SELECTOR SegmentSelector = { 0 };
	ULONG            uAccessRights;

	GetSegmentDescriptor(&SegmentSelector, Selector, GdtBase);
	uAccessRights = ((PUCHAR)& SegmentSelector.ATTRIBUTES)[0] + (((PUCHAR)& SegmentSelector.ATTRIBUTES)[1] << 12);

	if (!Selector)
		uAccessRights |= 0x10000;

	__vmx_vmwrite(GUEST_ES_SELECTOR + Segreg * 2, Selector);
	__vmx_vmwrite(GUEST_ES_LIMIT + Segreg * 2, SegmentSelector.LIMIT);
	__vmx_vmwrite(GUEST_ES_AR_BYTES + Segreg * 2, uAccessRights);
	__vmx_vmwrite(GUEST_ES_BASE + Segreg * 2, SegmentSelector.BASE);

}
```

The function body for **GetSegmentDescriptor** :

```

BOOLEAN GetSegmentDescriptor(IN PSEGMENT_SELECTOR SegmentSelector, IN USHORT Selector, IN PUCHAR GdtBase)
{
	PSEGMENT_DESCRIPTOR SegDesc;

	if (!SegmentSelector)
		return FALSE;

	if (Selector & 0x4) {
		return FALSE;
	}

	SegDesc = (PSEGMENT_DESCRIPTOR)((PUCHAR)GdtBase + (Selector & ~0x7));

	SegmentSelector->SEL = Selector;
	SegmentSelector->BASE = SegDesc->BASE0 | SegDesc->BASE1 << 16 | SegDesc->BASE2 << 24;
	SegmentSelector->LIMIT = SegDesc->LIMIT0 | (SegDesc->LIMIT1ATTR1 & 0xf) << 16;
	SegmentSelector->ATTRIBUTES.UCHARs = SegDesc->ATTR0 | (SegDesc->LIMIT1ATTR1 & 0xf0) << 4;

	if (!(SegDesc->ATTR0 & 0x10)) { // LA_ACCESSED
		ULONG64 tmp;
		// this is a TSS or callgate etc, save the base high part
		tmp = (*(PULONG64)((PUCHAR)SegDesc + 8));
		SegmentSelector->BASE = (SegmentSelector->BASE & 0xffffffff) | (tmp << 32);
	}

	if (SegmentSelector->ATTRIBUTES.Fields.G) {
		// 4096-bit granularity is enabled for this segment, scale the limit
		SegmentSelector->LIMIT = (SegmentSelector->LIMIT << 12) + 0xfff;
	}

	return TRUE;
}
```

Also, there is another MSR called _**IA32\_KERNEL\_GS\_BASE**_ that is used to set the kernel GS base. whenever you run instructions like SYSCALL and enter to the ring 0, you need to change the current GS register and that can be done using [**SWAPGS**](https://www.felixcloutier.com/x86/SWAPGS.html). This instruction copies the content of **IA32\_KERNEL\_GS\_BASE** into the IA32**\_GS\_BASE and** now it's used in the kernel when you want to re-enter user-mode, you should change the user-mode GS Base. MSR\_FS\_BASE on the other hand, don't have a kernel base because it used in 32-Bit mode while you have a 64-bit (long mode) kernel.

The GUEST\_INTERRUPTIBILITY\_INFO & GUEST\_ACTIVITY\_STATE.

```
	__vmx_vmwrite(GUEST_INTERRUPTIBILITY_INFO, 0);
	__vmx_vmwrite(GUEST_ACTIVITY_STATE, 0);   //Active state 
```

Now we reach to the most important part of our VMCS and it's the configuration of CPU\_BASED\_VM\_EXEC\_CONTROL and SECONDARY\_VM\_EXEC\_CONTROL.

These fields enable and disable some important features of guest, e.g you can configure VMCS to cause a VM-Exit whenever an execution of **HLT** instruction detected (in Guest). Please check the **VM-Execution Controls** parts above for a detailed description.

```
	__vmx_vmwrite(CPU_BASED_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_HLT_EXITING | CPU_BASED_ACTIVATE_SECONDARY_CONTROLS, MSR_IA32_VMX_PROCBASED_CTLS));
	__vmx_vmwrite(SECONDARY_VM_EXEC_CONTROL, AdjustControls(CPU_BASED_CTL2_RDTSCP /* | CPU_BASED_CTL2_ENABLE_EPT*/, MSR_IA32_VMX_PROCBASED_CTLS2));
```

As you can see we set **CPU\_BASED\_HLT\_EXITING** that will cause the VM-Exit on **HLT** and activate secondary controls using:

```
CPU_BASED_ACTIVATE_SECONDARY_CONTROLS
```

In the secondary controls, we used **CPU\_BASED\_CTL2\_RDTSCP** and for now comment **CPU\_BASED\_CTL2\_ENABLE\_EPT** because we don't need to deal with EPT in this part. In the future parts, I describe using EPT or Extended Page Table that we configured in the [4th part](https://rayanfam.com/topics/hypervisor-from-scratch-part-4/).

The description of **PIN\_BASED\_VM\_EXEC\_CONTROL**, **VM\_EXIT\_CONTROLS** and **VM\_ENTRY\_CONTROLS** is available above but for now, let zero them.

```
	__vmx_vmwrite(PIN_BASED_VM_EXEC_CONTROL, AdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
	__vmx_vmwrite(VM_EXIT_CONTROLS, AdjustControls(VM_EXIT_IA32E_MODE | VM_EXIT_ACK_INTR_ON_EXIT, MSR_IA32_VMX_EXIT_CTLS));
	__vmx_vmwrite(VM_ENTRY_CONTROLS, AdjustControls(VM_ENTRY_IA32E_MODE, MSR_IA32_VMX_ENTRY_CTLS));
```

Also, the AdjustControls is defined like this:

```
ULONG AdjustControls(IN ULONG Ctl, IN ULONG Msr)
{
	MSR MsrValue = { 0 };

	MsrValue.Content = __readmsr(Msr);
	Ctl &= MsrValue.High;     /* bit == 0 in high word ==> must be zero */
	Ctl |= MsrValue.Low;      /* bit == 1 in low word  ==> must be one  */
	return Ctl;
}
```

Next step is setting Control Register for guest and host, we set them to the same value using intrinsic functions.

```
	__vmx_vmwrite(GUEST_CR0, __readcr0());
	__vmx_vmwrite(GUEST_CR3, __readcr3());
	__vmx_vmwrite(GUEST_CR4, __readcr4());

	__vmx_vmwrite(GUEST_DR7, 0x400);

	__vmx_vmwrite(HOST_CR0, __readcr0());
	__vmx_vmwrite(HOST_CR3, __readcr3());
	__vmx_vmwrite(HOST_CR4, __readcr4());
```

The next part is setting up IDT and GDT's Base and Limit for our guest.

```
	__vmx_vmwrite(GUEST_GDTR_BASE, Get_GDT_Base());
	__vmx_vmwrite(GUEST_IDTR_BASE, Get_IDT_Base());
	__vmx_vmwrite(GUEST_GDTR_LIMIT, Get_GDT_Limit());
	__vmx_vmwrite(GUEST_IDTR_LIMIT, Get_IDT_Limit());
```

Set the RFLAGS.

```
	__vmx_vmwrite(GUEST_RFLAGS, Get_RFLAGS());
```

If you want to use SYSENTER in your guest then you should configure the following MSRs. It's not important to set these values in x64 Windows because Windows doesn't support SYSENTER in x64 versions of Windows, It uses SYSCALL instead and for 32-bit processes, first change the current execution mode to long-mode (using [Heaven's Gate technique](http://rce.co/knockin-on-heavens-gate-dynamic-processor-mode-switching/)) but in 32-bit processors these fields are mandatory.

```
	__vmx_vmwrite(GUEST_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(GUEST_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	__vmx_vmwrite(GUEST_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_CS, __readmsr(MSR_IA32_SYSENTER_CS));
	__vmx_vmwrite(HOST_IA32_SYSENTER_EIP, __readmsr(MSR_IA32_SYSENTER_EIP));
	__vmx_vmwrite(HOST_IA32_SYSENTER_ESP, __readmsr(MSR_IA32_SYSENTER_ESP));
```

Don't forget to configure **HOST\_FS\_BASE**, **HOST\_GS\_BASE**, **HOST\_GDTR\_BASE**, **HOST\_IDTR\_BASE**, **HOST\_TR\_BASE**.

```
	GetSegmentDescriptor(&SegmentSelector, GetTr(), (PUCHAR)Get_GDT_Base());
	__vmx_vmwrite(HOST_TR_BASE, SegmentSelector.BASE);

	__vmx_vmwrite(HOST_FS_BASE, __readmsr(MSR_FS_BASE));
	__vmx_vmwrite(HOST_GS_BASE, __readmsr(MSR_GS_BASE));

	__vmx_vmwrite(HOST_GDTR_BASE, Get_GDT_Base());
	__vmx_vmwrite(HOST_IDTR_BASE, Get_IDT_Base());
```

The next important part is to set the RIP and RSP of the guest when a VMLAUNCH executes it starts with RIP you configured in this part and RIP and RSP of the host when a VM-Exit occurs. It's pretty clear that Host RIP should point to a function that is responsible for managing VMX Events based on return code and decide to execute a VMRESUME or turn off hypervisor using VMXOFF.

```
	// left here just for test
	__vmx_vmwrite(0, (ULONG64)VirtualGuestMemoryAddress);     //setup guest sp
	__vmx_vmwrite(GUEST_RIP, (ULONG64)VirtualGuestMemoryAddress);     //setup guest ip



	__vmx_vmwrite(HOST_RSP, ((ULONG64)vmState->VMM_Stack + VMM_STACK_SIZE - 1));
	__vmx_vmwrite(HOST_RIP, (ULONG64)VMExitHandler);
```

**HOST\_RSP** points to **VMM\_Stack** that we allocated above and HOST\_RIP points to **VMExitHandler** (an assembly written function that described below). **GUEST\_RIP** points to **VirtualGuestMemoryAddress** (the global variable that we configured during EPT initialization) and **GUEST\_RSP** to zero because we don't put any instruction that uses stack so for a real-world example it should point to writeable different address.

Setting these fields to a Host Address will not cause a problem as long as we have a same CR3 in our guest state so all the addresses are mapped exactly the same as the host.

Done ! Our VMCS is almost ready.

# **Checking VMCS Layout**

Unfortunatly, checking VMCS Layout is not as straight as the other parts, you have to control all the checklists described in **\[CHAPTER 26\] VM ENTRIES** from **Intel’s 64 and IA-32 Architectures Software Developer’s Manual** including the following sections:

- **26.2 CHECKS ON VMX CONTROLS AND HOST-STATE AREA**
- **26.3 CHECKING AND LOADING GUEST STATE** 
- **26.4 LOADING MSRS**
- **26.5 EVENT INJECTION**
- **26.6 SPECIAL FEATURES OF VM ENTRY**
- **26.7 VM-ENTRY FAILURES DURING OR AFTER LOADING GUEST STATE**
- **26.8 MACHINE-CHECK EVENTS DURING VM ENTRY**

The hardest part of this process is when you have no idea about the incorrect part of your VMCS layout or on the other hand when you miss something that eventually causes the failure.

This is because Intel just gives an error number without any further details about what's exactly wrong in your VMCS Layout.

The errors shown below.

![VM Errors](../../assets/images/vm-error.png)

To solve this problem, I created a user-mode application called **VmcsAuditor**. As its name describes, if you have any error and don't have any idea about solving the problem then it can be a choice.

Keep in mind that [VmcsAuditor](https://rayanfam.com/topics/vmcsauditor-a-bochs-based-hypervisor-layout-checker/) is a tool based on Bochs emulator support for VMX so all the checks come from Bochs and it's not a 100% reliable tool that solves all the problem as we don't know what exactly happening inside processor but it can be really useful and time saver.

The source code and executable files available on GitHub :

\[[https://github.com/SinaKarvandi/VMCS-Auditor](https://github.com/SinaKarvandi/VMCS-Auditor)\]  

Further description available [here](https://rayanfam.com/topics/vmcsauditor-a-bochs-based-hypervisor-layout-checker/).

# **VM-Exit Handler**

When our guest software exits and give the handle back to the host, its VM-exit reasons can be defined in the following definitions.

#define EXIT\_REASON\_EXCEPTION\_NMI       0
#define EXIT\_REASON\_EXTERNAL\_INTERRUPT  1
#define EXIT\_REASON\_TRIPLE\_FAULT        2
#define EXIT\_REASON\_INIT                3
#define EXIT\_REASON\_SIPI                4
#define EXIT\_REASON\_IO\_SMI              5
#define EXIT\_REASON\_OTHER\_SMI           6
#define EXIT\_REASON\_PENDING\_VIRT\_INTR   7
#define EXIT\_REASON\_PENDING\_VIRT\_NMI    8
#define EXIT\_REASON\_TASK\_SWITCH         9
#define EXIT\_REASON\_CPUID               10
#define EXIT\_REASON\_GETSEC              11
#define EXIT\_REASON\_HLT                 12
#define EXIT\_REASON\_INVD                13
#define EXIT\_REASON\_INVLPG              14
#define EXIT\_REASON\_RDPMC               15
#define EXIT\_REASON\_RDTSC               16
#define EXIT\_REASON\_RSM                 17
#define EXIT\_REASON\_VMCALL              18
#define EXIT\_REASON\_VMCLEAR             19
#define EXIT\_REASON\_VMLAUNCH            20
#define EXIT\_REASON\_VMPTRLD             21
#define EXIT\_REASON\_VMPTRST             22
#define EXIT\_REASON\_VMREAD              23
#define EXIT\_REASON\_VMRESUME            24
#define EXIT\_REASON\_VMWRITE             25
#define EXIT\_REASON\_VMXOFF              26
#define EXIT\_REASON\_VMXON               27
#define EXIT\_REASON\_CR\_ACCESS           28
#define EXIT\_REASON\_DR\_ACCESS           29
#define EXIT\_REASON\_IO\_INSTRUCTION      30
#define EXIT\_REASON\_MSR\_READ            31
#define EXIT\_REASON\_MSR\_WRITE           32
#define EXIT\_REASON\_INVALID\_GUEST\_STATE 33
#define EXIT\_REASON\_MSR\_LOADING         34
#define EXIT\_REASON\_MWAIT\_INSTRUCTION   36
#define EXIT\_REASON\_MONITOR\_TRAP\_FLAG   37
#define EXIT\_REASON\_MONITOR\_INSTRUCTION 39
#define EXIT\_REASON\_PAUSE\_INSTRUCTION   40
#define EXIT\_REASON\_MCE\_DURING\_VMENTRY  41
#define EXIT\_REASON\_TPR\_BELOW\_THRESHOLD 43
#define EXIT\_REASON\_APIC\_ACCESS         44
#define EXIT\_REASON\_ACCESS\_GDTR\_OR\_IDTR 46
#define EXIT\_REASON\_ACCESS\_LDTR\_OR\_TR   47
#define EXIT\_REASON\_EPT\_VIOLATION       48
#define EXIT\_REASON\_EPT\_MISCONFIG       49
#define EXIT\_REASON\_INVEPT              50
#define EXIT\_REASON\_RDTSCP              51
#define EXIT\_REASON\_VMX\_PREEMPTION\_TIMER\_EXPIRED     52
#define EXIT\_REASON\_INVVPID             53
#define EXIT\_REASON\_WBINVD              54
#define EXIT\_REASON\_XSETBV              55
#define EXIT\_REASON\_APIC\_WRITE          56
#define EXIT\_REASON\_RDRAND              57
#define EXIT\_REASON\_INVPCID             58
#define EXIT\_REASON\_RDSEED              61
#define EXIT\_REASON\_PML\_FULL            62
#define EXIT\_REASON\_XSAVES              63
#define EXIT\_REASON\_XRSTORS             64
#define EXIT\_REASON\_PCOMMIT             65

VMX Exit handler should be a pure assembly function because calling a compiled function needs some preparing and some register modification and the most important thing in VMX Handler is saving the registers state so that you can continue, other time.

I create a sample function for saving the registers and returning the state but in this function we call another C function.

```
PUBLIC VMExitHandler


EXTERN MainVMExitHandler:PROC
EXTERN VM_Resumer:PROC

.code _text

VMExitHandler PROC

    push r15
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8        
    push rdi
    push rsi
    push rbp
    push rbp	; rsp
    push rbx
    push rdx
    push rcx
    push rax	


	mov rcx, rsp		;GuestRegs
	sub	rsp, 28h

	;rdtsc
	call	MainVMExitHandler
	add	rsp, 28h	


	pop rax
    pop rcx
    pop rdx
    pop rbx
    pop rbp		; rsp
    pop rbp
    pop rsi
    pop rdi 
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15


	sub rsp, 0100h ; to avoid error in future functions
	JMP VM_Resumer
	

VMExitHandler ENDP

end
```

The main VM-Exit handler is a switch-case function that has different decisions over the VMCS **VM\_EXIT\_REASON** and **EXIT\_QUALIFICATION**.

In this part, we're just performing an action over **EXIT\_REASON\_HLT** and just print the result and restore the previous state.

From the following code, you can clearly see what event cause the VM-exit. Just keep in mind that some reasons only lead to VM-Exit if the VMCS's control execution fields (described above) allows for it. For instance, the execution of HLT in guest software will cause VM-Exit if the 7th bit of the Primary Processor-Based VM-Execution Controls allows it.

```
VOID MainVMExitHandler(PGUEST_REGS GuestRegs)
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

		// DbgBreakPoint();

		// that's enough for now ;)
		Restore_To_VMXOFF_State();

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

# **Resume to next instruction**

If a VM-Exit occurs (e.g the guest executed a CPUID instruction), the guest RIP remains constant and it's up to you to change the Guest RIP or not so if you don't have a special function for managing this situation then you execute a VMRESUME and it's like an infinite loop of executing CPUID and VMRESUME because you didn't change the RIP.

In order to solve this problem you have to read a VMCS field called **VM\_EXIT\_INSTRUCTION\_LEN** that stores the length of the instruction that caused the VM-Exit so you have to first, read the GUEST current RIP, second the **VM\_EXIT\_INSTRUCTION\_LEN** and third add it to GUEST RIP. Now your GUEST RIP points to the next instruction and you're good to go.

The following function is for this purpose.

```
VOID ResumeToNextInstruction(VOID)
{
	PVOID ResumeRIP = NULL;
	PVOID CurrentRIP = NULL;
	ULONG ExitInstructionLength = 0;

	__vmx_vmread(GUEST_RIP, &CurrentRIP);
	__vmx_vmread(VM_EXIT_INSTRUCTION_LEN, &ExitInstructionLength);

	ResumeRIP = (PCHAR)CurrentRIP + ExitInstructionLength;

	__vmx_vmwrite(GUEST_RIP, (ULONG64)ResumeRIP);
}
```

# **VMRESUME**

VMRESUME is like VMLAUNCH but it's used in order to resume the Guest.

- VMLAUNCH fails if the launch state of current VMCS is not “clear”. If the instruction is successful, it sets the launch state to “launched.”
- VMRESUME fails if the launch state of the current VMCS is not “launched.”

So it's clear that if you executed VMLAUNCH before, then you can't use it anymore to resume to the Guest code and in this condition VMRESUME is used.

The following code is the implementation of VMRESUME.

VOID VM\_Resumer(VOID)
{

	\_\_vmx\_vmresume();

	// if VMRESUME succeed will never be here !

	ULONG64 ErrorCode = 0;
	\_\_vmx\_vmread(VM\_INSTRUCTION\_ERROR, &ErrorCode);
	\_\_vmx\_off();
	DbgPrint("\[\*\] VMRESUME Error : 0x%llx\\n", ErrorCode);

	// It's such a bad error because we don't where to go !
	// prefer to break
	DbgBreakPoint();
}

# **Let's Test it !**

Well, we have done with configuration and now its time to run our driver using OSR Driver Loader, as always, first you should disable driver signature enforcement then run your driver.

![](../../assets/images/hlt-execution.png)

As you can see from the above picture (in launching VM area), first we set the current logical processor to 0, next we clear our VMCS status using VMCLEAR instruction then we set up our VMCS layout and finally execute a VMLAUNCH instruction.

Now, our guest code is executed and as we configured our VMCS to exit on the execution of **HLT** **(CPU\_BASED\_HLT\_EXITING)**, so it's successfully executed and our VM-EXIT handler function called, then it calls the main VM-Exit handler and as the VMCS exit reason is **0xc (EXIT\_REASON\_HLT)**, our VM-Exit handler detects an execution of **HLT** in guest and now it captures the execution.

After that our machine state saving mechanism executed and we successfully turn off hypervisor using VMXOFF and return to the first caller with a successful (RAX = 1) status.

The sixth part is also available [here](https://rayanfam.com/topics/hypervisor-from-scratch-part-6/).

That's it! Wasn't it easy ?!

![:)](../../assets/images/anime.jpg)

# **Conclusion**

In this part, we get familiar with configuring Virtual Machine Control Structure and finally run our guest code. The future parts would be an enhancement to this configuration like entering **protected-mode,** **interrupt injection**, **page modification logging,** **virtualizing the current machine** and so on thus making sure to visit the blog more frequently for future parts and if you have any question or problem you can use the comments section below.

Thanks for reading!

# **References**

\[1\] Vol 3C - Chapter 24 – (VIRTUAL MACHINE CONTROL STRUCTURES ([https://software.intel.com/en-us/articles/intel-sdm](https://software.intel.com/en-us/articles/intel-sdm))

\[2\] Vol 3C - Chapter 26 – (VM ENTRIES) ([https://software.intel.com/en-us/articles/intel-sdm](https://software.intel.com/en-us/articles/intel-sdm))

\[3\] Segmentation ([https://wiki.osdev.org/Segmentation](https://wiki.osdev.org/Segmentation))

\[4\] x86 memory segmentation ([https://en.wikipedia.org/wiki/X86\_memory\_segmentation](https://en.wikipedia.org/wiki/X86_memory_segmentation))

\[5\] VmcsAuditor – A Bochs-Based Hypervisor Layout Checker ([https://rayanfam.com/topics/vmcsauditor-a-bochs-based-hypervisor-layout-checker/](https://rayanfam.com/topics/vmcsauditor-a-bochs-based-hypervisor-layout-checker/))

\[6\] Rohaaan/Hypervisor For Beginners ([https://github.com/rohaaan/hypervisor-for-beginners](https://github.com/rohaaan/hypervisor-for-beginners))

\[7\] SWAPGS — Swap GS Base Register ([https://www.felixcloutier.com/x86/SWAPGS.html](https://www.felixcloutier.com/x86/SWAPGS.html))

\[8\] Knockin' on Heaven's Gate - Dynamic Processor Mode Switching ([](http://rce.co/knockin-on-heavens-gate-dynamic-processor-mode-switching/)[http://rce.co/knockin-on-heavens-gate-dynamic-processor-mode-switching/](http://rce.co/knockin-on-heavens-gate-dynamic-processor-mode-switching/))
