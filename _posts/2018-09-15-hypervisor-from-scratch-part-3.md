---
title: "Hypervisor From Scratch – Part 3: Setting up Our First Virtual Machine"
date: "2018-09-15"
categories: 
  - "cpu"
  - "hypervisor"
  - "tutorials"
tags: 
  - "hypervisor"
  - "creating-vmm"
  - "initiating-vmx-operation"
  - "irp_mj_device_control"
  - "method_buffered"
  - "method_in_direct"
  - "method_niether"
  - "method_out_direct"
  - "vmcs"
  - "vmcs-region"
  - "vmm"
  - "vmx-operation"
  - "vmxon"
  - "vmxon-region"
coverImage: "../../assets/images/hvfs-part3.png"
author:
  name: Mohammad Sina Karvandi
  link: https://twitter.com/Intel80x86
---

![](../../assets/images/hvfs-part3.png)

## **Introduction**

This is the third part of the tutorial "**Hypervisor From Scratch**". You may have noticed that the previous parts have steadily been getting more complicated. This part should teach you how to get started with creating your own VMM, we go to demonstrate how to interact with the VMM from Windows User-mode (**IOCTL Dispatcher**), then we solve the problems with the affinity and running code in a special core. Finally, we get familiar with initializing **VMXON Regions** and **VMCS Regions** then we load our hypervisor regions into each core and implement our custom functions to work with hypervisor instruction and many more things related to Virtual-Machine Control Data Structures (**VMCS**).

Some of the implementations derived from [HyperBone](https://github.com/DarthTon/HyperBone) (Minimalistic VT-X hypervisor with hooks) and [HyperPlatform](https://github.com/tandasat/HyperPlatform) by [Satoshi Tanda](https://github.com/tandasat/HyperPlatform) and [hvpp](https://github.com/wbenny/hvpp) which is great work by my friend [Petr Beneš](https://twitter.com/PetrBenes) the person who really helped me creating these series.

The full source code of this tutorial is available on :

\[[https://github.com/SinaKarvandi/Hypervisor-From-Scratch](https://github.com/SinaKarvandi/Hypervisor-From-Scratch)\]

## **Interacting with VMM Driver from User-Mode**

The most important function in IRP MJ functions for us is **DrvIOCTLDispatcher (IRP\_MJ\_DEVICE\_CONTROL)** and that's because this function can be called from user-mode with a special IOCTL number, it means you can have a special code in your driver and implement a special functionality corresponding this code, then by knowing the code (from user-mode) you can ask your driver to perform your request, so you can imagine that how useful this function would be.

Now let's implement our functions for dispatching IOCTL code and print it from our kernel-mode driver.

As long as I know, there are several methods by which you can dispatch IOCTL e.g **METHOD\_BUFFERED, METHOD\_NIETHER, METHOD\_IN\_DIRECT, METHOD\_OUT\_DIRECT**. These methods should be followed by the user-mode caller (the difference are in the place where buffers transfer between user-mode and kernel-mode or vice versa), I just copy the implementations with some minor modification form [Microsoft's Windows Driver Samples](https://github.com/Microsoft/Windows-driver-samples), you can see the full code for [user-mode](https://github.com/Microsoft/Windows-driver-samples/blob/master/general/ioctl/wdm/exe/testapp.c) and [kernel-mode](https://github.com/Microsoft/Windows-driver-samples/blob/master/general/ioctl/wdm/sys/sioctl.c).

Imagine we have the following IOCTL codes:

//
// Device type           -- in the "User Defined" range."
//
#define SIOCTL\_TYPE 40000

//
// The IOCTL function codes from 0x800 to 0xFFF are for customer use.
//
#define IOCTL\_SIOCTL\_METHOD\_IN\_DIRECT \\
    CTL\_CODE( SIOCTL\_TYPE, 0x900, METHOD\_IN\_DIRECT, FILE\_ANY\_ACCESS  )

#define IOCTL\_SIOCTL\_METHOD\_OUT\_DIRECT \\
    CTL\_CODE( SIOCTL\_TYPE, 0x901, METHOD\_OUT\_DIRECT , FILE\_ANY\_ACCESS  )

#define IOCTL\_SIOCTL\_METHOD\_BUFFERED \\
    CTL\_CODE( SIOCTL\_TYPE, 0x902, METHOD\_BUFFERED, FILE\_ANY\_ACCESS  )

#define IOCTL\_SIOCTL\_METHOD\_NEITHER \\
    CTL\_CODE( SIOCTL\_TYPE, 0x903, METHOD\_NEITHER , FILE\_ANY\_ACCESS  )

There is a convention for defining IOCTLs as it mentioned [here](https://www.codeproject.com/Articles/9575/Driver-Development-Part-2-Introduction-to-Implemen),

The IOCTL is a 32-bit number. The first two low bits define the “transfer type” which can be METHOD\_OUT\_DIRECT, METHOD\_IN\_DIRECT, METHOD\_BUFFERED or METHOD\_NEITHER.

The next set of bits from 2 to 13 define the “Function Code”. The high bit is referred to as the “custom bit”. This is used to determine user-defined IOCTLs versus system defined. This means that function codes 0x800 and greater are customs defined similarly to how WM\_USER works for Windows Messages.

The next two bits define the access required to issue the IOCTL. This is how the I/O Manager can reject IOCTL requests if the handle has not been opened with the correct access. The access types are such as FILE\_READ\_DATA and FILE\_WRITE\_DATA for example.

The last bits represent the device type the IOCTLs are written for. The high bit again represents user-defined values.

In IOCTL Dispatcher, The "**Parameters.DeviceIoControl .IoControlCode**" of the **IO\_STACK\_LOCATION** contains the IOCTL code being invoked.

For **METHOD\_IN\_DIRECT** and **METHOD\_OUT\_DIRECT**, the difference between IN and OUT is that with IN, you can use the output buffer to pass in data while the OUT is only used to return data.

The **METHOD\_BUFFERED** is a buffer that the data is copied from this buffer. The buffer is created as the larger of the two sizes, the input or output buffer. Then the read buffer is copied to this new buffer. Before you return, you simply copy the return data into the same buffer. The return value is put into the **IO\_STATUS\_BLOCK** and the I/O Manager copies the data into the output buffer. The **METHOD\_NEITHER** is the same.

Ok, let's see an example :

First, we declare all our needed variable.

Note that the **PAGED\_CODE** macro ensures that the calling thread is running at an IRQL that is low enough to permit paging.

NTSTATUS DrvIOCTLDispatcher( PDEVICE\_OBJECT DeviceObject, PIRP Irp)
{
	PIO\_STACK\_LOCATION  irpSp;// Pointer to current stack location
	NTSTATUS            ntStatus = STATUS\_SUCCESS;// Assume success
	ULONG               inBufLength; // Input buffer length
	ULONG               outBufLength; // Output buffer length
	PCHAR               inBuf, outBuf; // pointer to Input and output buffer
	PCHAR               data = "This String is from Device Driver !!!";
	size\_t              datalen = strlen(data) + 1;//Length of data including null
	PMDL                mdl = NULL;
	PCHAR               buffer = NULL;

	UNREFERENCED\_PARAMETER(DeviceObject);

	PAGED\_CODE();

	irpSp = IoGetCurrentIrpStackLocation(Irp);
	inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	if (!inBufLength || !outBufLength)
	{
		ntStatus = STATUS\_INVALID\_PARAMETER;
		goto End;
	}

...

Then we have to use switch-case through the IOCTLs (Just copy buffers and show it from **DbgPrint()**).

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL\_SIOCTL\_METHOD\_BUFFERED:

		DbgPrint("Called IOCTL\_SIOCTL\_METHOD\_BUFFERED\\n");
		PrintIrpInfo(Irp);
		inBuf = Irp->AssociatedIrp.SystemBuffer;
		outBuf = Irp->AssociatedIrp.SystemBuffer;
		DbgPrint("\\tData from User :");
		DbgPrint(inBuf);
		PrintChars(inBuf, inBufLength);
		RtlCopyBytes(outBuf, data, outBufLength);
		DbgPrint(("\\tData to User : "));
		PrintChars(outBuf, datalen);
		Irp->IoStatus.Information = (outBufLength < datalen ? outBufLength : datalen);
		break;

...

The **PrintIrpInfo** is like this :

VOID PrintIrpInfo(PIRP Irp)
{
	PIO\_STACK\_LOCATION  irpSp;
	irpSp = IoGetCurrentIrpStackLocation(Irp);

	PAGED\_CODE();

	DbgPrint("\\tIrp->AssociatedIrp.SystemBuffer = 0x%p\\n",
		Irp->AssociatedIrp.SystemBuffer);
	DbgPrint("\\tIrp->UserBuffer = 0x%p\\n", Irp->UserBuffer);
	DbgPrint("\\tirpSp->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\\n",
		irpSp->Parameters.DeviceIoControl.Type3InputBuffer);
	DbgPrint("\\tirpSp->Parameters.DeviceIoControl.InputBufferLength = %d\\n",
		irpSp->Parameters.DeviceIoControl.InputBufferLength);
	DbgPrint("\\tirpSp->Parameters.DeviceIoControl.OutputBufferLength = %d\\n",
		irpSp->Parameters.DeviceIoControl.OutputBufferLength);
	return;
}

Even though you can see all the implementations in my GitHub but that's enough, in the rest of the post we only use the **IOCTL\_SIOCTL\_METHOD\_BUFFERED** method.

Now from user-mode and if you remember from the [previous part](https://rayanfam.com/topics/hypervisor-from-scratch-part-2/) where we create a handle (HANDLE) using **CreateFile**, now we can use the **DeviceIoControl** to call **DrvIOCTLDispatcher** (**IRP\_MJ\_DEVICE\_CONTROL**) along with our parameters from user-mode.

	char OutputBuffer\[1000\];
	char InputBuffer\[1000\];
	ULONG bytesReturned;
	BOOL Result;

	StringCbCopy(InputBuffer, sizeof(InputBuffer),
		"This String is from User Application; using METHOD\_BUFFERED");

	printf("\\nCalling DeviceIoControl METHOD\_BUFFERED:\\n");

	memset(OutputBuffer, 0, sizeof(OutputBuffer));

	Result = DeviceIoControl(handle,
		(DWORD)IOCTL\_SIOCTL\_METHOD\_BUFFERED,
		&InputBuffer,
		(DWORD)strlen(InputBuffer) + 1,
		&OutputBuffer,
		sizeof(OutputBuffer),
		&bytesReturned,
		NULL
	);

	if (!Result)
	{
		printf("Error in DeviceIoControl : %d", GetLastError());
		return 1;

	}
	printf("    OutBuffer (%d): %s\\n", bytesReturned, OutputBuffer);

There is an old, yet great topic [here](https://www.codeproject.com/Articles/9575/Driver-Development-Part-2-Introduction-to-Implemen) which describes the different types of IOCT dispatching.

I think we're done with WDK basics, its time to see how we can use Windows in order to build our VMM.

![](../../assets/images/Sad-Anime.jpg)

* * *

## **Per Processor Configuration and Setting Affinity**

Affinity to a special logical processor is one of the main things that we should consider when working with the hypervisor.

Unfortunately, in Windows, there is nothing like **on\_each\_cpu** (like it is in Linux Kernel Module) so we have to change our affinity manually in order to run on each logical processor. In my **Intel Core i7 6820HQ** I have 4 physical cores and each core can run 2 threads simultaneously (due to the presence of hyper-threading) thus we have 8 logical processors and of course 8 sets of all the registers (including general purpose registers and MSR registers) so we should configure our VMM to work on 8 logical processors.

To get the count of logical processors you can use **KeQueryActiveProcessorCount(0)**, then we should pass a **KAFFINITY** mask to the **KeSetSystemAffinityThread** which sets the system affinity of the current thread.

**KAFFINITY** mask can be configured using a simple power function :

int ipow(int base, int exp) {
	int result = 1;
	for (;;)
	{
		if ( exp & 1)
		{
			result \*= base;
		}
		exp >>= 1;
		if (!exp)
		{
			break;
		}
		base \*= base;
	}
	return result;
}

then we should use the following code in order to change the affinity of the processor and run our code in all the logical cores separately:

	KAFFINITY kAffinityMask;
	for (size\_t i = 0; i < KeQueryActiveProcessorCount(0); i++)
	{
		kAffinityMask = ipow(2, i);
		KeSetSystemAffinityThread(kAffinityMask);
		DbgPrint("=====================================================");
		DbgPrint("Current thread is executing in %d th logical processor.",i);
		// Put you function here !

	}

## **Conversion between the physical and virtual addresses**

VMXON Regions and VMCS Regions (see below) use physical address as the operand to VMXON and VMPTRLD instruction so we should create functions to convert Virtual Address to Physical address:

UINT64 VirtualAddress\_to\_PhysicallAddress(void\* va)
{
	return MmGetPhysicalAddress(va).QuadPart;
}

And as long as we can't directly use physical addresses for our modifications in protected-mode then we have to convert physical address to virtual address.

UINT64 PhysicalAddress\_to\_VirtualAddress(UINT64 pa)
{
	PHYSICAL\_ADDRESS PhysicalAddr;
	PhysicalAddr.QuadPart = pa;

	return MmGetVirtualForPhysical(PhysicalAddr);
}

## **Query about Hypervisor from the kernel**

In the previous part, we query about the presence of hypervisor from user-mode, but we should consider checking about hypervisor from kernel-mode too. This reduces the possibility of getting kernel errors in the future or there might be something that disables the hypervisor using the **lock bit**, by the way, the following code checks **IA32\_FEATURE\_CONTROL** MSR (MSR address 3AH) to see if the **lock bit** is set or not.

BOOLEAN Is\_VMX\_Supported()
{
	CPUID data = { 0 };

	// VMX bit
	\_\_cpuid((int\*)&data, 1);
	if ((data.ecx & (1 << 5)) == 0)
		return FALSE;

	IA32\_FEATURE\_CONTROL\_MSR Control = { 0 };
	Control.All = \_\_readmsr(MSR\_IA32\_FEATURE\_CONTROL);

	// BIOS lock check
	if (Control.Fields.Lock == 0)
	{
		Control.Fields.Lock = TRUE;
		Control.Fields.EnableVmxon = TRUE;
		\_\_writemsr(MSR\_IA32\_FEATURE\_CONTROL, Control.All);
	}
	else if (Control.Fields.EnableVmxon == FALSE)
	{
		DbgPrint("\[\*\] VMX locked off in BIOS");
		return FALSE;
	}

	return TRUE;
}

The structures used in the above function declared like this:

typedef union \_IA32\_FEATURE\_CONTROL\_MSR
{
	ULONG64 All;
	struct
	{
		ULONG64 Lock : 1;                // \[0\]
		ULONG64 EnableSMX : 1;           // \[1\]
		ULONG64 EnableVmxon : 1;         // \[2\]
		ULONG64 Reserved2 : 5;           // \[3-7\]
		ULONG64 EnableLocalSENTER : 7;   // \[8-14\]
		ULONG64 EnableGlobalSENTER : 1;  // \[15\]
		ULONG64 Reserved3a : 16;         //
		ULONG64 Reserved3b : 32;         // \[16-63\]
	} Fields;
} IA32\_FEATURE\_CONTROL\_MSR, \*PIA32\_FEATURE\_CONTROL\_MSR;

typedef struct \_CPUID
{
	int eax;
	int ebx;
	int ecx;
	int edx;
} CPUID, \*PCPUID;

## **VMXON Region**

Before executing VMXON, software should allocate a naturally aligned 4-KByte region of memory that a logical processor may use to support VMX operation. This region is called the **VMXON region**. The address of the **VMXON region** (the VMXON pointer) is provided in an operand to VMXON.

A VMM can (should) use different VMXON Regions for each logical processor otherwise the behavior is "undefined".

Note: The first processors to support VMX operation require that the following bits be 1 in VMX operation: CR0.PE, CR0.NE, CR0.PG, and CR4.VMXE. The restrictions on CR0.PE and CR0.PG imply that VMX operation is supported only in paged protected mode (including IA-32e mode). Therefore, the guest software cannot be run in unpaged protected mode or in real-address mode. 

Now that we are configuring the hypervisor, we should have a global variable that describes the state of our virtual machine, I create the following structure for this purpose, currently, we just have two fields (**VMXON\_REGION** and **VMCS\_REGION**) but we will add new fields in this structure in the future parts.

typedef struct \_VirtualMachineState
{
	UINT64 VMXON\_REGION;                        // VMXON region
	UINT64 VMCS\_REGION;                         // VMCS region
} VirtualMachineState, \*PVirtualMachineState;

And of course a global variable:

extern PVirtualMachineState vmState;

I create the following function (in memory.c) to allocate VMXON Region and execute VMXON instruction using the allocated region's pointer.

BOOLEAN Allocate\_VMXON\_Region(IN PVirtualMachineState vmState)
{
	// at IRQL > DISPATCH\_LEVEL memory allocation routines don't work
	if (KeGetCurrentIrql() > DISPATCH\_LEVEL)
		KeRaiseIrqlToDpcLevel();

	PHYSICAL\_ADDRESS PhysicalMax = { 0 };
	PhysicalMax.QuadPart = MAXULONG64;

	int VMXONSize = 2 \* VMXON\_SIZE;
	BYTE\* Buffer = MmAllocateContiguousMemory(VMXONSize + ALIGNMENT\_PAGE\_SIZE, PhysicalMax);  // Allocating a 4-KByte Contigous Memory region

	PHYSICAL\_ADDRESS Highest = { 0 }, Lowest = { 0 };
	Highest.QuadPart = ~0;

	//BYTE\* Buffer = MmAllocateContiguousMemorySpecifyCache(VMXONSize + ALIGNMENT\_PAGE\_SIZE, Lowest, Highest, Lowest, MmNonCached);
	
	if (Buffer == NULL) {
		DbgPrint("\[\*\] Error : Couldn't Allocate Buffer for VMXON Region.");
		return FALSE;// ntStatus = STATUS\_INSUFFICIENT\_RESOURCES;
	}
	UINT64 PhysicalBuffer = VirtualAddress\_to\_PhysicallAddress(Buffer);

	// zero-out memory 
	RtlSecureZeroMemory(Buffer, VMXONSize + ALIGNMENT\_PAGE\_SIZE);
	UINT64 alignedPhysicalBuffer = (BYTE\*)((ULONG\_PTR)(PhysicalBuffer + ALIGNMENT\_PAGE\_SIZE - 1) &~(ALIGNMENT\_PAGE\_SIZE - 1));

	UINT64 alignedVirtualBuffer = (BYTE\*)((ULONG\_PTR)(Buffer + ALIGNMENT\_PAGE\_SIZE - 1) &~(ALIGNMENT\_PAGE\_SIZE - 1));

	DbgPrint("\[\*\] Virtual allocated buffer for VMXON at %llx", Buffer);
	DbgPrint("\[\*\] Virtual aligned allocated buffer for VMXON at %llx", alignedVirtualBuffer);
	DbgPrint("\[\*\] Aligned physical buffer allocated for VMXON at %llx", alignedPhysicalBuffer);

	// get IA32\_VMX\_BASIC\_MSR RevisionId

	IA32\_VMX\_BASIC\_MSR basic = { 0 };

	basic.All = \_\_readmsr(MSR\_IA32\_VMX\_BASIC);

	DbgPrint("\[\*\] MSR\_IA32\_VMX\_BASIC (MSR 0x480) Revision Identifier %llx", basic.Fields.RevisionIdentifier);

	//\* (UINT64 \*)alignedVirtualBuffer  = 04;

	//Changing Revision Identifier
	\*(UINT64 \*)alignedVirtualBuffer = basic.Fields.RevisionIdentifier;

	int status = \_\_vmx\_on(&alignedPhysicalBuffer);
	if (status)
	{
		DbgPrint("\[\*\] VMXON failed with status %d\\n", status);
		return FALSE;
	}

	vmState->VMXON\_REGION = alignedPhysicalBuffer;

	return TRUE;
}

Let's explain the  above function,

	// at IRQL > DISPATCH\_LEVEL memory allocation routines don't work
	if (KeGetCurrentIrql() > DISPATCH\_LEVEL)
		KeRaiseIrqlToDpcLevel();

This code is for changing current **IRQL Level** to **DISPATCH\_LEVEL** but we can ignore this code as long as we use:

```
MmAllocateContiguousMemory
```

but if you want to use another type of memory for your VMXON region you should use  

```
MmAllocateContiguousMemorySpecifyCache
```

Other types of memory you can use can be found [here](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ne-wdm-_memory_caching_type).

Note that to ensure proper behavior in VMX operation, you should maintain the VMCS region and related structures in writeback cacheable memory. Alternatively, you may map any of these regions or structures with the UC memory type. Doing so is strongly discouraged unless necessary as it will cause the performance of transitions using those structures to suffer significantly.

Write-back is a storage method in which data is written into the cache every time a change occurs, but is written into the corresponding location in main memory only at specified intervals or under certain conditions. Being cachable or not cachable can be determined from the **cache disable bit** in paging structures (PTE).

By the way, we should allocate 8192 Byte because there is no guarantee that Windows allocates the aligned memory so we can find a piece of 4096 Bytes aligned in 8196 Bytes. (by aligning I mean, the physical address should be divisible by 4096 without any reminder).

In my experience, the **MmAllocateContiguousMemory** allocation is always aligned, maybe it is because every page in PFN are allocated by 4096 bytes and as long as we need 4096 Bytes, then it's aligned.

If you are interested in Page Frame Number (PFN) then you can read [Inside Windows Page Frame Number (PFN) – Part 1](https://rayanfam.com/topics/inside-windows-page-frame-number-part1/) and [Inside Windows Page Frame Number (PFN) – Part 2](https://rayanfam.com/topics/inside-windows-page-frame-number-part2/).

	PHYSICAL\_ADDRESS PhysicalMax = { 0 };
	PhysicalMax.QuadPart = MAXULONG64;

	int VMXONSize = 2 \* VMXON\_SIZE;
	BYTE\* Buffer = MmAllocateContiguousMemory(VMXONSize, PhysicalMax);  // Allocating a 4-KByte Contigous Memory region
	if (Buffer == NULL) {
		DbgPrint("\[\*\] Error : Couldn't Allocate Buffer for VMXON Region.");
		return FALSE;// ntStatus = STATUS\_INSUFFICIENT\_RESOURCES;
	}

Now we should convert the address of the allocated memory to its physical address and make sure it's aligned.

Memory that **MmAllocateContiguousMemory** allocates is uninitialized. A kernel-mode driver must first set this memory to zero. Now we should use **RtlSecureZeroMemory** for this case.

	UINT64 PhysicalBuffer = VirtualAddress\_to\_PhysicallAddress(Buffer);

	// zero-out memory 
	RtlSecureZeroMemory(Buffer, VMXONSize + ALIGNMENT\_PAGE\_SIZE);
	UINT64 alignedPhysicalBuffer = (BYTE\*)((ULONG\_PTR)(PhysicalBuffer + ALIGNMENT\_PAGE\_SIZE - 1) &~(ALIGNMENT\_PAGE\_SIZE - 1));
	UINT64 alignedVirtualBuffer = (BYTE\*)((ULONG\_PTR)(Buffer + ALIGNMENT\_PAGE\_SIZE - 1) &~(ALIGNMENT\_PAGE\_SIZE - 1));

	DbgPrint("\[\*\] Virtual allocated buffer for VMXON at %llx", Buffer);
	DbgPrint("\[\*\] Virtual aligned allocated buffer for VMXON at %llx", alignedVirtualBuffer);
	DbgPrint("\[\*\] Aligned physical buffer allocated for VMXON at %llx", alignedPhysicalBuffer);

From Intel's manual (24.11.5 VMXON Region ):

> Before executing VMXON, software should write the VMCS revision identifier to the VMXON region. (Specifically, it should write the 31-bit VMCS revision identifier to bits 30:0 of the first 4 bytes of the VMXON region; bit 31 should be cleared to 0.)
> 
> It need not initialize the VMXON region in any other way. Software should use a separate region for each logical processor and should not access or modify the VMXON region of a logical processor between the execution of VMXON and VMXOFF on that logical processor. Doing otherwise may lead to unpredictable behavior.

So let's get the Revision Identifier from **IA32\_VMX\_BASIC\_MSR**  and write it to our VMXON Region.

	// get IA32\_VMX\_BASIC\_MSR RevisionId

	IA32\_VMX\_BASIC\_MSR basic = { 0 };

	basic.All = \_\_readmsr(MSR\_IA32\_VMX\_BASIC);

	DbgPrint("\[\*\] MSR\_IA32\_VMX\_BASIC (MSR 0x480) Revision Identifier %llx", basic.Fields.RevisionIdentifier);

	//Changing Revision Identifier
	\*(UINT64 \*)alignedVirtualBuffer = basic.Fields.RevisionIdentifier;

The last part is used for executing VMXON instruction.

	int status = \_\_vmx\_on(&alignedPhysicalBuffer);
	if (status)
	{
		DbgPrint("\[\*\] VMXON failed with status %d\\n", status);
		return FALSE;
	}

	vmState->VMXON\_REGION = alignedPhysicalBuffer;

	return TRUE;

**\_\_vmx\_on** is the intrinsic function for executing VMXON. The status code shows diffrenet meanings.

| Value | Meaning |
| --- | --- |
| 0 | The operation succeeded. |
| 1 | The operation failed with extended status available in the `VM-instruction error field` of the current VMCS. |
| 2 | The operation failed without status available. |

If we set the VMXON Region using VMXON and it fails then status = 1. If there isn't any VMCS the status =2 and if the operation was successful then status =0.

If you execute the above code twice without executing VMXOFF then you definitely get errors.

Now, our VMXON Region is ready and we're good to go.

## **Virtual-Machine Control Data Structures (VMCS)**

A logical processor uses virtual-machine control data structures (VMCSs) while it is in VMX operation. These manage transitions into and out of VMX non-root operation (VM entries and VM exits) as well as processor behavior in VMX non-root operation. This structure is manipulated by the new instructions VMCLEAR, VMPTRLD, VMREAD, and VMWRITE.

![VMX Life cycle](../../assets/images/VMXLifecycle.png)

The above picture illustrates the lifecycle VMX operation on VMCS Region.

## **Initializing VMCS Region**

A VMM can (should) use different VMCS Regions so you need to set logical processor affinity and run you initialization routine multiple times.

The location where the VMCS located is called “VMCS Region”.

VMCS Region is a

- 4 Kbyte (bits 11:0 must be zero)
- Must be aligned to the 4KB boundary

This pointer must not set bits beyond the processor’s physical-address width (Software can determine a processor’s physical-address width by executing CPUID with 80000008H in EAX. The physical-address width is returned in bits 7:0 of EAX.)

There might be several VMCSs simultaneously in a processor but just one of them is currently active and the VMLAUNCH, VMREAD, VMRESUME, and VMWRITE instructions operate only on the current VMCS.

Using VMPTRLD sets the current VMCS on a logical processor.

The memory operand of the VMCLEAR instruction is also the address of a VMCS. After execution of the instruction, that VMCS is neither active nor current on the logical processor. If the VMCS had been current on the logical processor, the logical processor no longer has a current VMCS.

VMPTRST is responsible to give the current VMCS pointer it stores the value FFFFFFFFFFFFFFFFH if there is no current VMCS.

The launch state of a VMCS determines which VM-entry instruction should be used with that VMCS. The VMLAUNCH instruction requires a VMCS whose launch state is “clear”; the VMRESUME instruction requires a VMCS whose launch state is “launched”. A logical processor maintains a VMCS’s launch state in the corresponding VMCS region.

If the launch state of the current VMCS is “clear”, successful execution of the VMLAUNCH instruction changes the launch state to “launched”.

The memory operand of the VMCLEAR instruction is the address of a VMCS. After execution of the instruction, the launch state of that VMCS is “clear”.

There are no other ways to modify the launch state of a VMCS (it cannot be modified using VMWRITE) and there is no direct way to discover it (it cannot be read using VMREAD).

The following picture illustrates the contents of a VMCS Region.

![VMCS Region](../../assets/images/Init-VMCS.png)

The following code is responsible for allocating VMCS Region :

BOOLEAN Allocate\_VMCS\_Region(IN PVirtualMachineState vmState)
{
	// at IRQL > DISPATCH\_LEVEL memory allocation routines don't work
	if (KeGetCurrentIrql() > DISPATCH\_LEVEL)
		KeRaiseIrqlToDpcLevel();

	PHYSICAL\_ADDRESS PhysicalMax = { 0 };
	PhysicalMax.QuadPart = MAXULONG64;

	int VMCSSize = 2 \* VMCS\_SIZE;
	BYTE\* Buffer = MmAllocateContiguousMemory(VMCSSize + ALIGNMENT\_PAGE\_SIZE, PhysicalMax);  // Allocating a 4-KByte Contigous Memory region

	PHYSICAL\_ADDRESS Highest = { 0 }, Lowest = { 0 };
	Highest.QuadPart = ~0;

	//BYTE\* Buffer = MmAllocateContiguousMemorySpecifyCache(VMXONSize + ALIGNMENT\_PAGE\_SIZE, Lowest, Highest, Lowest, MmNonCached);

	UINT64 PhysicalBuffer = VirtualAddress\_to\_PhysicallAddress(Buffer);
	if (Buffer == NULL) {
		DbgPrint("\[\*\] Error : Couldn't Allocate Buffer for VMCS Region.");
		return FALSE;// ntStatus = STATUS\_INSUFFICIENT\_RESOURCES;
	}
	// zero-out memory 
	RtlSecureZeroMemory(Buffer, VMCSSize + ALIGNMENT\_PAGE\_SIZE);
	UINT64 alignedPhysicalBuffer = (BYTE\*)((ULONG\_PTR)(PhysicalBuffer + ALIGNMENT\_PAGE\_SIZE - 1) &~(ALIGNMENT\_PAGE\_SIZE - 1));

	UINT64 alignedVirtualBuffer = (BYTE\*)((ULONG\_PTR)(Buffer + ALIGNMENT\_PAGE\_SIZE - 1) &~(ALIGNMENT\_PAGE\_SIZE - 1));

	DbgPrint("\[\*\] Virtual allocated buffer for VMCS at %llx", Buffer);
	DbgPrint("\[\*\] Virtual aligned allocated buffer for VMCS at %llx", alignedVirtualBuffer);
	DbgPrint("\[\*\] Aligned physical buffer allocated for VMCS at %llx", alignedPhysicalBuffer);

	// get IA32\_VMX\_BASIC\_MSR RevisionId

	IA32\_VMX\_BASIC\_MSR basic = { 0 };

	basic.All = \_\_readmsr(MSR\_IA32\_VMX\_BASIC);

	DbgPrint("\[\*\] MSR\_IA32\_VMX\_BASIC (MSR 0x480) Revision Identifier %llx", basic.Fields.RevisionIdentifier);

	//Changing Revision Identifier
	\*(UINT64 \*)alignedVirtualBuffer = basic.Fields.RevisionIdentifier;

	int status = \_\_vmx\_vmptrld(&alignedPhysicalBuffer);
	if (status)
	{
		DbgPrint("\[\*\] VMCS failed with status %d\\n", status);
		return FALSE;
	}

	vmState->VMCS\_REGION = alignedPhysicalBuffer;

	return TRUE;
}

The above code is exactly the same as VMXON Region except for **\_\_vmx\_vmptrld** instead of **\_\_vmx\_on**, **\_\_vmx\_vmptrld**  is the intrinsic function for VMPTRLD instruction.

In VMCS also we should find the **Revision Identifier** from **MSR\_IA32\_VMX\_BASIC**  and write in VMCS Region before executing VMPTRLD.

The MSR\_IA32\_VMX\_BASIC  is defined as below.

typedef union \_IA32\_VMX\_BASIC\_MSR
{
	ULONG64 All;
	struct
	{
		ULONG32 RevisionIdentifier : 31;   // \[0-30\]
		ULONG32 Reserved1 : 1;             // \[31\]
		ULONG32 RegionSize : 12;           // \[32-43\]
		ULONG32 RegionClear : 1;           // \[44\]
		ULONG32 Reserved2 : 3;             // \[45-47\]
		ULONG32 SupportedIA64 : 1;         // \[48\]
		ULONG32 SupportedDualMoniter : 1;  // \[49\]
		ULONG32 MemoryType : 4;            // \[50-53\]
		ULONG32 VmExitReport : 1;          // \[54\]
		ULONG32 VmxCapabilityHint : 1;     // \[55\]
		ULONG32 Reserved3 : 8;             // \[56-63\]
	} Fields;
} IA32\_VMX\_BASIC\_MSR, \*PIA32\_VMX\_BASIC\_MSR;

## **VMXOFF**

After configuring the above regions, now its time to think about **DrvClose** when the handle to the driver is no longer maintained by the user-mode application. At this time, we should terminate VMX and free every memory that we allocated before.

The following function is responsible for executing VMXOFF then calling to **MmFreeContiguousMemory** in order to free the allocated memory :

void Terminate\_VMX(void) {

	DbgPrint("\\n\[\*\] Terminating VMX...\\n");

	KAFFINITY kAffinityMask;
	for (size\_t i = 0; i < ProcessorCounts; i++)
	{
		kAffinityMask = ipow(2, i);
		KeSetSystemAffinityThread(kAffinityMask);
		DbgPrint("\\t\\tCurrent thread is executing in %d th logical processor.", i);

		\_\_vmx\_off();
		MmFreeContiguousMemory(PhysicalAddress\_to\_VirtualAddress(vmState\[i\].VMXON\_REGION));
		MmFreeContiguousMemory(PhysicalAddress\_to\_VirtualAddress(vmState\[i\].VMCS\_REGION));

	}

	DbgPrint("\[\*\] VMX Operation turned off successfully. \\n");

}

Keep in mind to convert VMXON and VMCS Regions to virtual address because **MmFreeContiguousMemory** accepts VA, otherwise, it leads to a BSOD.

Ok, It's almost done!

## **Testing our VMM**

![](../../assets/images/at_work_computer.jpg)

Let's create a test case for our code, first a function for Initiating VMXON and VMCS Regions through all logical processor.

PVirtualMachineState vmState;
int ProcessorCounts;

PVirtualMachineState Initiate\_VMX(void) {

	if (!Is\_VMX\_Supported())
	{
		DbgPrint("\[\*\] VMX is not supported in this machine !");
		return NULL;
	}

	ProcessorCounts = KeQueryActiveProcessorCount(0);
	vmState = ExAllocatePoolWithTag(NonPagedPool, sizeof(VirtualMachineState)\* ProcessorCounts, POOLTAG);

	DbgPrint("\\n=====================================================\\n");

	KAFFINITY kAffinityMask;
	for (size\_t i = 0; i < ProcessorCounts; i++)
	{
		kAffinityMask = ipow(2, i);
		KeSetSystemAffinityThread(kAffinityMask);
		// do st here !
		DbgPrint("\\t\\tCurrent thread is executing in %d th logical processor.", i);

		Enable\_VMX\_Operation();	// Enabling VMX Operation
		DbgPrint("\[\*\] VMX Operation Enabled Successfully !");

		Allocate\_VMXON\_Region(&vmState\[i\]);
		Allocate\_VMCS\_Region(&vmState\[i\]);

		DbgPrint("\[\*\] VMCS Region is allocated at  ===============> %llx", vmState\[i\].VMCS\_REGION);
		DbgPrint("\[\*\] VMXON Region is allocated at ===============> %llx", vmState\[i\].VMXON\_REGION);

		DbgPrint("\\n=====================================================\\n");
	}
}

The above function should be called from IRP MJ CREATE so let's modify our **DrvCreate** to :

NTSTATUS DrvCreate(IN PDEVICE\_OBJECT DeviceObject, IN PIRP Irp)
{

	DbgPrint("\[\*\] DrvCreate Called !");

	if (Initiate\_VMX()) {
		DbgPrint("\[\*\] VMX Initiated Successfully.");
	}

	Irp->IoStatus.Status = STATUS\_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO\_NO\_INCREMENT);

	return STATUS\_SUCCESS;
}

And modify DrvClose to :

NTSTATUS DrvClose(IN PDEVICE\_OBJECT DeviceObject, IN PIRP Irp)
{
	DbgPrint("\[\*\] DrvClose Called !");

	// executing VMXOFF on every logical processor
	Terminate\_VMX();

	Irp->IoStatus.Status = STATUS\_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO\_NO\_INCREMENT);

	return STATUS\_SUCCESS;
}

Now, run the code, In the case of creating the handle (You can see that our regions allocated successfully).

![VMX Regions](../../assets/images/VMXONandVMCS.png)

And when we call **CloseHandle** from user mode:

![VMXOFF](../../assets/images/TerminateVMX.png)

## **Source code**

The source code of this part of the tutorial is available on my [GitHub](https://github.com/SinaKarvandi/Hypervisor-From-Scratch).

Note: Please keep in mind that hypervisors change during the time because new features added to the operating systems or using new technologies, for example, updates to Meltdown & Spectre have made a lot of changes to the hypervisors, so if you want to use Hypervisor From Scratch in your projects, researches or whatever, you have to use the driver from the latest parts of these tutorial series as this tutorial is actively updated and changes are applied to the newer parts (earlier parts keep untouched) so you might encounter errors and instability problems in the earlier parts thus make sure to use the latest parts in real-world projects.

## **Conclusion**

In this part we learned about different types of IOCTL Dispatching, then we see different functions in Windows to manage our hypervisor VMM and we initialized the VMXON Regions and VMCS Regions then we terminate them.

In the future part, we'll focus on VMCS and different actions that can be performed in VMCS Regions in order to control our guest software.

The fourth part is also available [here](https://rayanfam.com/topics/hypervisor-from-scratch-part-4/).

## **References**

\[1\] Intel® 64 and IA-32 architectures software developer’s manual combined volumes 3 ([https://software.intel.com/en-us/articles/intel-sdm](https://software.intel.com/en-us/articles/intel-sdm)) 

\[2\] Windows Driver Samples ([https://github.com/Microsoft/Windows-driver-samples](https://github.com/Microsoft/Windows-driver-samples))

\[3\] Driver Development Part 2: Introduction to Implementing IOCTLs ([https://www.codeproject.com/Articles/9575/Driver-Development-Part-2-Introduction-to-Implemen](https://www.codeproject.com/Articles/9575/Driver-Development-Part-2-Introduction-to-Implemen))

\[3\] Hyperplatform ([https://github.com/tandasat/HyperPlatform](https://github.com/tandasat/HyperPlatform))

\[4\] PAGED\_CODE macro ([https://technet.microsoft.com/en-us/ff558773(v=vs.96)](https://technet.microsoft.com/en-us/ff558773(v=vs.96)))

\[5\] HVPP ([https://github.com/wbenny/hvpp](https://github.com/wbenny/hvpp))

\[6\] HyperBone Project ([https://github.com/DarthTon/HyperBone](https://github.com/DarthTon/HyperBone))

\[7\] Memory Caching Types ([https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ne-wdm-\_memory\_caching\_type)](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/ne-wdm-_memory_caching_type)

\[8\] What is write-back cache? ([https://whatis.techtarget.com/definition/write-back](https://whatis.techtarget.com/definition/write-back))
