---
title: "Using Intel's Streaming SIMD Extensions 3 (MONITOR \ MWAIT) As A Kernel Debugging Trick"
date: "2018-09-08"
categories: 
  - "cpu"
  - "debugging"
  - "kernel-mode"
tags: 
  - "intel-mon-feature"
  - "intel-streaming-simd-extensions-3"
  - "intel-synchronization-agent"
  - "monitor-mwait-instructions"
coverImage: "../../assets/images/intel-inside-cover.jpg"
---

![](../../assets/images/intel-inside-cover.jpg)

## **Introduction**

MONITOR and MWAIT are using when the CPU needs to be stopped executing the instruction and enter an implementation-dependent optimized state until some special event happens.

MONITOR sets up an address range used to monitor write-back stores while MWAIT enables a logical processor to enter into an optimized state while waiting for a write-back store to the address range set up by MONITOR instruction.

MWAIT and MONITOR may be executed only at privilege level 0, if you use these instructions in any other privilege level, then an invalid opcode exception is thrown.

If the preceding MONITOR instruction did not successfully arm an address range or if the MONITOR instruction has not been executed prior to executing MWAIT, then the processor will not enter the implementation-dependent-optimized state. Execution will resume at the instruction following the MWAIT.

The opcode and the instructions are shown below :

0:  0f 01 c9                mwait

0:  0f 01 c8                monitor

## **Check Availability**

The BIOS or any kernel-level driver or operating system can disable these instructions by using the IA32\_MISC\_ENABLE MSR;

CPUID.01H:ECX.MONITOR\[bit 3\] indicates the availability of MONITOR and MWAIT in the processor.

## **Query About Details**

To query about the smallest and the largest line size that MONITOR supports you can use CPUID.05H:EAX\[bits 15:0\] and CPUID.05H:EBX.Largest\[bits 15:0\]. Values are returned in bytes.

## **Implementation**

For MONITOR address should be in RAX/EAX, ECX and EDX are hints to processor about Monitor state. (We make them zeros.). MWAIT, on the other hand, should be executed after MONITOR and you can use ECX in order to config MWAIT about interrupts.

If ECX\[0th Bit\] = 0, then MWAIT will wake on every interrupts (that's exactly like HLT instruction) but if ECX\[0th Bit\] = 1 then it doesn't wake on interrupts.

As you can see in the following code, we don't need MWAIT to wake by system interrupts so just increment the ECX.

MWAIT/MONITOR in Linux Kernel Module (AT&T Syntax):

int init\_module(void)
{
long unsigned int address = 0xffffffff12345678; 

\_\_asm\_\_ volatile(

"push %%rax\\n\\t"
"push %%rcx\\n\\t"
"push %%rdx\\n\\t"

"xor %%rax,%%rax\\n\\t"
"xor %%rcx,%%rax\\n\\t"
"xor %%rdx,%%rax\\n\\t"

"movq %0,%%rax\\n\\t"
"MONITOR\\n\\t"

"xor %%rax,%%rax\\n\\t"
"xor %%rcx,%%rax\\n\\t"

"inc %%rax\\n\\t"

"MWAIT\\n\\t"

"pop %%rdx\\n\\t"
"pop %%rcx\\n\\t"
"pop %%rax\\n\\t"

:: "g" (address));

printk("The requested location has been accessed !");

return 0;
}

The address to monitor is stored in "address" and in our example it is **0xffffffff12345678**.

## **Using MONITOR/MWAIT To Detect Modifications**

As I told you, MONITOR/MWAIT can be used as a debugging trick, whenever we used all of our 4 debug registers then we can use our cores instead! I always use these instructions to detect whether a special range of memory (in the kernel) is modified by other processors or not. On the other hand, you have more flexibility in size rather than the debug registers but the worst thing about it is that you can notify in the case of modification but you never know what was the code that leads to this modification.

As Intel describes MONITOR/MWAIT are agent synchronization instructions so they might be used in order to trigger an event to notify a kernel program.

## **Limitation**

One of the limitations for MONITOR/MWAIT is that it only wakes on modification on the write-back cache and not write-through cache so it seems Intel implemented these instructions just in L1 write-back.

A good answer in [StackOverflow](https://stackoverflow.com/questions/27087912/write-back-vs-write-through) describes the differences between write-back and write-through caches:

> Write-back is used for the up-to-date data is in a processor cache, and sometimes it is in main memory. If the data is in a processor cache, then that processor must stop main memory from replying to the read request, because the main memory might have a stale copy of the data. This is more complicated than write-through.
> 
> Write-through can simplify the cache coherency protocol because it doesn't need the _Modify_ state. The _Modify_ state records that the cache must write back the cache line before it invalidates or evicts the line. In write-through, a cache line can always be invalidated without writing back since memory already has an up-to-date copy of the line. The

The equivalent of MWAIT and Monitor in other processors is MIPS'LL/Pause.

![](../../assets/images/anime-girl-computer-animated.jpg)

## **References**

\[1\] How to Use the MONITOR and MWAIT Streaming SIMD Extensions 3 Instructions ([https://software.intel.com/en-us/articles/how-to-use-the-monitor-and-mwait-streaming-simd-extensions-3-instructions](https://software.intel.com/en-us/articles/how-to-use-the-monitor-and-mwait-streaming-simd-extensions-3-instructions))

\[2\] MWAIT — Monitor Wait ([https://www.felixcloutier.com/x86/MWAIT.html](https://www.felixcloutier.com/x86/MWAIT.html))

\[3\] Write-back vs Write-Through ([https://stackoverflow.com/questions/27087912/write-back-vs-write-through](https://stackoverflow.com/questions/27087912/write-back-vs-write-through))
