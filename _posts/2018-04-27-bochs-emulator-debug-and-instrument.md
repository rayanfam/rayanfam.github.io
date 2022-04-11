---
title: "Bochs Emulator - Debug & Instrument"
date: "2018-04-27"
categories: 
  - "debugging"
  - "emulator"
  - "instrumentation"
tags: 
  - "debug-using-bochs"
  - "emulator-debugging"
  - "instrument-instructions-using-bochs"
  - "instrument-kernel-mode"
  - "instrument-linux"
  - "instrument-operating-system"
  - "instrument-os-x"
  - "instrument-windows"
coverImage: "Boch-Debugger-GUI.png"
author:
  name: Mohammad Sina Karvandi
  link: https://twitter.com/Intel80x86
---

![](../../assets/images/Boch-Debugger-GUI.png)

There is also another post about configuring and building Bochs on Windows & OS X if you have a problem compiling Bochs, take a look at [here](https://rayanfam.com/topics/bochs-config-and-build-on-windows-and-os-x/)!

In my opinion, Bochs is an amazing thing because it provides instrumentation in the lowest level of the Operating System. One of the advantages of the Boch is being able to instrument in kernel-mode, which is not available in other instrumenting tools like Intel's pin tool.

You can see how to interact with Bochs debugger [here](http://bochs.sourceforge.net/doc/docbook/user/internal-debugger.html). It's somehow like Windbg in its syntax, if you enabled the debugger feature during the compilation then after running the OS, you can press ctrl+c and it gives you a command-line interface.

In the rest of the post, I'm gonna explain about instrumentation.

Instrumenting in Bochs is depending on the following functions that exist in /stubs/ instrument.cc.

#include "bochs.h"

#if BX\_INSTRUMENTATION

void bx\_instr\_init\_env(void) {}
void bx\_instr\_exit\_env(void) {}

void bx\_instr\_initialize(unsigned cpu) {}
void bx\_instr\_exit(unsigned cpu) {}
void bx\_instr\_reset(unsigned cpu, unsigned type) {}
void bx\_instr\_hlt(unsigned cpu) {}
void bx\_instr\_mwait(unsigned cpu, bx\_phy\_address addr, unsigned len, Bit32u flags) {}

void bx\_instr\_debug\_promt() {}
void bx\_instr\_debug\_cmd(const char \*cmd) {}

void bx\_instr\_cnear\_branch\_taken(unsigned cpu, bx\_address branch\_eip, bx\_address new\_eip) {}
void bx\_instr\_cnear\_branch\_not\_taken(unsigned cpu, bx\_address branch\_eip) {}
void bx\_instr\_ucnear\_branch(unsigned cpu, unsigned what, bx\_address branch\_eip, bx\_address new\_eip) {}
void bx\_instr\_far\_branch(unsigned cpu, unsigned what, Bit16u prev\_cs, bx\_address prev\_eip, Bit16u new\_cs, bx\_address new\_eip) {}

void bx\_instr\_opcode(unsigned cpu, bxInstruction\_c \*i, const Bit8u \*opcode, unsigned len, bx\_bool is32, bx\_bool is64) {}

void bx\_instr\_interrupt(unsigned cpu, unsigned vector) {}
void bx\_instr\_exception(unsigned cpu, unsigned vector, unsigned error\_code) {}
void bx\_instr\_hwinterrupt(unsigned cpu, unsigned vector, Bit16u cs, bx\_address eip) {}

void bx\_instr\_tlb\_cntrl(unsigned cpu, unsigned what, bx\_phy\_address new\_cr3) {}
void bx\_instr\_clflush(unsigned cpu, bx\_address laddr, bx\_phy\_address paddr) {}
void bx\_instr\_cache\_cntrl(unsigned cpu, unsigned what) {}
void bx\_instr\_prefetch\_hint(unsigned cpu, unsigned what, unsigned seg, bx\_address offset) {}

void bx\_instr\_before\_execution(unsigned cpu, bxInstruction\_c \*i) {}
void bx\_instr\_after\_execution(unsigned cpu, bxInstruction\_c \*i) {}
void bx\_instr\_repeat\_iteration(unsigned cpu, bxInstruction\_c \*i) {}

void bx\_instr\_inp(Bit16u addr, unsigned len) {}
void bx\_instr\_inp2(Bit16u addr, unsigned len, unsigned val) {}
void bx\_instr\_outp(Bit16u addr, unsigned len, unsigned val) {}

void bx\_instr\_lin\_access(unsigned cpu, bx\_address lin, bx\_address phy, unsigned len, unsigned memtype, unsigned rw) {}
void bx\_instr\_phy\_access(unsigned cpu,                 bx\_address phy, unsigned len, unsigned memtype, unsigned rw) {}

void bx\_instr\_wrmsr(unsigned cpu, unsigned addr, Bit64u value) {}

void bx\_instr\_vmexit(unsigned cpu, Bit32u reason, Bit64u qualification) {}

#endif

For using Bochs instrumentation, first, you need to configure Bochs with the following argument:

./configure --enable-instrumentation="instrument/stubs"

Then you can change the above file and compile your project again and run Bochs with its debugger feature then Bochs automatically sets your function as a callback to its main CPU emulation functions and every time, one of the above functions performed in the target machine, then you'll be aware.

The best reference for describing the above functions is Instrument.txt which exists under /instrument/Instrument.txt, I copied the newest version of Instrument.txt (at the time of writing this post), you can see the below file :

> **Instrumentation**
> 
> To use instrumentation features in bochs, you must compile in support for it. You should build a custom instrumentation library in a separate directory in the "instrument/" directory. To tell configure which instrumentation library you want to use, use the "--enable-instrumentation" option. The default library consists of a set of stubs, and the following are equivalent:
> 
> ./configure \[...\] --enable-instrumentation
> ./configure \[...\] --enable-instrumentation="instrument/stubs"
> 
> You could make a separate directory with your custom library, for example "instrument/myinstrument", copy the contents of the "instrument/stubs" directory to it, then customize it. Use:
> 
> ./configure \[...\] --enable-instrumentation="instrument/myinstrument"
> 
> \----------------------------------------------------------------------------- BOCHS instrumentation callbacks
> 
> void bx\_instr\_init\_env();
> 
> The callback is called when Bochs is initialized, before of reading .bochsrc. It can be used for registration of parameters in siminterface. Then when bx\_instr\_init() is called it can access configuration parameters defined by bx\_instr\_init\_env(), so instrumentalization module can use additional options in .bochsrc.
> 
> void bx\_instr\_exit\_env();
> 
> The callback is called each time Bochs exits.
> 
> void bx\_instr\_initialize(unsigned cpu);
> 
> The callback is called each time, when Bochs initializes the CPU object. It can be used for initialization of user's data, dynamic memory allocation and etc.
> 
> void bx\_instr\_exit(unsigned cpu);
> 
> The callback is called each time, when Bochs destructs the CPU object. It can be used for destruction of user's data, allocated by bx\_instr\_init callback.
> 
> void bx\_instr\_reset(unsigned cpu, unsigned type);
> 
> The callback is called each time, when Bochs resets the CPU object. It would be executed once at the start of simulation and each time that user presses RESET BUTTON on the simulator's control panel.
> 
> void bx\_instr\_hlt(unsigned cpu);
> 
> The callback is called each time, when Bochs' emulated CPU enters HALT or SHUTDOWN state.
> 
> void bx\_instr\_mwait(unsigned cpu, bx\_phy\_address addr, unsigned len, Bit32u flags);
> 
> The callback is called each time, when Bochs' emulated CPU enters to the MWAIT state. The callback receives monitored memory range and MWAIT flags as a parameters.
> 
> void bx\_instr\_cnear\_branch\_taken(unsigned cpu, bx\_address branch\_rip, bx\_address new\_rip);
> 
> The callback is called each time, when currently executed instruction is a conditional near branch and it is taken.
> 
> void bx\_instr\_cnear\_branch\_not\_taken(unsigned cpu, bx\_address branch\_rip);
> 
> The callback is called each time, when currently executed instruction is a conditional near branch and it is not taken.
> 
> void bx\_instr\_ucnear\_branch(unsigned cpu, unsigned what, bx\_address branch\_rip, bx\_address new\_rip);
> 
> The callback is called each time, when currently executed instruction is an unconditional near branch (always taken).
> 
> void bx\_instr\_far\_branch(unsigned cpu, unsigned what, Bit16u prev\_cs, bx\_address prev\_rip, Bit16u new\_cs, bx\_address new\_rip);
> 
> The callback is called each time, when currently executed instruction is an unconditional far branch (always taken).
> 
> Possible operation types, passed through bx\_instr\_ucnear\_branch and bx\_instr\_far\_branch are:
> 
> #define BX\_INSTR\_IS\_JMP 10
> #define BX\_INSTR\_IS\_JMP\_INDIRECT 11
> #define BX\_INSTR\_IS\_CALL 12
> #define BX\_INSTR\_IS\_CALL\_INDIRECT 13
> #define BX\_INSTR\_IS\_RET 14
> #define BX\_INSTR\_IS\_IRET 15
> #define BX\_INSTR\_IS\_INT 16
> #define BX\_INSTR\_IS\_SYSCALL 17
> #define BX\_INSTR\_IS\_SYSRET 18
> #define BX\_INSTR\_IS\_SYSENTER 19
> #define BX\_INSTR\_IS\_SYSEXIT 20
> 
> void bx\_instr\_vmexit(unsigned cpu, Bit32u reason, Bit64u qualification);
> 
> This callback is called right before Bochs executes a VMEXIT.
> 
> void bx\_instr\_opcode(unsigned cpu, bxInstruction\_c \*i, const Bit8u \*opcode, unsigned len, bx\_bool is32, bx\_bool is64);
> 
> The callback is called each time, when Bochs completes to decode a new instruction. Through this callback function Bochs could provide an opcode of the instruction, opcode length and an execution mode (16/32/64).
> 
> Note, that Bochs uses translation caches so each simulated instruction might be executed multiple times but decoded only once.
> 
> void bx\_instr\_interrupt(unsigned cpu, unsigned vector);
> 
> The callback is called each time, when Bochs simulator executes an interrupt (software interrupt, hardware interrupt or an exception).
> 
> void bx\_instr\_exception(unsigned cpu, unsigned vector, unsigned error\_code);
> 
> The callback is called each time, when Bochs simulator executes an exception.
> 
> void bx\_instr\_hwinterrupt(unsigned cpu, unsigned vector, Bit16u cs, bx\_address rip);
> 
> The callback is called each time, when Bochs simulator executes a hardware interrupt.
> 
> void bx\_instr\_clflush(unsigned cpu, bx\_address laddr, bx\_phy\_address paddr);
> 
> The callback is called each time the CLFLUSH instruction is executed.
> 
> void bx\_instr\_tlb\_cntrl(unsigned cpu, unsigned what, bx\_phy\_address new\_cr\_value);
> void bx\_instr\_cache\_cntrl(unsigned cpu, unsigned what);
> 
> The callback is called each time, when Bochs simulator executes a cache/tlb control instruction.
> 
> Possible instruction types, passed through bx\_instr\_tlb\_cntrl are:
> 
> #define BX\_INSTR\_MOV\_CR0 10
> #define BX\_INSTR\_MOV\_CR3 11
> #define BX\_INSTR\_MOV\_CR4 12
> #define BX\_INSTR\_TASK\_SWITCH 13
> #define BX\_INSTR\_CONTEXT\_SWITCH 14 /\* VMM and SMM enter/exit \*/
> #define BX\_INSTR\_INVLPG 15
> #define BX\_INSTR\_INVEPT 16
> #define BX\_INSTR\_INVVPID 17
> #define BX\_INSTR\_INVPCID 18
> 
> The new\_cr\_value is provided for first 4 instruction types only and undefined for all others.
> 
> Possible instruction types, passed through bx\_instr\_cache\_cntrl are:
> 
> #define BX\_INSTR\_INVD 10
> #define BX\_INSTR\_WBINVD 11
> 
> void bx\_instr\_prefetch\_hint(unsigned cpu, unsigned what, unsigned seg, bx\_address offset);
> 
> The callback is called each time, when Bochs simulator executes a PREFETCH instruction.
> 
> Possible PREFETCH types:
> 
> #define BX\_INSTR\_PREFETCH\_NTA 00
> #define BX\_INSTR\_PREFETCH\_T0 01
> #define BX\_INSTR\_PREFETCH\_T1 02
> #define BX\_INSTR\_PREFETCH\_T2 03
> 
> The seg/offset arguments indicate the address of the requested prefetch.
> 
> void bx\_instr\_wrmsr(unsigned cpu, unsigned msr, Bit64u value);
> 
> This callback is called each time when WRMSR instruction is executed. MSR number and written value passed as parameters to the callback function.
> 
> void bx\_instr\_repeat\_iteration(unsigned cpu, bxInstruction\_c \*i);
> 
> The callback is called each time, when Bochs simulator starts a new repeat iteration.
> 
> void bx\_instr\_before\_execution(unsigned cpu, bxInstruction\_c \*i);
> 
> The callback is called each time, when Bochs simulator starts a new instruction execution. In case of repeat instruction the callback will be called only once before the first iteration will be started.
> 
> void bx\_instr\_after\_execution(unsigned cpu, bxInstruction\_c \*i);
> 
> The callback is called each time, when Bochs simulator finishes any instruction execution. In case of repeat instruction the callback will be called only once after all repeat iterations.
> 
> void bx\_instr\_lin\_access(unsigned cpu, bx\_address lin, bx\_address phy, unsigned len, unsigned memtype, unsigned rw);
> 
> The callback is called each time, when Bochs simulator executes a linear memory access. Note that no page split accesses will be generated because Bochs splits page split accesses to two different memory accesses during its execution flow. The callback also will not be generated in case of direct physical memory access like page walks, SMM, VMM or SVM operations.
> 
> Possible access types are: BX\_READ, BX\_WRITE and BX\_RW.
> 
> Currently the callback is not supported when repeat-speedups optimization is enabled.
> 
> void bx\_instr\_phy\_access(unsigned cpu, bx\_address lin, bx\_address phy, unsigned len, unsigned memtype, unsigned rw);
> 
> The callback is called each time, when Bochs simulator executes a physical memory access. Physical accesses include memory accesses generated by the CPU during page walks, SMM, VMM or SVM operations. Note that no page split accesses will be generated because Bochs splits page split accesses to two different memory accesses during its execution flow.
> 
> Possible access types are: BX\_READ, BX\_WRITE and BX\_RW.
> 
> void bx\_instr\_inp(Bit16u addr, unsigned len);
> void bx\_instr\_inp2(Bit16u addr, unsigned len, unsigned val);
> void bx\_instr\_outp(Bit16u addr, unsigned len, unsigned val);
> 
> These callback functions are a feedback from various system devices.
> 
> \----------------------------------------------------------------------------- Known problems:
> 
> 1\. BX\_INSTR\_LIN\_ACCESS doesn't work when repeat-speedups feature is enabled.
> 
> Feature requests:
> 
> 1\. BX\_INSTR\_CNEAR\_BRANCH\_NOT\_TAKEN callback should have an additional 'not taken' new\_rip parameter.
> 
> 2\. BX\_INSTR\_SMI, BX\_INSTR\_NMI, BX\_INSTR\_SIPI and other external events callbacks

 

If you read the above description about instrument functions, then let's have a look at some of the important ones!

For debugging VMX you should use bx\_instr\_vmexit, but you should be sure to compile your Bochs with this feature enabled. By default it is enabled in the current version of Bochs :

#define BX\_SUPPORT\_VMX 2

bx\_instr\_phy\_access can also help you debugging EPT (Extended Page Table) by checking physical addresses.

There are also other functions like bx\_instr\_wrmsr which is used for detecting what kind of MSR indexes an operating system or system drivers try to use.

## References

- \[Bochs User Manual\] ([http://bochs.sourceforge.net/doc/docbook/user/index.html](http://bochs.sourceforge.net/doc/docbook/user/index.html))
- \[Platform emulation with Bochs\] ([https://www.ibm.com/developerworks/library/l-bochs](https://www.ibm.com/developerworks/library/l-bochs)) - \[PDF Version\] ([https://www.ibm.com/developerworks/library/l-bochs/l-bochs-pdf.pdf](https://www.ibm.com/developerworks/library/l-bochs/l-bochs-pdf.pdf))
- \[Wikipedia - Bochs\] ([https://en.wikipedia.org/wiki/Bochs](https://en.wikipedia.org/wiki/Bochs))
- \[Using Bochs internal debugger\] ([http://bochs.sourceforge.net/doc/docbook/user/internal-debugger.html](http://bochs.sourceforge.net/doc/docbook/user/internal-debugger.html))
