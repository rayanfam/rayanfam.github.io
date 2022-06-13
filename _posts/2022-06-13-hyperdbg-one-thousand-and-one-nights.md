---
title: "HyperDbg’s One Thousand and One Nights"
date: "2022-06-13"
categories: 
  - "debugger"
  - "hyperdbg"
  - "tutorials"
tags: 
  - "hyperdbg"
  - "windbg"
  - "hyperdbg-vs-windbg"
  - "debugger"
  - "hyperdbg-principles"
  - "reversing-using-hyperdbg"
  - "hypervisor"
  - "using-hyperdbg-debugger"
coverImage: "../../assets/images/HyperDbg-v0.1-1-compressed.jpg"
comments: true
author:
  name: Saleh Monfared
  link: https://twitter.com/sal3hh
  name: Mohammad Sina Karvandi
  link: https://twitter.com/Intel80x86
---

![](../../assets/images/HyperDbg-v0.1-1-compressed.jpg)

# HyperDbg’s One Thousand and One Nights

This post is a different one, in that, it is more of an overview, rather than a technical post. Here, we provide a high-level summary of HyperDbg Debugger, its principles, and perspective.


## Introduction

HyperDbg is an open-source, hypervisor-assisted debugger that can be used to debug both user-mode and kernel-mode applications. The closest similar product available to HyperDbg is WinDbg.
HyperDbg provides unique abilities, enabled by exploitation of the latest features of modern processors, to assist you in your reversing journey.

The design principles employed in HyperDbg make for an OS-independent debugger with a unique architecture, offering exclusive, brand-new features.

## A Bit of History

Almost three years ago (precisely, on 18 December 2019), we finished implementing EPT hooks and VPIDs, thus setting the cornerstones for designing a new debugger. Ever since, many of our friends have joined the project to develop an advanced, fully-practical, and usable debugger.

During our Windows analysis journey, we always felt the lack of two elements that we thought would most likely make our tasks much faster and more efficient, and that was our main motive, to tackle the following setbacks:
1.  None of the current classic debuggers, (such as WinDbg) have the ability to trace read/write/executes to a large structure. Sure they have to be able to debug registers, but that’s limited. They can’t specify more than four addresses, and the size is also limited to 1, 2, and 4 Bytes.
2.  There was no support for tracing instructions from user mode to kernel mode and from kernel mode to user mode. A feature like this would allow us to trace the parameter to the system calls and find the exact routines (basic blocks) executed due to our produced parameter in static analysis tools like IDA Pro, Ghidra, and Radare2.

The solution to the first issue was implemented in HyperDbg and exported as a command named “!monitor”, and the secondly discussed issue was addressed with the Instrumentation Step-in or the “i”.

After that, dozens of features were added to the debugger to get HyperDbg to where it is today.

## Motivation
Let’s talk about the motivations behind HyperDbg.

### Classic Debuggers are Still Stuck At at their 90’s features.

Debuggers are one of the essential tools used in computer sciences for a variety of purposes.

Although there have been some upgrades and improvements over the course of years to the available debugging toolset, such as the Time Travel Debugging (TTD) feature that was introduced by Microsoft into their main debugger, WinDbg, people are essentially still debugging the same way they used to do back in the ’90s, with the same simple elements such as step-in and step-over. This puts a fundamental setback in the way of software programmers, reversers, and security researchers.

We believe debugging, analyzing, and software profiling are inseparable elements that should all be coherently integrated into debuggers to make an enhanced experience of software development and bug finding.

### The intention was not to reinvent the wheel.

Our motive was not to reintroduce yet another debugger with the same set of already available features, but it was fueled by the vision of how better a debugging experience can get, and the gap between that vision and the status quo. More specifically, we recognized the powerhouse, that is, the modern hardware features of newer generation processors, and their immense capacity for utilization towards providing an enriched software analysis experience, and the lack of meaningful and practical support for such features in commodity debuggers. And it was this state of mind that gave rise to the emergence of HyperDbg. We see where HyperDbg is today, only as a starting point for future milestones and improvements to provide even easier and more convenient debugging experiences.


## Kernel Debugger

The central part of the HyperDbg debugger is its kernel-mode debugger called kHyperDbg. 

It has been almost two decades since kernel debuggers (such as WinDbg and GDB) have had any significant changes. We wanted that to change that and advance the debugging experience to new horizons. Furthermore, HyperDbg delivers these improvements on rudimentary levels, compared to commonly used debuggers, in that, it enormously expands the range of privileges available to the user by shifting the debugging process from kernel-level (ring 0) to hypervisor-level (ring -1), a much-needed enhancement in our opinion, especially when it comes to kernel-debugging. 

As kernel level debuggers are prohibited the access to manipulate the operating system’s structures to make facilities for the debugging, HyperDbg uses an entirely separate layer to monitor and change these structures without interfering with the operating system, the hypervisor level, that resides below the kernel of the operating system in the hardware privilege rings. This makes HyperDbg blazingly fast and a highly powerful tool in terms of the flexibility, privileges, and the transparency it can provide for debugging and analysis. Owing to this fundamental transition, HyperDbg is able to deliver state-of-the-art features that make it particularly more convenient to analyze complex modern binaries that run on kernel mode of operating systems and are crucial to the security and reliability of the system. Furthermore, the highly efficient and low-level implementation, coupled with the potent script engine, allows for some tremendously powerful abilities, such as changing the flow of the applications and even the operating system using simple scripts.

## A few of its unique features

In this section, we will try and summarize some of the unique features of HyperDbg.

### Tremendously Faster

As described earlier, HyperDbg is incredibly fast, thanks to its low-level and efficient implementation. This brings forward new opportunities for many innovative debugging scenarios. For example, let’s imagine you want to analyze every system, or get a log from a function called at a very high rate. HyperDbg allows you to do all of them with ease and high performance.

### Better Transparency
One of the future goals of HyperDbg is to keep enhancing the stealth and transparency of its transparent mode. Of course, it is not possible to achieve 100% transparency, but we keep trying to make it more challenging for the anti-debugging methods to detect HyperDbg.

### Exporting Processor Events In Debugger
HyperDbg tends to export all system events of interest as debugger events. So many events happen in the CPU at all times. Fortunately, the majority of them are accessible via hypervisors. In HyperDbg, we export events into HyperDbg event format. Each HyperDbg event then can be used as a trigger for executing a desired action, such as breaking the debugger, executing custom assembly codes, or running a custom script engine. This standard pipeline will apply to all the current events and possible future events.

## HyperDbg vs. WinDbg

As one of the closest counterparts of HyperDbg, in this section, we draw a comparison between Windbg and HyperDbg in a detailed manner.

How different is HyperDbg from Windbg?
HyperDbg has an entirely different and standalone architecture. Windbg operates on ring 0 (kernel) while HyperDbg is running on ring -1 (hypervisor); thus, HyperDbg is capable of providing unique features that are not available on Windbg (OS-Level).

Additionally, HyperDbg is not just a simple debugger. It comes with modern reverse engineering methods, powered by vt-x and other similar capabilities of modern processors to facilitate reverse engineering, analyzing, and fuzzing.

WinDbg is built for development HyperDbg is built for reversing. We are not the same!

Microsoft made WinDbg to build Windows and perform driver development tasks. Contrarily, HyperDbg is mainly geared towards use in reverse engineering, where one has no idea about their target debuggee. Of course, WinDbg is better at debugging drivers with the source code. However, if you wanted to understand a mechanism in which you have no access to the source code or if symbols are only partially available, then HyperDbg would give you way more features to explore your debuggee.

**HyperDbg is not a classic debugger.**
One of the main differentiating factors between HyperDbg and commodity debuggers stems from HyperDbg’s deliberation on the use of sophisticated methods and techniques by modern binaries to obfuscate their internal structures.

For instance, most malware uses various anti-debugging techniques to avoid showing its malicious behavior when a debugger is around. On the other hand, classic debuggers are not suitable for analyzing the internal mechanisms that are buried deep into the complicated modules of the operating systems.

**HyperDbg is a hypervisor-based debugger.**
HyperDbg uses Intel VT-x (Ring -1) technology, while WinDbg is a kernel-based (Ring 0) debugger. Thus, HyperDbg is more privileged in terms of hardware terminology.

Being a hypervisor-based debugger brings new magical features to life.
Dozens of wonderful features already exist in HyperDbg that no other debuggers have. These features drastically enhance your reverse engineering journey, and we continue to add more and more features to further improve your debugging experience.

**HyperDbg is more transparent by nature.**
Generally, basing the debugger on the hypervisor layer makes HyperDbg more transparent than WinDbg. HyperDbg doesn’t use any debugging-related API, so even the operating system doesn’t have any idea that it’s being debugged! And that’s not all! HyperDbg can also hide from microarchitectural timing attacks that reveal the presence of the hypervisors. Transparency is a priority and is under active development.

**HyperDbg is open-source, WinDbg is not.**
HyperDbg is a community-driven debugger, and everyone can contribute to the project. In contrast, WinDbg is not open-source, although the source codes of some older versions have been leaked several times by now.

WinDbg works on multi-architectures, but so far, HyperDbg only works on x64-based systems.
You can use WinDbg to debug many architectures like ARM, ARM64 (AARCH64), and AMD64 (x86_64), while HyperDbg currently only works on Intel x64-bit processors. However, it is still possible to debug x86 applications running in a system with an x64-bit processor.

**HyperDbg is faster, tremendously faster.**
HyperDbg is shipped with a vmx-root mode compatible script engine. Every check is performed on the kernel side (vmx-root mode), and in contrast to WinDbg, nothing is passed to the debugger. This makes for a substantially faster debugging process. Based on our evaluations as part of an academic publication on HyperDbg, Windbg was able to check 6,941 conditions, while HyperDbg could check  23,214,792 in the same time period, making HyperDbg about ~3300 folds faster than Windbg in this benchmark.

## HyperDbg’s Logo

HyperDbg’s logo is the Schrödinger’s cat, which is both dead and alive. It serves as a reminder that analyzing and reversing is not always a deterministic route for getting the correct answer. One will try, and one might succeed or fail, and that’s the nature of the digital world, which boils down to one of the two fundamental states: ones and zeros. 


<blockquote class="twitter-tweet"><p lang="en" dir="ltr">Here are 11 reasons why we should use <a href="https://twitter.com/hashtag/HyperDbg?src=hash&amp;ref_src=twsrc%5Etfw">#HyperDbg</a>, the differences between HyperDbg and <a href="https://twitter.com/hashtag/WinDbg?src=hash&amp;ref_src=twsrc%5Etfw">#WinDbg</a>, and how HyperDbg will change our debugging/reversing journey.<br><br>A thread (24 tweets) 🧵:</p>&mdash; HyperDbg Debugger (@HyperDbg) <a href="https://twitter.com/HyperDbg/status/1533121695900479488?ref_src=twsrc%5Etfw">June 4, 2022</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

## Contribution

HyperDbg is a large-scale project that requires a lot of time and effort from the community. Given the current number of developers and their limited time and resources, we cannot develop every part simultaneously. Therefore, new developers are warmly welcomed to join and contribute to the project. Please open discussions to discuss the HyperDbg and possible future assistance.

## The future works

In the future, we want to add UEFI support to start HyperDbg before Windows. Another significant contribution would be adding Intel Processor Trace (PT) in an event and action style to the debugger and finally joining and integrating many cool projects to the HyperDbg to bring a unique debugging experience, like no one has seen before.

More importantly, HyperDbg is (for the most part) operating system-independent. We want to port HyperDbg to other operating systems like Linux and OS X.

## Conclusion

Reaching the goal of a transparent, fast, and innovative debugger is not possible without the help of the community of the developers. We believe those who use HyperDbg are professional computer programmers/reversers, and almost all of them can help in this project. So, what are you waiting for? Go ahead and add your own contributions to the project!
