---
title: "Import Address Table (IAT) in action"
date: "2017-04-11"
categories: 
  - "debugging"
  - "user-mode"
tags: 
  - "firstthunk"
  - "forwardchain"
  - "iat"
  - "image_import_descriptor"
  - "import-address-table-address"
  - "orginalfirstthunk"
  - "timedatestamp"
coverImage: "../../assets/images/import-address-table.png"
author:
  name: Mohammad Sina Karvandi
  link: https://twitter.com/Intel80x86
---

![](../../assets/images/import-address-table.png)

Did you ever think about how different dll files with different versions and obviously with different addresses of functions work perfectly together ? The answer is Import Address Table (IAT).

In the previous [post](/topics/how-to-get-every-details-about-ssdt-gdt-idt-in-a-blink-of-an-eye/) I describe about how to get SSDT. IAT is somehow a User-Mode version of SSDT and in this post I’m gonna write about what I read and experience about IAT in action.

![](../../assets/images/import-address-table.png)

Why IAT is important ? It is important because it gives PE executer a list of Functions pointer which normally used to jump to Windows API’s functions. That’s okay but the thing is most of packers and protectors that I see just destroy this table ! So it is important for a reverser to know about this table because if you don’t know about it, simply can’t dump a packed exe .

All normal (Not packed) application make this table at first so in the future calls they can use calls or jumps to this addresses to reach to the functions and put function pointer to eip register.

For example, I see this kind of calling a lot in ollydbg :

Call jmp&.Kernel32.ExitProcessA

Which points to IAT version of ExitProcessA in Kernel32.dll image.

One of the ways to easily hook functions is to change IAT’s addresses so the new invoked functions come to your code instead of original function.

Where is IAT ?!

For creating IAT, process first create a import table by going to “ImageBase (Most of times 0x400000) + 0x3C” in this address you can find a pointer that you can find import table address in (the pointer + 0x80). This table consists of multiple variables in a structure which is called Image\_Import\_Descriptor and ends with a null Image\_Import\_Descriptor. The first variable of this structure is OrginalFirstThunk. This field is actually a backup variable (I explain it more in later paragraph in this post.)

The second parameter is TimeDateStamp (Which probably points to time or version of building function but can be null) and the third is ForwardChain (Can be null too) and last is Name.

Then process just follows the FirstThunk address and goes to dll to find the address of function which FirstThunk points to. If with any reason it can’t find the function then try it again by using OrginalFisrtThunk instead of FirstThunk and if it can’t find it again then simply the program crashes !

IAT is actually in .data but if you are interfering with some kinds of packers or proctors it can be different or completely destroyed because if you dump an exe with a destroyed IAT it doesn’t work. If you find IAT in your debugger then keep in mind that all addresses separate with two null dword.

I write this post because I can’t find any complete description about how IAT works in action but I simply describe how it works so if you have any problem with finding IAT then you can comment in this post.

In future posts I will explain about how to build new IAT when this table is destroyed by packers or protectors.
