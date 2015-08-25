**Project Description**

EasyHook starts where Microsoft Detours ends.
This project supports extending (hooking) unmanaged code (APIs) with pure managed ones, from within a fully managed environment like C# using Windows 2000 SP4 and later, including Windows XP x64, Windows Vista x64 and Windows Server 2008 x64. Also 32- and 64-bit kernel mode hooking is supported as well as an unmanaged user-mode API which allows you to hook targets without requiring a NET Framework on the customers PC. An experimental stealth injection hides hooking from most of the current AV software.

**The following is an incomplete list of features:**

  * A so called "Thread Deadlock Barrier" will get rid of many core problems when hooking unknown APIs; this technology is unique to EasyHook
  * You can write managed hook handlers for unmanaged APIs
  * You can use all the convenience managed code provides, like NET Remoting, WPF and WCF for example
  * A documented, pure unmanaged hooking API
  * Support for 32- and 64-bit kernel mode hooking (also check out my PatchGuard 3 bypass driver which can be found in the release list)
  * No resource or memory leaks are left in the target
  * Source code was rewritten entirely and this will greatly improve performance, stability and maintainability
  * Experimental stealth injection mechanism that won't raise attention of any current AV Software
  * EasyHook32.dll and EasyHook64.dll are now pure unmanaged modules and can be used without any NET framework installed!
  * All hooks are installed and automatically removed in a stable manner
  * Support for Windows Vista SP1 x64 and Windows Server 2008 SP1 x64 by utilizing totally undocumented APIs, to still allow hooking into any terminal session.
  * Managed/Unmanaged module stack trace added
  * Get calling managed/unmanaged module inside a hook handler
  * Create custom stack traces inside a hook handler
  * You will be able to write injection libraries and host processes compiled for AnyCPU, which will allow you to inject your code into 32- and 64-Bit processes from 64- and 32-Bit processes by using the very same assembly in all cases.
  * EasyHook supports RIP-relative addressing relocation for 64-Bit targets.
  * License has changed to Lesser GPL (LGPL)
  * No unpacking/installation necessary anymore.
  * No CRT bindings for release configurations, reducing deployment size about some megabytes.
  * The Visual Studio Redistributable is not required anymore.
  * First feature complete release of EasyHook...


The library is currently still in BETA state, but should be stable enough for development. Don't hesitate to report any bugs you find, because that's the only way for me to fix them. You can be sure that any serious bug you report, will be fixed soon...

**Donations to support Intel Itanium**

I want to add support for Itanium, so that EasyHook will span through all architectures, platforms and modes (managed/unmanaged/kernel). If anyone has used/new hardware, supporting Itanium, which he/she can donate, please contact me. Also money for buying such hardware would be appreciated! As I am currently a student, I can't effort this myself. Of course we could talk about some sponsorship agreements...

**WHAT ARE THE IMPACTS OF THE LICENSE CHANGE?**

To wrap it up (without warranty):

  1. You are granted to sell any software that uses EasyHook over DLL, NET bindings or EasyHookQueryInterface(). This is covered by the native API and the managed interface.
  1. You are NOT granted to sell any software that includes parts of the EasyHook source code or any modification! If you want to modify EasyHook, you are forced to release your work under the LGPL or GPL... Of course this only applies to the library itself. For example you could release a modification of EasyHook under LGPL, while still being able to release software, which takes advantage of this modification over DLL or NET bindings, under a proprietary license!
  1. You shall include a visible hint in your software that EasyHook is used as module and also point out, that this module in particular is released under the terms of the LGPL and NOT under the terms of your software (assuming that your software has another license than LGPL or GPL).


I decided to release EasyHook under LGPL to prevent commercial abuse of this free work. I didn't release it under GPL, because I also want to address commercial vendors which are more common under Windows.

Best regards
Christoph Husse