# 1 Continuing Detours: the reinvention of Windows API Hooking #

Microsoft® Detours latest release was in December 2006. Now times have changed and the NET Framework has become more and more popular. EasyHook provides a way to hook unmanaged code from a managed environment. This implies several advantages:

  * No resource or memory leaks are left in the target
  * Support for Windows Vista SP1 and Windows Server 2008 SP1 by utilizing totally undocumented APIs, to still allow hooking into any terminal session.
  * You can write managed hook handlers for unmanaged APIs
  * All hooks are installed and automatically removed in a stable manner
  * You can use all the convenience managed code provides, like NET Remoting
  * EasyHook has done extensive work to provide managed handlers for unmanged code and this will finally lead into a stable way of hooking.
  * You will be able to write injection libraries and host processes compiled for AnyCPU, which will allow you to inject your code into 32- and 64-Bit processes from 64- and 32-Bit processes by using the very same assembly in all cases.
  * EasyHook supports RIP-relative addressing relocation for 64-Bit targets.

This way hooking has become a simple task and you can now write hooking applications like FileMon or RegMon with a few lines of code. Of course this is not the only thing you can do with hooking, which is limited by your mind only :-).

Why is that a reinvention? To make a long story short, EasyHook has nothing in common with any existing hooking library except that it hooks native code and can inject libraries. All in all, it provides impressive improvements, in any direction.


**Minimal software requirements** for end-users to execute applications using EasyHook:

  * Windows 2000 SP4 or later
  * Microsoft NET Framework 2.0 Redistributable
  * Microsoft Visual Studio 2005 SP1 Redistributable (only during Beta state of EasyHook)


---

## Table of Content ##

1 Continuing Detours: the reinvention of Windows API Hooking

1.1 A simple FileMon derivate

2 A deep look under the hook

2.1 Injection – A burden made easy

2.1.1 Creating an already hooked process

2.2 The injected library entry point

2.2.1 The library constructor

2.2.2 The library Run-Method

2.3 Injection helper routines

2.4 How to install a hook

2.5 How to write a hook handler

2.6 Using Thread ACLs

2.7 Using handler utilities

2.8 The IPC helper API



---

## 1.1 A simple FileMon derivate ##

To prove that EasyHook really makes hooking simple, look at the following demo application, which will log all file accesses from a given process. We need a host process which injects the library and displays file accesses. It is possible to combine injection library and host process in one file as both are just threaded as valid NET assemblies, but I think to separate them is a more consistent approach. This demo will be used throughout the whole guide:

```

using System;
using System.Collections.Generic;
using System.Runtime.Remoting;
using System.Text;
using EasyHook;

namespace FileMon
{
    public class FileMonInterface : MarshalByRefObject
    {
        public void IsInstalled(Int32 InClientPID)
        {
            Console.WriteLine("FileMon has been installed in target {0}.\r\n", InClientPID);
        }

        public void OnCreateFile(Int32 InClientPID, String[] InFileNames)
        {
            for (int i = 0; i < InFileNames.Length; i++)
            {
                Console.WriteLine(InFileNames[i]);
            }
        }

        public void ReportException(Exception InInfo)
        {
            Console.WriteLine("The target process has reported an error:\r\n" + InInfo.ToString());
        }

      public void Ping()
        {
        }
    }

    class Program
    {
        static String ChannelName = null;

        static void Main(string[] args)
        {
            try
            {
                Config.Install(typeof(Config).Assembly.Location);
                Config.Register(
                    "A FileMon like demo application.",
                    "FileMon.exe",
                    "FileMonInject.dll");

                RemoteHooking.IpcCreateServer<FileMonInterface>(ref ChannelName, WellKnownObjectMode.SingleCall);

                RemoteHooking.Inject(
                    Int32.Parse(args[0]),
                    InjectionOptions.None,
                    "FileMonInject.dll",
                    "FileMonInject.dll",
                    ChannelName);

                Console.ReadLine();
            }
            catch (Exception ExtInfo)
            {
                Console.WriteLine("There was an error while connecting to target:\r\n{0}", ExtInfo.ToString());
            }
        }
    }
} 
```

The most complex part is the injected library which has to fulfill various requirements. We are hooking the CreateFile-API and redirecting all requests to our host process. The library will be unloaded if the host process is terminated:
Collapse

```
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;
using EasyHook;

namespace FileMonInject
{
    public class Main : EasyHook.IEntryPoint
    {
        FileMon.FileMonInterface Interface;
        LocalHook CreateFileHook;
        Stack<String> Queue = new Stack<String>();

        public Main(
            RemoteHooking.IContext InContext,
            String InChannelName)
        {
            // connect to host...

            Interface = RemoteHooking.IpcConnectClient<FileMon.FileMonInterface>(InChannelName);
        }

        public void Run(
            RemoteHooking.IContext InContext,
            String InChannelName)
        {
            // install hook...
            try
            {
                LocalHook.BeginUpdate(true);

                CreateFileHook = LocalHook.Create(
                    LocalHook.GetProcAddress("kernel32.dll", "CreateFileW"),
                    new DCreateFile(CreateFile_Hooked),
                    this);

                LocalHook.EndUpdate();

                CreateFileHook.ThreadACL.SetExclusiveACL(new Int32[] { 0 });
            }
            catch (Exception ExtInfo)
            {
                Interface.ReportException(ExtInfo);

                return;
            }

            Interface.IsInstalled(RemoteHooking.GetCurrentProcessId());

            // wait for host process termination...
            try
            {
                while (true)
                {
                    Thread.Sleep(500);

                    // transmit newly monitored file accesses...
                    if (Queue.Count > 0)
                    {
                        String[] Package = null;

                        lock (Queue)
                        {
                            Package = Queue.ToArray();

                            Queue.Clear();
                        }

                        Interface.OnCreateFile(RemoteHooking.GetCurrentProcessId(), Package);
                    }
                    else
                        Interface.Ping();
                }
            }
            catch
            {
                // NET Remoting will raise an exception if host is unreachable
            }
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall,
            CharSet = CharSet.Unicode,
            SetLastError = true)]
        delegate IntPtr DCreateFile(
            String InFileName,
            UInt32 InDesiredAccess,
            UInt32 InShareMode,
            IntPtr InSecurityAttributes,
            UInt32 InCreationDisposition,
            UInt32 InFlagsAndAttributes,
            IntPtr InTemplateFile);

        // just use a P-Invoke implementation to get native API access from C# (this step is not necessary for C++.NET)
        [DllImport("kernel32.dll",
            CharSet = CharSet.Unicode,
            SetLastError = true,
            CallingConvention = CallingConvention.StdCall)]
        static extern IntPtr CreateFile(
            String InFileName,
            UInt32 InDesiredAccess,
            UInt32 InShareMode,
            IntPtr InSecurityAttributes,
            UInt32 InCreationDisposition,
            UInt32 InFlagsAndAttributes,
            IntPtr InTemplateFile);

        // this is where we are intercepting all file accesses!
        static IntPtr CreateFile_Hooked(
            String InFileName,
            UInt32 InDesiredAccess,
            UInt32 InShareMode,
            IntPtr InSecurityAttributes,
            UInt32 InCreationDisposition,
            UInt32 InFlagsAndAttributes,
            IntPtr InTemplateFile)
        {
            try
            {
                Main This = (Main)HookRuntimeInfo.Callback;

                lock (This.Queue)
                {
                    This.Queue.Push(InFileName);
                }
            }
            catch
            {
            }

            // call original API...
            return CreateFile(
                InFileName,
                InDesiredAccess,
                InShareMode,





                InSecurityAttributes,
                InCreationDisposition,
                InFlagsAndAttributes,
                InTemplateFile);
        }
    }
}
```

Even if this might look strange, the next chapters will explain what is done there and why. You may start this application with a user defined target process ID as one and only parameter from command line. I recommend using the PID of “explorer.exe” because this will immediately produce output! Just browse your file system while running the FileMon utility...


---

# 2 A deep look under the hook #

Now that you have seen the basic ideas of EasyHook and some sample code, we should start to discover what is really going on under the hood. In this chapter you will learn how to utilize most parts of the EasyHook API injecting libraries into any process and hooking any API you want.

If I refer to a specific EasyHook-API, please look them up in the API-Reference manual. Mostly I will explain them on introduction but I can’t cover all the services you will get for every API at this point! To point out the difference between this guide and the API-Reference: the latter one describes the use of every single method, class and all of its parameters in detail, whereas the first one covers how all common APIs may be used as a whole to hook any process. In fact this guide does only cover a small excerpt of what you will learn by reading the API-Reference and vice versa.

You should still look at the examples and try to understand them before you start writing your own applications!

## 2.1 Injection – A burden made easy ##

In general, library injection is one of the most complicated parts of any hooking library. But EasyHook goes further. It provides three layers of injection abstraction and your library is the fourth one. The first layer is pure, relocatable assembler code. It launches the second layer, an unmanaged C++ method. The assembler code itself is really stable. It provides extensive error information and is able to unload itself without leaving any resource leaks in the target. The C++ layer starts the managed injection loader and adjusts the target’s PATH variable by adding the injecting process’ application base directory as first entry. This way you will have access to any file you would also have access to from your injecting process. The managed injection loader uses NET Reflection and NET Remoting to provide extensive error reports in case of failure and to find a proper entry point in your injection library. It also cares about graceful hook removal and resource cleanup. It is supported to load the same library multiple times into the same target!

Another complex part is run on host side. It is supported to inject libraries into other terminal sessions, system services and even through WOW64 boundaries. To you, all cases seem the same. EasyHook will automatically select the right injection procedure. If EasyHook has succeeded injection, you can be 99% sure that your library has been successfully loaded and executed. If it fails you can be 99% sure that no resource leaks are left in the target and it remains in a stable, hookable state! Nearly all possible failures are being caught and it would be like a lottery win to see a target getting crashed by library injection!
Please note that Windows Vista has advanced security for its subsystem services. They are running in a protected environment like the “Protected Media Path”. It is not possible to hook such services with EasyHook or any other user-mode library.
The following shows the API method that we are talking about:

```
RemoteHooking.Inject(
         Int32.Parse(args[0]),
         InjectionOptions.None,
         "FileMonInject.dll", // 32-Bit version
         "FileMonInject.dll", // 64-Bit version
         ChannelName); 
```

The first four parameters are required. If you only want to hook either 32- or 64-Bit targets, you can set the unused path to null. You may either specify a file path that EasyHook will automatically translate to a full qualified assembly name or a partial assembly name like “FileMonInject, PublicKeyToken = 3287453648abcdef”. Currently there is only one injection option preventing EasyHook from attaching a debugger to the target but you should only set this option if the target does not like an attached debugger. EasyHook will detach it before injection is completed so in general there is nothing to worry about and it increases injection stability about magnitudes by using the target symbol addresses instead of assuming that the local ones remain valid in the target!

You can pass as many additional parameters as you like but be aware of that you shall only pass types that are accessible through GAC, otherwise the injected library is not able to deserialize the parameter list. In such a case the exception will be redirected to the host process and you may catch it with a try-catch statement around RemoteHooking.Inject(). That’s one of the great advantages!

The injected library will automatically get access to all additional parameters you specify after the fourth one. This way you can easily pass channel names to the target so that your injected library is able to connect to your host.
Attention

Keep in mind that the CLR will unload your library only if the target is being terminated. Even if EasyHook releases all associated resources much earlier, you won’t be able to change the injected DLL which implies that the corresponding GAC library is not updateable until the target is terminated. So if you need to change your injected library very frequently (during development) you should always terminate the target after each debugging session. This will ensure that no application depends on the library and it can be removed from the GAC.

### 2.1.1 Creating an already hooked process ###

Sometimes it is necessary to hook a process from the beginning. This is no big deal, just call RemoteHooking.CreateAndInject() instead of Inject(). This will execute your library main method before any other instruction. You can resume the newly created process by calling RemoteHooking.WakeUpProcess() from your injected library Run() method. This only makes sense in conjunction with CreateAndInject(), otherwise it will do nothing.

## 2.2 The injected library entry point ##

All injected libraries have to export at least one public class implementing the EasyHook.IEntryPoint interface. The interface itself is empty but identifies your class as entry point. A class marked as entry point this way, is expected to export an instance constructor and a Run() instance method having the signature “void Run(IContext, %ArgumentList%)” and “.ctor(IContext, %ArgumentList%)”. Please note that “%ArgumentList%” is a placeholder for additional parameters passed to RemoteHooking.Inject(). The list is starting with the fifth parameter you passed to Inject() and will be passed to both, the constructor and Run(). The list is not passed as array but as expanded parameter list. For example if you call Inject(Target, Options, Path32, Path64, String, Int32, MemoryStream), then %ArgumentList% would be “String, Int32, MemoryStream” and your expected Run() signature “void Run(IContext, String, Int32, MemoryStream)”. EasyHook enforces strict binding which means that the parameter list is not casted in any way. The types passed to Inject() shall be exactly the same as in the Run() signature. I hope this explains it.

The next thing to mention is that you should avoid using static fields or properties. Only if you know for sure that it is not possible having two instances of your library in the same target simultaneously, you can safely use static variables!

### 2.2.1 The library constructor ###

The constructor is called immediately after EasyHook has gained control in the target process. You should only connect to your host and validate the parameters. At this point EasyHook already has a working connection to the host so all exceptions you are leaving unhandled, will automatically be redirected to the host process. A common constructor may look like this:

```
public class Main : EasyHook.IEntryPoint
{
    FileMon.FileMonInterface Interface;
    LocalHook CreateFileHook;
    Stack<String> Queue = new Stack<String>();

    public Main(RemoteHooking.IContext InContext, String InChannelName)
    {
        // connect to host...
        Interface = RemoteHooking.IpcConnectClient<FileMon.FileMonInterface>(InChannelName);


        // validate connection...
        Interface.Ping();
    }
} 
```

### 2.2.2 The library Run-Method ###

The Run() method can be threaded as application entry point. If you return from it, your library will be unloaded. But this is not really true ;-). In fact your library stays alive until the CLR decides to unload it. This behavior might change in future EasyHook versions by utilizing the CLR Hosting API, but currently we simply don’t know about! EasyHook will continue to call a cleanup thread every thirty seconds that initiates a GC for your library. In general this will soon cleanup all consumed resources and hooks.

In contrast to the constructor, your Run() method has no exception redirection. If you leave any exception unhandled, it will just initiate the usual unload procedure. In debug versions of EasyHook, you will find such unhandled exceptions in event logs. You should install all hooks and notify your host about success, what might look like this:
Collapse

```
public void Run(RemoteHooking.IContext InContext, String InChannelName)
{
    // install hook...
    try
    {
        LocalHook.BeginUpdate(true);

        CreateFileHook = LocalHook.Create(
            LocalHook.GetProcAddress("kernel32.dll", "CreateFileW"),
            new DCreateFile(CreateFile_Hooked),
            this);

        LocalHook.EndUpdate();

        CreateFileHook.ThreadACL.SetExclusiveACL(new Int32[] {0});
    }
    catch(Exception ExtInfo)
    {
        Interface.ReportException(ExtInfo);

        return;
    }

    Interface.IsInstalled(RemoteHooking.GetCurrentProcessId());

    // wait for host process termination...
    try
    {
        while (true)
        {
            Thread.Sleep(500);

            // transmit newly monitored file accesses...
            if (Queue.Count > 0)
            {
                String[] Package = null;

                lock (Queue)
                {
                    Package = Queue.ToArray();

                    Queue.Clear();
                }

                Interface.OnCreateFile(RemoteHooking.GetCurrentProcessId(), Package);
            }
            else
                Interface.Ping();
        }    
    }
    catch
    {
        // NET Remoting will raise an exception if host is unreachable
    }
} 
```

The loop simply sends the currently queued files accesses to the host process. If the host process is being terminated, such attempts throw an exception which causes the CLR to return from the Run() method and automatically unload your library!

## 2.3 Injection helper routines ##

There are several methods that you will find useful when dealing with injection.
To query if the current user is administrator, you can use RemoteHooking.IsAdministrator. Please note that injection will fail in most cases if you don’t have admin privileges! Vista is using the UAC evaluating to admin privileges and so you should read some MSDN articles about how to utilize it.

If you already are admin, you may use the RemoteHooking.ExecuteAsService

&lt;T&gt;

() method to execute a given static method under system privileges without the need to start a service. This is potentially useful when enumerating running processes of all sessions or for any other information querying task, which might require highest privileges. Keep in mind that the static method will be executed within a system service. So any handle or other process related information will be invalid when transmitted back into your process. You should design such a method so that you retrieve all information and store it in a serializable, process independent form. This form shall be an object that is returned and this way sent back to your application by NET Remoting.

If you want to determine whether a target process is 64-Bit or not, you may use RemoteHooking.IsX64Process(). But be aware of that you need PROCESS\_QUERY\_INFORMATION access to complete the call. It will also work on 32-Bit only Windows versions like Windows 2000, of course, by returning false in any case.
Further there are RemoteHooking.GetCurrentProcessId() and GetCurrentThreadId() which might help to query the real native values in a pure managed environment! Managed thread IDs don’t necessarily map to native ones, when thinking about the coming NET FX.

## 2.4 How to install a hook ##

To install a hook you are required to pass at least two parameters. The first one is the entry point address you want to hook and the second one is the delegate where calls should be redirected to. The delegate shall have the UnmanagedFunctionPointerAttribute and also the exact call signature as the corresponding P-Invoke implementation. The best way is to look for a well tested P-Invoke implementation already out in the net and just make a delegate out of it. The managed hook handler also has to match this signature what is automatically enforced by the compiler… A P-Invoke implementation with the DllImportAttribute may be used to call the original API within the handler which will be necessary in most cases. Don’t forget that most APIs are expected to SetLastError() in case of failure. So you should set it to ERROR\_ACCESS\_DENIED or ERROR\_INTERNAL\_ERROR for example if your code does not want to execute the call. Otherwise external code might behave unexpected!

A third parameter provides a way to associate an uninterpreted callback object with the hook. This is exactly the object accessible through HookRuntimeInfo.Callback later in the handler.
EasyHook provides a level based transactional way for installing hooks. That means you may use several levels of hook installation code and commit/rollback each level separately. Only the final call to LocalHook.EndUpdate() will install all remaining hooks (some hooks might be removed due to rollback of sublevels; of course you could cancel the overall installation in such cases). BeginUpdate() will also take one argument specifying if the engine should ignore warnings. Warnings are evaluated in the final EndUpdate() call and occur if the engine “is thinking” that a hook may violate process stability. For example if the entry point is already hooked or contains other unusual machine code potentially causing side effects, a warning is raised. If you ignore warnings this will have no effect but otherwise the installation will be rolled back and an exception thrown. Note that you may set the warning state for each level. If no exception is thrown by the finally EndUpdate() all hooks of all non-cancelled levels have been installed; otherwise you can be sure that no hook has been installed! And this is why it is transactional.
As only the last EndUpdate() call will install any hooks the overall process is something like a delayed installation. Local thread ACLs and various other properties are only accessible for installed hooks and will throw an exception if accessed during the root BeginUpdate() EndUpdate() level or any sublevel. You may always use the LocalHook.IsInstalled property to check if a given hook is installed. If so you can also use all other properties!

To uninstall a hook just remove all references to the object obtained during creation. To prevent it from being uninstalled you have to keep the reference of course… This is always a delayed removal because you won’t know when a hook is finally removed and your handler is never called again. If you want to remove it immediately you have to call LocalHook.Dispose() like known from dealing with unmanaged resources as file streams are.
The following code snipped is an example of how to install a hook that is excluding the current thread from being intercepted:

```
LocalHook.BeginUpdate(true);
{
    CreateFileHook = LocalHook.Create(
            LocalHook.GetProcAddress("kernel32.dll", "CreateFileW"),
            new DCreateFile(CreateFile_Hooked),
            this);
}
LocalHook.EndUpdate();

CreateFileHook.ThreadACL.SetExclusiveACL(new Int32[] {0}); 
```

In debug versions of EasyHook, this will also output some extensive error information in the console and in the event logs. To access such information in release versions, you may call LocalHook.QueryJournal(). If you encounter any weird error during hooking, please include this journal in your error report. A journal does only contain useful information AFTER all hooks have been (tried to be) installed!

EasyHook also does provide a way to install pure unmanaged hooks using LocalHook.CreateUnmanaged(). You may write them using C++.NET that allows you to combine managed and unmanaged code. But keep in mind that you won’t have access to the HookRuntimeInformation class, this is why you can’t specify a callback for unmanaged hooks. All protection mechanisms (see next paragraph) will still wrap around your code. An empty unmanaged hook is about magnitudes faster than an empty managed one. If your handler once has gained execution, both are running with the same speed. The costly operation is the switch from unmanaged to managed environment and vice versa, which is not required when using pure unmanaged hooks! So your handler will be invoked in approx. 70 nanoseconds whereas a managed handler requires up to some microseconds… In some scenarios you will need this speed gain and this is why EasyHook offers it.

## 2.5 How to write a hook handler ##

Until now there was nothing complicated and I hope you agree. But writing a hook handler is something very strange. EasyHook already does provide several mechanisms to make writing hook handlers much easier or let’s say possible at all (I can’t imagine writing stable hook handlers for Detours):

  * A Thread Deadlock Barrier (TDB) which will allow you and any subcalls to invoke the hooked API from within its handler again. Normally this would lead into a deadlock because the handler would invoke itself again and again. EasyHook will prevent such loops! This also provides the advantage that you don’t need to keep track of a clean entry point.
  * An OS loader lock protection which will prevent your handler from being executed in an OS loader lock and in case of managed handler code attempting so would crash the process!
  * A TDB self protection which will protect the TDB itself from invoking any hook. This way you are able to hook any API except TlsGetValue/TlsSetValue or FlsGetValue/FlsSetValue (if supported), because even if the TDB requires some well known API methods, like HeapAlloc(), you can still hook them because of the TDB self protection!
  * A Thread ACL model allowing you to exclude well known dedicated threads, used to manage your hooking library (for example threads that are communicating with your host), from being intercepted. Refer to the chapter “Guidelines for stable hooking”, to learn about the differences and why the TDB is not enough!
  * A mechanism to provide hook specific callbacks through a static class namedHookRuntimeInfo. This way you are able to access the library instance without using a static variable for example. You may even query the hook’s return address and initial RSP value, providing information about which code portion has invoked the current interception. A stack trace can only be made with this information because the EasyHook prolog code will prevent a usual stack trace!

Without some of the above mechanisms it would be simply impossible to use managed code as hook handler and this is what is unique to EasyHook. All of those mechanisms are very stable and heavily tested with hundred simultaneous threads executing hundred thousands of hooks (on a quad-core CPU).

Using a hook handler you can simply provide your own implementation for the hooked API. But you should read and understand the related API documentation in detail, to provide the correct behavior for external code. If it is possible you should handle an interception as fast as possible and negotiate access or whatever within the injected library. Only in rare cases you should redirect calls to the host application in a synchronous manner as this will heavily slow down the hooked application; for example if an access negotiation can’t be completed with the knowledge of the library. In a real world application you should queue all requests and transmit them periodically as an array and not every single call. This can be done like it is shown in the FileMon demo.

Keep in mind that if you are compiling for 64-Bit or AnyCPU, you have to use the right type replacements. For example HANDLE does NOT map to Int32, but to IntPtr. In case of 32-Bit this is not important but when switching to 64-Bit a handle is 64-Bit wide, like IntPtr. A DWORD in contrast will always be 32-Bit as its name implies.
The following is an example hook handler as used in the FileMon demo:
Collapse

```
static IntPtr CreateFile_Hooked(
    String InFileName, 
    UInt32 InDesiredAccess, 
    UInt32 InShareMode, 
    IntPtr InSecurityAttributes,
    UInt32 InCreationDisposition, 
    UInt32 InFlagsAndAttributes, 
    IntPtr InTemplateFile)
{
    try
    {
        Main This = (Main)HookRuntimeInfo.Callback;

        lock (This.Queue)
        {
            This.Queue.Push(InFileName);
        }
    }
    catch
    {
    }

    // call original API...
    return CreateFile(
        InFileName, 
        InDesiredAccess, 
        InShareMode, 
        InSecurityAttributes, 
        InCreationDisposition,
        InFlagsAndAttributes, 
        InTemplateFile);
}
```

## 2.6 Using Thread ACLs ##

EasyHook manages a global ThreadACL and also an ACL for every hook. Further each ACL can either be inclusive or exclusive. This allows you to compose nearly any kind of access negotiation based on thread IDs without much effort. By default EasyHook sets an empty global exclusive ACL, which will grant access for all threads, and an empty inclusive local ACL for every hook, which will finally deny access for all threads. You see that the local ACLs are of higher importance and will overwrite the global ACL for a specific hook. All hooks are installed virtually suspended meaning no threads will pass access negotiation. This is to prevent hook handler invocation before you are able to initialize possible structures, like ACLs for example. To enable a hook for all threads just set its local ACL to an empty exclusive one. To enable it for the current thread only, just set a local inclusive ACL with zero as one and only entry. A thread ID of zero will automatically be replaced by the current thread ID BEFORE the ACL is set (this is negotiation will later use your thread ID and doesn’t know anything about zero). The following is a pseudo-code of IsThreadIntercepted() and should be self explaining:

```
if(InThreadID == 0)
    InThreadID = GetCurrentThreadId();

if(GlobalACL.Contains(InThreadID))
{
    if(LocalACL.Contains(InThreadID))
    {
        if(LocalACL.IsExclusive)
            return false;
    }
    else
    {
        if(GlobalACL.IsExclusive)
            return false;

        if(!LocalACL.IsExclusive)
            return false;
    }
}
else
{
    if(LocalACL.Contains(InThreadID))
    {
        if(LocalACL.IsExclusive)
            return false;
    }
    else
    {
        if(!GlobalACL.IsExclusive)
            return false;

        if(!LocalACL.IsExclusive)
            return false;
    }
}

return true; 
```

A return value of true will grant access and false will deny it. Just play around with them and use LocalHook.IsThreadIntercepted() to check whether your ACLs will provide expected access negotiation.

## 2.7 Using handler utilities ##

EasyHook exposes some debugging routines which may be extended in future versions. They are statically available through the EasyHook.Debugger class. Currently they solve the following issues which are common when writing hook handlers:

  * Translate a thread handle back to its thread ID (requires the handle to have THREAD\_QUERY\_INFORMATION access).
  * Translate a process handle back to its process ID (requires the handle to have PROCESS\_QUERY\_INFORMATION access).
  * Query kernel object information for any given handle. This way you are able to convert a file handle obtained by CreateFile() back to its file name. This will even work if the handle has no access to anything! Please note that this method is quiet slow and you should maintain a handle directory by hooking CloseHandle() to call it only once per handle!
  * Disassemble a given machine code portion into human readable text. This will allow you to provide advanced error information in case of failure… EasyHook is using this internally and I don’t know if you will need it ;-).

There is nothing special to know about, just read the corresponding API references. The latter two will only work if debugging is available and enabled (which is the default). On windows 2000 a debugger is not available and so also the latter two methods… To still support them, just ship the 32-Bit libraries “dbgeng.dll” and “dbghelp.dll” of the “Microsoft Debugging Tools for Windows 32-Bit Version” with your application and put them into the application base directory where also “EasyHook.dll” should be located! This will additionally consume four MBs of space… For windows XP and later you don’t need to do this because all required libraries are already included in every clean installation. Of course EasyHook itself is designed to work without a debugger if it is not available!

The first two methods will supply additional error information if a debugger is available. This is whether the handle is valid or not, whether it was opened with required access and whether the handle type is matching.

## 2.8 The IPC helper API ##

The core part of any target-host scenario is IPC. With NET remoting this has become really amazing. As you can see in the FileMon demo it is a thing of two lines to setup a stable, fast and secure IPC channel between the injected library and host. Of course this is only possible with the IPC helper routines exposed by EasyHook. Using the native IpcChannels the code blows up to three A4 pages which is still quiet small. The helper routines will take care of serialization setup and channel privileges so that you can even connect a system service with a normal user application running without admin privileges. It also offers to generate a random port name. This service should always be used because it is the only way to get a connection secure! If you want to provide your own name, you also have to specify proper well known SIDs, which are allowed to access the channel. You should always specify the built in admin group in this case, because all admin users could crash the whole system so you don’t have to worry about being exploited by an admin!

To create a server with a random port name, just call:

```
String ChannelName = null;

RemoteHooking.IpcCreateServer<FileMonInterface>(
            ref ChannelName, 
            WellKnownObjectMode.SingleCall);
```

Pass the generated port name to the client and call:

```
FileMon.FileMonInterface Interface = 
    RemoteHooking.IpcConnectClient<FileMon.FileMonInterface>(InChannelName); 
```

From now on you are able to call the server by using the client instance of the returned underlying MarshalByRefObject and those calls will be automatically redirected to the server. Isn’t that great?! But be aware of that this will only apply to instance members! Static members and fields will always be processed locally…