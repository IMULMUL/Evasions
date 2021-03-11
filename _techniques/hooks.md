---
layout: post
title:  "Evasions: Hooks"
title-image: "/assets/icons/hooks.svg"
categories: evasions 
tags: hooks
---

<h1>Contents</h1>

[Hooks detection methods](#hooks-detection-methods)
<br />
  [1. Check whether hooks are set within system functions](#check-whether-hooks-are-set-within-system-functions)
<br />
  [2. Check for incorrectly hooked functions](#check-incorrectly-hooked-functions)
<br />
  [3. Check user clicks via mouse hooks](#check-user-clicks-via-mouse-hooks)
<br />
  [Signature recommendations](#signature-recommendations)
<br />
  [Countermeasures](#countermeasures)
<br />
  [Credits](#credits)
<br />
<br />

<hr class="space">

<h2><a class="a-dummy" name="hooks-detection-methods">Hooks detection methods</a></h2>
Techniques described here make use of hooks either to detect user presence or as means to be checked whether some unusual-for-host-OS hooks installed.

<br />
<h3><a class="a-dummy" name="check-whether-hooks-are-set-within-system-functions">1. Check whether hooks are set within system functions</a></h3>
Malware reads memory at specific addresses to check if Windows API functions are hooked.
<br />
This method is based on the fact, that emulation environments are most likely to hook these functions to be able to gather data and statistics during an emulation.

<hr class="space">

Popular functions to be checked:
<p></p>
<ul>
<li><tt>ReadFile</tt></li>
<li><tt>DeleteFile</tt></li>
<li><tt>CreateProcessA/W</tt></li>
</ul>

<hr class="space">

Reading memory is accomplished via the following functions:
<p></p>
<ul>
<li><tt>ReadProcessMemory</tt></li>
<li><tt>NtReadVirtualMemory</tt></li>
</ul>

<hr class="space">

Then different algorithms may be used for checking:
<p></p>
<ul>
<li>Comparing first two bytes with <tt>\x8B\xFF (mov edi, edi)</tt> — typical prologue start for <tt>kernel32</tt> functions.</li>
<li>Comparing first N bytes with <tt>\xCC</tt> - software breakpoint (<tt>int 3</tt>), not connected with hooks directly but still a suspicious behavior.</li>
<li>Comparing first N bytes with <tt>\xE9</tt> (<tt>call</tt>) or with <tt>\xEB</tt> (<tt>jmp</tt> instruction) — typical instructions for redirecting execution.</li>
<li>Checking for <tt>push/ret</tt> combo for execution redirection.</li>
</ul>
and so on.

<hr class="space">

It's pretty tricky to count for every possible comparison so general indication of something unusual in application's behavior is reading memory where OS libraries reside. If to be more precise: reading memory where "interesting" functions are situated.

<hr class="space">

<a href="https://0x00sec.org/t/defeating-userland-hooks-ft-bitdefender/12496">This atricle</a> explains how to detect user-mode hooks and remove them. The following code samples are taken from the article.

<hr class="space">

<b>Example of hook detection</b>
<p></p>

{% highlight c %}

HOOK_TYPE IsHooked(LPCVOID lpFuncAddress, DWORD_PTR *dwAddressOffset) {
    LPCBYTE lpBytePtr = (LPCBYTE)lpFuncAddress;

    if (lpBytePtr[0] == 0xE9) {
        *dwAddressOffset = 1;
        return HOOK_RELATIVE;    // E9 jmp is relative.
    } else if (lpBytePtr[0] == 0x68 &&  lpBytePtr[5] == 0xC3) {
        *dwAddressOffset = 1;
        return HOOK_ABOLSUTE;    // push/ret is absolute.
    }

    return HOOK_NONE;            // No hook.
}

LPVOID lpFunction = ...;
DWORD_PTR dwOffset = 0;
LPVOID dwHookAddress = 0;

HOOK_TYPE ht = IsHooked(lpFunction, &dwOffset);
if (ht == HOOK_ABSOLUTE) {
    // 1. Get the pointer to the address (lpFunction + dwOffset)
    // 2. Cast it to a DWORD pointer
    // 3. Dereference it to get the DWORD value
    // 4. Cast it to a pointer
    dwHookAddress = (LPVOID)(*(LPDWORD)((LPBYTE)lpFunction + dwOffset));
} else if (ht == HOOK_RELATIVE) {
    // 1. Get the pointer to the address (lpFunction + dwOffset)
    // 2. Cast it to an INT pointer
    // 3. Dereference it to get the INT value (this can be negative)
    INT nJumpSize = (*(PINT)((LPBYTE)lpFunction  + dwOffset);
    // 4. E9 jmp starts from the address AFTER the jmp instruction
    DWORD_PTR dwRelativeAddress = (DWORD_PTR)((LPBYTE)lpFunction + dwOffset + 4));
    // 5. Add the relative address and jump size
    dwHookAddress = (LPVOID)(dwRelativeAddress + nJumpSize);
}
{% endhighlight %}

<hr class="space">

<b>Example of unhooking functions</b>
<p></p>

{% highlight c %}

// Parse the PE headers.
PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)lpMapping;
PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpMapping + pidh->e_lfanew);

// Walk the section headers and find the .text section.
for (WORD i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
    PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pinh) + 
                                 ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
    if (!strcmp(pish->Name, ".text")) {
        // Deprotect the module's memory region for write permissions.
        DWORD flProtect = ProtectMemory(
            (LPVOID)((DWORD_PTR)hModule + (DWORD_PTR)pish->VirtualAddress),    // Address to protect.
            pish->Misc.VirtualSize,                        // Size to protect.
            PAGE_EXECUTE_READWRITE                         // Desired protection.
        );

        // Replace the hooked module's .text section with the newly mapped module's.
        memcpy(
            (LPVOID)((DWORD_PTR)hModule + (DWORD_PTR)pish->VirtualAddress),
            (LPVOID)((DWORD_PTR)lpMapping + (DWORD_PTR)pish->VirtualAddress),
            pish->Misc.VirtualSize
        );

        // Reprotect the module's memory region.
        flProtect = ProtectMemory(
            (LPVOID)((DWORD_PTR)hModule + (DWORD_PTR)pish->VirtualAddress),    // Address to protect.
            pish->Misc.VirtualSize,                        // Size to protect.
            flProtect                                      // Revert to old protection.
        );
    }
}
{% endhighlight %}

<hr class="space">

<br />
<h3><a class="a-dummy" name="check-incorrectly-hooked-functions">2. Check for incorrectly hooked functions</a></h3>
There are more than 400 Nt-functions in ntdll.dll that are usually hooked in sandboxes. In such a large list
there is enough space for different kind of mistakes.
An example of such a mistake is a lack of neccessary checks for all arguments in a hooked function. This case is described 
in our article "<a href="timing.html#call-hooked-function-with-invalid-arguments">Timing: Call a potentially hooked delay function with invalid arguments evasions</a>".
<br />
Another kind of mistake is discrepancy in the number of arguments in a hooked  
and original functions. If a function hooked incorrectly, in kernel mode this may lead operating system to crash. 
Incorrect user-mode hooks are not so harmfull, however they may lead an analyzed application to crash or can be
easily detected.
For example, lets look into the <tt>NtLoadKeyEx</tt> function. Natively it has 8 arguments:
    
    ; Exported entry 337. NtLoadKeyEx
    ; __stdcall NtLoadKeyEx(x, x, x, x, x, x, x, x)
    public _NtLoadKeyEx@32
    _NtLoadKeyEx@32 proc near
    
However, in Cuckoo monitor <tt>NtLoadKeyEx</tt> declaration there are only
<a href="https://github.com/cuckoosandbox/monitor/blob/7c5854fae12e1f01f56eab2db4008148c790cc7a/sigs/registry_native.rst#ntloadkeyex">4 arguments</a>:

    *  POBJECT_ATTRIBUTES TargetKey
    *  POBJECT_ATTRIBUTES SourceFile
    ** ULONG Flags flags
    ** HANDLE TrustClassKey trust_class_key
    
For some reason we can find the usage of this wrong prototype in other sources too. For example, 
<a href="https://github.com/ctxis/capemon/blob/e541d7ccd41d519de4198f7965c5b584d2a66ed6/hooks.h#L710">CAPE sandbox</a> contains the same error:

{% highlight c %}
extern HOOKDEF(NTSTATUS, WINAPI, NtLoadKeyEx,
    __in      POBJECT_ATTRIBUTES TargetKey,
    __in      POBJECT_ATTRIBUTES SourceFile,
    __in      ULONG Flags,
    __in_opt  HANDLE TrustClassKey
);
{% endhighlight %}

After the call of the incorrectly hooked function the stack pointer value will be invalid.  This fact can be used to 
detect a sandbox. We can store ESP value before the call of a potentially hooked function and compare it with the value 
after the function returns. If the values are different it means that the function is hooked incorrectly.

<b>Code sample</b>
<p></p>
{% highlight c %}
DWORD old_esp, new_esp;
_asm mov old_esp, ESP
NtLoadKeyEx(0, 0, 0, 0, 0, 0, 0, 0);
_asm mov new_esp, ESP
_asm mov ESP, old_esp

if (old_esp != new_esp)
    printf("Sandbox detected!");
{% endhighlight %}


<hr class="space">

<br />
<h3><a class="a-dummy" name="check-user-clicks-via-mouse-hooks">3. Check user clicks via mouse hooks</a></h3>
This technique is described <a href="https://www.fireeye.com/content/dam/fireeye-www/current-threats/pdfs/pf/file/fireeye-hot-knives-through-butter.pdf">by this link</a> (p.4, p.7).

<hr class="space">

Malware sets mouse hook to detect a click (or more) if it occurs. If it's the case malware treats the host a usual one, i.e., with end user behind the screen - not a virtual environment. If no mouse click is detected then it's very likely a virtual environment.

<hr class="space">

Functions used:
<p></p>
<ul>
<li><tt>SetWindowsHookExA/W (WH_MOUSE_LL, ...)</tt></li>
<li><tt>GetAsyncKeyState</tt></li>
</ul>

<hr class="space">

<b>Code sample (<tt>SetWindowsHookExA</tt>)</b>
<p></p>

{% highlight c %}

HHOOK g_hhkMouseHook = NULL;

LRESULT CALLBACK mouseHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
  switch (wParam)
  {
  case WM_MOUSEMOVE:
    // ...
    break;
  case WM_NCLBUTTONDOWN:
    // ...
    break;
  case WM_LBUTTONUP:
    UnhookWindowsHookEx(g_hhkMouseHook);
    CallMaliciousCode();
    ExitProcess(0);
  }
  return CallNextHookEx(g_hhkMouseHook, nCode, wParam, lParam);
}

g_hhkMouseHook = SetWindowsHookEx(WH_MOUSE_LL, mouseHookProc, GetModuleHandleA(NULL), NULL);
{% endhighlight %}

<hr class="space">

<b>Code sample (<tt>GetAsyncKeyState</tt>)</b>
<p></p>

{% highlight c %}

std::thread t([]()
{
  int count = 0;
  while (true)
  {
    if (GetAsyncKeyState(VK_LBUTTON) || GetAsyncKeyState(VK_RBUTTON) || GetAsyncKeyState(VK_MBUTTON))
    {
      if (++count == 2)
        break;
    }
    Sleep(100);
  }
  CallMaliciousCode();
});
t.join();
{% endhighlight %}

<br />
<h3><a class="a-dummy" name="signature-recommendations">Signature recommendations</a></h3>
<i>No signature recommendations are provided for this evasion group as it's hard to make a difference between the code which aims for some evasion technique and the one which is "legally used".</i>

<br />
<h3><a class="a-dummy" name="countermeasures">Countermeasures</a></h3>

<ul>
<li><tt>versus function hook checks:</tt> set kernel mode hooks; second solution is to use stack routing to implement function hooking;</li> 
<li><tt>versus mouse click checks via hooks:</tt> use mouse movement emulation module.</li> 
</ul>

<br />
<h3><a class="a-dummy" name="credits">Credits</a></h3>

Credits go to user <tt>dtm</tt> from  <a href="https://0x00sec.org/">0x00sec.org</a> forum.

Due to modular code structure of the Check Point's tool called InviZzzible it would require more space to show a code sample from this tool for the same purposes. That's why we've decided to use other great open-source projects for examples throughout the encyclopedia.
