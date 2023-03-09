# ShellCodeExec

### This shellcode loader works without any imports and uses my own headers to parse PE, strings...

* Use NT functions
* Resolve nt functions with custom GetProcAddress and GetModuleHandle
* Use a 'custom' malloc function with NtAllocateVirtualMemoy
* Works for both x86 (WoW64) & x64

![64](https://user-images.githubusercontent.com/42241901/224010127-2fdfd26c-e6bc-40f3-af19-27a671924a5c.png)

![86](https://user-images.githubusercontent.com/42241901/224010134-77ee865a-f5db-4519-9fe9-a79c8db30b9d.png)
