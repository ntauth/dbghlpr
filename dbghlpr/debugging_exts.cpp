#define _CRT_SECURE_NO_WARNINGS
#include <engextcpp.hpp>
#include <windows.h>
#include <TlHelp32.h>
#include <stdio.h>

#include <list>
#include <memory>
#include <strsafe.h>

#include <interface.h>
#include <engine.h>

#include <capstone.h>
#include <engine_linker.h>
#include <helper.h>

typedef struct __tag_thread_args__
{
	unsigned long pid;
	DLL_ARGS dll_args;
}thread_args, *thread_args_ptr;

DWORD WINAPI suspend_process_thread(LPVOID args)
{
	thread_args_ptr pta = (thread_args_ptr)args;
	unsigned long pid = pta->pid;
	DLL_ARGS dll_args = pta->dll_args;

	free(pta);

	module_load_information_type module_load_info;
	if (install(L"suspend.dll", pid, &module_load_info, dll_args))
	{
		dprintf("loader base=>0x%0*I64x, size=>%x\n", 16, (unsigned long long)module_load_info.loader_address, (unsigned long)module_load_info.size_of_loader);
		dprintf("module image base=>0x%0*I64x, size=>%x\n", 16, (unsigned long long)module_load_info.module_load_address, (unsigned long)module_load_info.size_of_module_image);

		ResumeThread(module_load_info.main_thread_handle);

		DWORD exit_code = 0;
		WaitForSingleObject(module_load_info.main_thread_handle, INFINITE);
		GetExitCodeThread(module_load_info.main_thread_handle, &exit_code);

		VirtualFreeEx(module_load_info.target_process_handle, module_load_info.loader_address, module_load_info.size_of_loader, MEM_RELEASE);
		VirtualFreeEx(module_load_info.target_process_handle, module_load_info.module_load_address, module_load_info.size_of_module_image, MEM_RELEASE);

		CloseHandle(module_load_info.main_thread_handle);
		CloseHandle(module_load_info.target_process_handle);

		//g_Ext->ExecuteSilent("qd");

		g_Ext->Dml("<b><col fg=\"changed\">break=>%x\n\n</col></b>", dll_args.break_point);
	}
	else
		dprintf("install fail\n");

	return 0;
}

#if 0
EXT_CLASS_COMMAND(WindbgEngine, rbc, "", "{p;ed,o;p;;}") // rbc = remote break code
{
	if (!g_Ext->IsLiveLocalUser())
		return;

	DLL_ARGS dll_args;
	unsigned long pid;

	if (g_Ext->m_System->GetCurrentProcessSystemId(&pid) != S_OK)
		return;
	if (!g_Ext->HasArg("p"))
		return;

	GetCurrentDirectoryW(MAX_PATH, dll_args.dll_path);

	dll_args.break_point = GetArgU64("p", FALSE);
#if 1
	module_load_information_type module_load_info;
	if (install(L"suspend.dll", pid, &module_load_info, dll_args))
	{
		dprintf("loader base=>0x%0*I64x, size=>%x\n", 16, (unsigned long long)module_load_info.loader_address, (unsigned long)module_load_info.size_of_loader);
		dprintf("module image base=>0x%0*I64x, size=>%x\n", 16, (unsigned long long)module_load_info.module_load_address, (unsigned long)module_load_info.size_of_module_image);

		ResumeThread(module_load_info.main_thread_handle);

		DWORD exit_code = 0;
		WaitForSingleObject(module_load_info.main_thread_handle, INFINITE);
		GetExitCodeThread(module_load_info.main_thread_handle, &exit_code);

		VirtualFreeEx(module_load_info.target_process_handle, module_load_info.loader_address, module_load_info.size_of_loader, MEM_RELEASE);
		VirtualFreeEx(module_load_info.target_process_handle, module_load_info.module_load_address, module_load_info.size_of_module_image, MEM_RELEASE);

		CloseHandle(module_load_info.main_thread_handle);
		CloseHandle(module_load_info.target_process_handle);

		g_Ext->ExecuteSilent("qd");
		//g_Ext->Dml("<b><col fg=\"changed\">break=>%x\n\n</col></b>", dll_args.break_point);
	}
	else
		dprintf("install fail\n");
#endif

#if 0
	thread_args_ptr pta = (thread_args_ptr)malloc(sizeof(thread_args));
	memset(pta, 0, sizeof(thread_args));

	pta->pid = pid;
	pta->dll_args = dll_args;

	unsigned long tid = 0;
	HANDLE h_thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)suspend_process_thread, pta, 0, &tid);
	if (WaitForSingleObject(h_thread, 1000) == WAIT_TIMEOUT)
	{
		g_Ext->ExecuteSilent("qd");
	}
#endif
}
#endif

EXT_CLASS_COMMAND(WindbgEngine, suspend, "", "{p;ed,o;p;;}")
{
	THREADENTRY32 thread_block32 = { 0, };
	HANDLE h_snapshot = NULL;
	HANDLE h_thread = NULL;
	DWORD s = 0;

	unsigned long pid;

	if (g_Ext->m_System->GetCurrentProcessSystemId(&pid) != S_OK)
		return;

	helper::suspend(pid);
}

EXT_CLASS_COMMAND(WindbgEngine, resume, "", "{p;ed,o;p;;}")
{
	THREADENTRY32 thread_block32 = { 0, };
	HANDLE h_snapshot = NULL;
	HANDLE h_thread = NULL;
	DWORD s = 0;

	unsigned long pid;

	if (g_Ext->m_System->GetCurrentProcessSystemId(&pid) != S_OK)
		return;

	helper::resume(pid);
}

//
// break point 1.
//
void __stdcall print32(unsigned long long c, unsigned long long b)
{
	if (c != b)
		g_Ext->Dml("<b><col fg=\"changed\">%08x</col></b>", (unsigned long)c);
	else
		dprintf("%08x", c);
}

EXT_CLASS_COMMAND(WindbgEngine, bc, "", "{p;ed,o;p;;}") // bc = break code
{
	if (!g_Ext->IsLiveLocalUser())
		return;

	engine_linker linker;
	cpu_context_type context;
	memset(&context, 0, sizeof(context));

	if (!linker.get_thread_context(&context))
	{
		g_Ext->Dml("<b><col fg=\"changed\">thread context:: catch miss..\n</col></b>");
	}

	unsigned long pid;
	if (g_Ext->m_System->GetCurrentProcessSystemId(&pid) != S_OK)
		return;
	if (!g_Ext->HasArg("p"))
		return;

	HANDLE token_handle = nullptr;
	TOKEN_PRIVILEGES tp;
	if (OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token_handle))
	{
		memset(&tp, 0, sizeof(tp));
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		tp.Privileges[0].Luid.LowPart = 20;
		tp.Privileges[0].Luid.HighPart = 0;

		AdjustTokenPrivileges(token_handle, FALSE, &tp, 0, NULL, NULL);
		CloseHandle(token_handle);
	}

	HANDLE process_handle = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid);
	if (!process_handle)
	{
		dprintf("%d open fail..\n", pid);
		return;
	}

	unsigned long long ip = GetArgU64("p", FALSE);
	if (helper::patch(process_handle, ip) == 0)
	{
		dprintf("patch fail..\n");
		return;
	}

	unsigned long tid = 0;
	do
	{
		tid = helper::check_thread(pid, ip);
	} while (tid == 0);

	if (helper::restore(process_handle, tid, ip) == 0)
	{
		dprintf("restore fail..\n");
	}
	else
	{
		g_Ext->Dml("<b><col fg=\"empfg\">break:: tid=>%d(0x%x), ip=>%x\n\n</col></b>", tid, tid, ip);

		cpu_context_type new_context;
		memset(&new_context, 0, sizeof(new_context));

		if (linker.get_thread_context(&new_context))
		{
			dprintf("	eax="), print32(context.rax, new_context.rax), dprintf(" ");
			dprintf("ebx="), print32(context.rbx, new_context.rbx), dprintf(" ");
			dprintf("ecx="), print32(context.rcx, new_context.rcx), dprintf(" ");
			dprintf("edx="), print32(context.rdx, new_context.rdx), dprintf(" ");
			dprintf("esi="), print32(context.rsi, new_context.rsi), dprintf(" ");
			dprintf("edi="), print32(context.rdi, new_context.rdi), dprintf("\n");

			dprintf("	eip="), print32(context.rip, new_context.rip), dprintf(" ");
			dprintf("esp="), print32(context.rsp, new_context.rsp), dprintf(" ");
			dprintf("ebp="), print32(context.rbp, new_context.rbp), dprintf(" ");
			dprintf("efl="), print32(context.efl, new_context.efl), dprintf("\n");
		}
	}

	helper::suspend(pid);
}

