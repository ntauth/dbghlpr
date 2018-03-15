#include <windows.h>
#include <memory>
#include <strsafe.h>
#include <dbgeng.h>
#include <stdio.h>
#include <capstone.h>

#include <interface.h>
#include <engine_linker.h>

#pragma comment(lib, "dbgeng.lib")

#ifdef _WIN64
#pragma comment(lib, "capstone_static_x64.lib")
#else
#pragma comment(lib, "capstone_static.lib")
#endif

engine_linker::engine_linker() : insn_(nullptr)
{
#ifdef _WIN64
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle_) != 0)
#else
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle_) != 0)
#endif
	{
		cs_handle_ = 0;
	}

	if (cs_option(cs_handle_, CS_OPT_DETAIL, CS_OPT_ON) != 0)
	{
		cs_close(&cs_handle_);
		cs_handle_ = 0;
	}

	if (cs_handle_)
	{
		insn_ = cs_malloc(cs_handle_);
	}

	if (DebugCreate(__uuidof(IDebugClient), (void **)&debug_client_) != S_OK)
	{
		debug_client_ = nullptr;
	}

	if (debug_client_)
	{
		if (((IDebugClient *)debug_client_)->QueryInterface(__uuidof(IDebugDataSpaces), (void **)&debug_data_space_) != S_OK)
		{
			debug_data_space_ = nullptr;
		}

		if (((IDebugClient *)debug_client_)->QueryInterface(__uuidof(IDebugDataSpaces2), (void **)&debug_data_space_2_) != S_OK)
		{
			debug_data_space_2_ = nullptr;
		}

		if (((IDebugClient *)debug_client_)->QueryInterface(__uuidof(IDebugAdvanced), (void **)&debug_advanced_) != S_OK)
		{
			debug_advanced_ = nullptr;
		}

		if (((IDebugClient *)debug_client_)->QueryInterface(__uuidof(IDebugSystemObjects), (void **)&debug_system_objects_) != S_OK)
		{
			debug_system_objects_ = nullptr;
		}

		if (((IDebugClient *)debug_client_)->QueryInterface(__uuidof(IDebugControl), (void **)&debug_control_) != S_OK)
		{
			debug_control_ = nullptr;
		}

		if (((IDebugClient *)debug_client_)->QueryInterface(__uuidof(IDebugRegisters), (void **)&debug_register_) != S_OK)
		{
			debug_register_ = nullptr;
		}
	}
}

engine_linker::~engine_linker()
{
	cs_close(&cs_handle_);
	if (insn_)
		cs_free(insn_, 1);
}

//
//
//
bool __stdcall engine_linker::open(char *path)
{
	if (!debug_client_)
	{
		return false;
	}

	if (((IDebugClient *)debug_client_)->OpenDumpFile(path) != S_OK)
	{
		return false;
	}

	if (!debug_control_)
	{
		return false;
	}

	if (((IDebugControl *)debug_control_)->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE) != S_OK)
	{
		return false;
	}

	return true;
}

bool __stdcall engine_linker::virtual_query(unsigned long long virtual_address, void *out_memory_info)
{
	MEMORY_BASIC_INFORMATION64 *out_mbi = (MEMORY_BASIC_INFORMATION64 *)out_memory_info;

	if (!debug_data_space_2_)
	{
		return false;
	}

	unsigned long long address = 0;
	unsigned long long base = 0;
	unsigned long long end = 0;

	while (((IDebugDataSpaces2 *)debug_data_space_2_)->QueryVirtual(address, out_mbi) == S_OK)
	{
		if (out_mbi->BaseAddress > address)
		{
			address = out_mbi->BaseAddress;
			continue;
		}

		base = (unsigned long long)out_mbi->BaseAddress;
		end = base + out_mbi->RegionSize;

		if (virtual_address >= base && virtual_address < end)
		{
			return true;
		}

		address += out_mbi->RegionSize;
		memset(out_mbi, 0, sizeof(MEMORY_BASIC_INFORMATION64));
	}

	return false;
}

unsigned long long __stdcall engine_linker::get_next_virtual_address(unsigned long long virtual_address)
{
	MEMORY_BASIC_INFORMATION64 mbi;

	if (!debug_data_space_2_)
	{
		return 0;
	}

	if (((IDebugDataSpaces2 *)debug_data_space_2_)->QueryVirtual(virtual_address, &mbi) != S_OK)
	{
		return 0;
	}

	return mbi.BaseAddress;
}

unsigned long __stdcall engine_linker::read_virtual_memory(unsigned long long virtual_address, unsigned char *out_memory, unsigned long read_size)
{
	unsigned long readn = 0;

	if (((IDebugDataSpaces2 *)debug_data_space_2_)->ReadVirtual(virtual_address, out_memory, read_size, &readn) != S_OK)
	{
		return 0;
	}

	return readn;
}

bool __stdcall engine_linker::get_thread_context(cpu_context_type *context)
{
	if (context == nullptr)
		return false;

	unsigned long count = 0;

	if (((IDebugRegisters *)debug_register_)->GetNumberRegisters(&count) != S_OK)
		return false;

	DEBUG_VALUE debug_value_array[1000];
	memset(debug_value_array, 0, sizeof(debug_value_array));

	if (((IDebugRegisters *)debug_register_)->GetValues(count, nullptr, 0, debug_value_array) != S_OK)
		return false;

#ifdef _WIN64
	context->rax = debug_value_array[DBG_X64_REG_IDX_RAX].I64;
	context->rbx = debug_value_array[DBG_X64_REG_IDX_RBX].I64;
	context->rcx = debug_value_array[DBG_X64_REG_IDX_RCX].I64;
	context->rdx = debug_value_array[DBG_X64_REG_IDX_RDX].I64;

	context->rbp = debug_value_array[DBG_X64_REG_IDX_RBP].I64;
	context->rsp = debug_value_array[DBG_X64_REG_IDX_RSP].I64;

	context->rdi = debug_value_array[DBG_X64_REG_IDX_RDI].I64;
	context->rsi = debug_value_array[DBG_X64_REG_IDX_RSI].I64;

	context->r8 = debug_value_array[DBG_X64_REG_IDX_R8].I64;
	context->r9 = debug_value_array[DBG_X64_REG_IDX_R9].I64;
	context->r10 = debug_value_array[DBG_X64_REG_IDX_R10].I64;
	context->r11 = debug_value_array[DBG_X64_REG_IDX_R11].I64;
	context->r12 = debug_value_array[DBG_X64_REG_IDX_R12].I64;
	context->r13 = debug_value_array[DBG_X64_REG_IDX_R13].I64;
	context->r14 = debug_value_array[DBG_X64_REG_IDX_R14].I64;
	context->r15 = debug_value_array[DBG_X64_REG_IDX_R15].I64;

	context->rip = debug_value_array[DBG_X64_REG_IDX_RIP].I64;

	context->efl = (unsigned long)debug_value_array[DBG_X64_REG_IDX_EFL].I64;

	context->cs = (unsigned long)debug_value_array[DBG_X64_REG_IDX_CS].I64;
	context->ds = (unsigned long)debug_value_array[DBG_X64_REG_IDX_DS].I64;
	context->es = (unsigned long)debug_value_array[DBG_X64_REG_IDX_ES].I64;
	context->fs = (unsigned long)debug_value_array[DBG_X64_REG_IDX_FS].I64;
	context->gs = (unsigned long)debug_value_array[DBG_X64_REG_IDX_GS].I64;
	context->ss = (unsigned long)debug_value_array[DBG_X64_REG_IDX_SS].I64;

	context->dr0 = debug_value_array[DBG_X64_REG_IDX_DR0].I64;
	context->dr1 = debug_value_array[DBG_X64_REG_IDX_DR1].I64;
	context->dr2 = debug_value_array[DBG_X64_REG_IDX_DR2].I64;
	context->dr3 = debug_value_array[DBG_X64_REG_IDX_DR3].I64;
	context->dr6 = debug_value_array[DBG_X64_REG_IDX_DR6].I64;
	context->dr7 = debug_value_array[DBG_X64_REG_IDX_DR7].I64;

	context->fpcw = debug_value_array[DBG_X64_REG_IDX_FPCW].I64;
	context->fpsw = debug_value_array[DBG_X64_REG_IDX_FPSW].I64;
	context->fptw = debug_value_array[DBG_X64_REG_IDX_FPTW].I64;

	context->st0 = debug_value_array[DBG_X64_REG_IDX_ST0].I64;
	context->st1 = debug_value_array[DBG_X64_REG_IDX_ST1].I64;
	context->st2 = debug_value_array[DBG_X64_REG_IDX_ST2].I64;
	context->st3 = debug_value_array[DBG_X64_REG_IDX_ST3].I64;
	context->st4 = debug_value_array[DBG_X64_REG_IDX_ST4].I64;
	context->st5 = debug_value_array[DBG_X64_REG_IDX_ST5].I64;
	context->st6 = debug_value_array[DBG_X64_REG_IDX_ST6].I64;
	context->st7 = debug_value_array[DBG_X64_REG_IDX_ST7].I64;

	context->mm0 = debug_value_array[DBG_X64_REG_IDX_MM0].I64;
	context->mm1 = debug_value_array[DBG_X64_REG_IDX_MM1].I64;
	context->mm2 = debug_value_array[DBG_X64_REG_IDX_MM2].I64;
	context->mm3 = debug_value_array[DBG_X64_REG_IDX_MM3].I64;
	context->mm4 = debug_value_array[DBG_X64_REG_IDX_MM4].I64;
	context->mm5 = debug_value_array[DBG_X64_REG_IDX_MM5].I64;
	context->mm6 = debug_value_array[DBG_X64_REG_IDX_MM6].I64;
	context->mm7 = debug_value_array[DBG_X64_REG_IDX_MM7].I64;

	context->mxcsr = debug_value_array[DBG_X64_REG_IDX_MXCSR].I64;

	context->xmm0 = debug_value_array[DBG_X64_REG_IDX_XMM0].I64;
	context->xmm1 = debug_value_array[DBG_X64_REG_IDX_XMM1].I64;
	context->xmm2 = debug_value_array[DBG_X64_REG_IDX_XMM2].I64;
	context->xmm3 = debug_value_array[DBG_X64_REG_IDX_XMM3].I64;
	context->xmm4 = debug_value_array[DBG_X64_REG_IDX_XMM4].I64;
	context->xmm5 = debug_value_array[DBG_X64_REG_IDX_XMM5].I64;
	context->xmm6 = debug_value_array[DBG_X64_REG_IDX_XMM6].I64;
	context->xmm7 = debug_value_array[DBG_X64_REG_IDX_XMM7].I64;
	context->xmm8 = debug_value_array[DBG_X64_REG_IDX_XMM8].I64;
	context->xmm9 = debug_value_array[DBG_X64_REG_IDX_XMM9].I64;
	context->xmm10 = debug_value_array[DBG_X64_REG_IDX_XMM10].I64;
	context->xmm11 = debug_value_array[DBG_X64_REG_IDX_XMM11].I64;
	context->xmm12 = debug_value_array[DBG_X64_REG_IDX_XMM12].I64;
	context->xmm13 = debug_value_array[DBG_X64_REG_IDX_XMM13].I64;
	context->xmm14 = debug_value_array[DBG_X64_REG_IDX_XMM14].I64;
	context->xmm15 = debug_value_array[DBG_X64_REG_IDX_XMM15].I64;

	context->ymm0 = debug_value_array[DBG_X64_REG_IDX_YMM0].I64;
	context->ymm1 = debug_value_array[DBG_X64_REG_IDX_YMM1].I64;
	context->ymm2 = debug_value_array[DBG_X64_REG_IDX_YMM2].I64;
	context->ymm3 = debug_value_array[DBG_X64_REG_IDX_YMM3].I64;
	context->ymm4 = debug_value_array[DBG_X64_REG_IDX_YMM4].I64;
	context->ymm5 = debug_value_array[DBG_X64_REG_IDX_YMM5].I64;
	context->ymm6 = debug_value_array[DBG_X64_REG_IDX_YMM6].I64;
	context->ymm7 = debug_value_array[DBG_X64_REG_IDX_YMM7].I64;
	context->ymm8 = debug_value_array[DBG_X64_REG_IDX_YMM8].I64;
	context->ymm9 = debug_value_array[DBG_X64_REG_IDX_YMM9].I64;
	context->ymm10 = debug_value_array[DBG_X64_REG_IDX_YMM10].I64;
	context->ymm11 = debug_value_array[DBG_X64_REG_IDX_YMM11].I64;
	context->ymm12 = debug_value_array[DBG_X64_REG_IDX_YMM12].I64;
	context->ymm13 = debug_value_array[DBG_X64_REG_IDX_YMM13].I64;
	context->ymm14 = debug_value_array[DBG_X64_REG_IDX_YMM14].I64;
	context->ymm15 = debug_value_array[DBG_X64_REG_IDX_YMM15].I64;

	context->iopl = debug_value_array[DBG_X64_REG_IDX_IOPL].I64;
	context->vip = debug_value_array[DBG_X64_REG_IDX_VIP].I64;
	context->vif = debug_value_array[DBG_X64_REG_IDX_VIF].I64;
#else
	context->rax = debug_value_array[DBG_X86_REG_IDX_EAX].I32;
	context->rbx = debug_value_array[DBG_X86_REG_IDX_EBX].I32;
	context->rcx = debug_value_array[DBG_X86_REG_IDX_ECX].I32;
	context->rdx = debug_value_array[DBG_X86_REG_IDX_EDX].I32;

	context->rbp = debug_value_array[DBG_X86_REG_IDX_EBP].I32;
	context->rsp = debug_value_array[DBG_X86_REG_IDX_ESP].I32;

	context->rdi = debug_value_array[DBG_X86_REG_IDX_EDI].I32;
	context->rsi = debug_value_array[DBG_X86_REG_IDX_ESI].I32;

	context->rip = debug_value_array[DBG_X86_REG_IDX_EIP].I32;

	context->efl = (unsigned long)debug_value_array[DBG_X86_REG_IDX_EFL].I32;

	context->cs = (unsigned long)debug_value_array[DBG_X86_REG_IDX_CS].I32;
	context->ds = (unsigned long)debug_value_array[DBG_X86_REG_IDX_DS].I32;
	context->es = (unsigned long)debug_value_array[DBG_X86_REG_IDX_ES].I32;
	context->fs = (unsigned long)debug_value_array[DBG_X86_REG_IDX_FS].I32;
	context->gs = (unsigned long)debug_value_array[DBG_X86_REG_IDX_GS].I32;
	context->ss = (unsigned long)debug_value_array[DBG_X86_REG_IDX_SS].I32;

	context->dr0 = debug_value_array[DBG_X86_REG_IDX_DR0].I32;
	context->dr1 = debug_value_array[DBG_X86_REG_IDX_DR1].I32;
	context->dr2 = debug_value_array[DBG_X86_REG_IDX_DR2].I32;
	context->dr3 = debug_value_array[DBG_X86_REG_IDX_DR3].I32;
	context->dr6 = debug_value_array[DBG_X86_REG_IDX_DR6].I32;
	context->dr7 = debug_value_array[DBG_X86_REG_IDX_DR7].I32;

	context->fpcw = debug_value_array[DBG_X86_REG_IDX_FPCW].I32;
	context->fpsw = debug_value_array[DBG_X86_REG_IDX_FPSW].I32;
	context->fptw = debug_value_array[DBG_X86_REG_IDX_FPTW].I32;

	context->st0 = debug_value_array[DBG_X86_REG_IDX_ST0].I32;
	context->st1 = debug_value_array[DBG_X86_REG_IDX_ST1].I32;
	context->st2 = debug_value_array[DBG_X86_REG_IDX_ST2].I32;
	context->st3 = debug_value_array[DBG_X86_REG_IDX_ST3].I32;
	context->st4 = debug_value_array[DBG_X86_REG_IDX_ST4].I32;
	context->st5 = debug_value_array[DBG_X86_REG_IDX_ST5].I32;
	context->st6 = debug_value_array[DBG_X86_REG_IDX_ST6].I32;
	context->st7 = debug_value_array[DBG_X86_REG_IDX_ST7].I32;

	context->mm0 = debug_value_array[DBG_X86_REG_IDX_MM0].I32;
	context->mm1 = debug_value_array[DBG_X86_REG_IDX_MM1].I32;
	context->mm2 = debug_value_array[DBG_X86_REG_IDX_MM2].I32;
	context->mm3 = debug_value_array[DBG_X86_REG_IDX_MM3].I32;
	context->mm4 = debug_value_array[DBG_X86_REG_IDX_MM4].I32;
	context->mm5 = debug_value_array[DBG_X86_REG_IDX_MM5].I32;
	context->mm6 = debug_value_array[DBG_X86_REG_IDX_MM6].I32;
	context->mm7 = debug_value_array[DBG_X86_REG_IDX_MM7].I32;

	context->mxcsr = debug_value_array[DBG_X86_REG_IDX_MXCSR].I32;

	context->xmm0 = debug_value_array[DBG_X86_REG_IDX_XMM0].I32;
	context->xmm1 = debug_value_array[DBG_X86_REG_IDX_XMM1].I32;
	context->xmm2 = debug_value_array[DBG_X86_REG_IDX_XMM2].I32;
	context->xmm3 = debug_value_array[DBG_X86_REG_IDX_XMM3].I32;
	context->xmm4 = debug_value_array[DBG_X86_REG_IDX_XMM4].I32;
	context->xmm5 = debug_value_array[DBG_X86_REG_IDX_XMM5].I32;
	context->xmm6 = debug_value_array[DBG_X86_REG_IDX_XMM6].I32;
	context->xmm7 = debug_value_array[DBG_X86_REG_IDX_XMM7].I32;

	context->ymm0 = debug_value_array[DBG_X86_REG_IDX_YMM0].I32;
	context->ymm1 = debug_value_array[DBG_X86_REG_IDX_YMM1].I32;
	context->ymm2 = debug_value_array[DBG_X86_REG_IDX_YMM2].I32;
	context->ymm3 = debug_value_array[DBG_X86_REG_IDX_YMM3].I32;
	context->ymm4 = debug_value_array[DBG_X86_REG_IDX_YMM4].I32;
	context->ymm5 = debug_value_array[DBG_X86_REG_IDX_YMM5].I32;
	context->ymm6 = debug_value_array[DBG_X86_REG_IDX_YMM6].I32;
	context->ymm7 = debug_value_array[DBG_X86_REG_IDX_YMM7].I32;

	context->iopl = debug_value_array[DBG_X86_REG_IDX_IOPL].I32;
	context->vip = debug_value_array[DBG_X86_REG_IDX_VIP].I32;
	context->vif = debug_value_array[DBG_X86_REG_IDX_VIF].I32;
#endif

	return true;
}

//
//
//
void * __stdcall engine_linker::disasm(unsigned long long address, const unsigned char *code_table)
{
	size_t size = 16;

	if (cs_handle_ == 0 || insn_ == nullptr)
	{
		return nullptr;
	}

	if (!cs_disasm_iter(cs_handle_, &code_table, &size, &address, insn_))
	{
		return nullptr;
	}

	return insn_;
}

void * __stdcall engine_linker::get_disasm_handle()
{
	return (void *)cs_handle_;
}

unsigned long long __stdcall engine_linker::get_peb_address()
{
	unsigned long long peb_address = 0;

	try
	{
		if (((IDebugSystemObjects*)debug_system_objects_)->GetCurrentProcessPeb(&peb_address) != S_OK)
			return 0;
	}
	catch (...)
	{
		return 0;
	}

	return peb_address;
}

unsigned long long __stdcall engine_linker::get_teb_address()
{
	unsigned long long teb_address = 0;

	try
	{
		if (((IDebugSystemObjects*)debug_system_objects_)->GetCurrentThreadTeb(&teb_address) != S_OK)
			return 0;
	}
	catch (...)
	{
		return 0;
	}

	return teb_address;
}
