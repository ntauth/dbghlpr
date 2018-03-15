#define _CRT_SECURE_NO_WARNINGS

#include <unicorn/unicorn.h>

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
#include <emulator.h>

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
	dprintf("run %I64x\n", address);
}

static void hook_unmap_memory(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
	if (type == UC_MEM_WRITE_UNMAPPED || type == UC_MEM_READ_UNMAPPED)
	{
		dprintf("unmaped memory.. %I64x\n", address);
	}
}

static void hook_fetch_memory(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
{
	if (type == UC_MEM_FETCH_UNMAPPED)
	{
		dprintf("fetch memory.. %I64x\n", address);
	}
}

unsigned long long __stdcall alignment(unsigned long long region_size, unsigned long image_aligin)
{
	unsigned long mod = region_size % image_aligin;
	region_size -= mod;

	return region_size + image_aligin;
}

//
//
//
uc_engine *_uc = nullptr;

bool __stdcall query(unsigned long long address, unsigned long long *base, unsigned long long *size)
{
	uc_mem_region *um = nullptr;
	uint32_t count = 0;

	if (uc_mem_regions(_uc, &um, &count) != 0)
		return false;
	std::shared_ptr<void> uc_memory_closer(um, free);

	for (unsigned int i = 0; i < count; ++i)
	{
		if (address >= um[i].begin && address <= um[i].end)
		{
			*base = um[i].begin;
			*size = um[i].end - um[i].begin;

			return true;
		}
	}

	return false;
}

void set_global_descriptor(SegmentDescriptor *desc, uint32_t base, uint32_t limit, uint8_t is_code)
{
	desc->descriptor = 0;
	desc->base_low = base & 0xffff;
	desc->base_mid = (base >> 16) & 0xff;
	desc->base_hi = base >> 24;

	if (limit > 0xfffff)
	{
		limit >>= 12;
		desc->granularity = 1;
	}
	desc->limit_low = limit & 0xffff;
	desc->limit_hi = limit >> 16;

	desc->dpl = 3;
	desc->present = 1;
	desc->db = 1;
	desc->type = is_code ? 0xb : 3;
	desc->system = 1;
}

bool __stdcall read_x86_cpu_context(cpu_context_type *context)
{
	int x86_register[] = { UC_X86_REGISTER_SET };
	int size = sizeof(x86_register) / sizeof(int);
	unsigned long *read_register = nullptr;
	void **read_ptr = nullptr;

	read_register = (unsigned long *)malloc(sizeof(unsigned long)*size);
	if (!read_register)
		return false;
	std::shared_ptr<void> read_register_closer(read_register, free);
	memset(read_register, 0, sizeof(unsigned long)*size);

	read_ptr = (void **)malloc(sizeof(void **)*size);
	if (!read_ptr)
		return false;

	std::shared_ptr<void> read_ptr_closer(read_ptr, free);
	memset(read_ptr, 0, sizeof(void **)*size);

	for (int i = 0; i < size; ++i)
		read_ptr[i] = &read_register[i];

	if (uc_reg_read_batch(_uc, x86_register, read_ptr, size) != 0)
		return false;

	context->rax = read_register[PR_RAX];
	context->rbx = read_register[PR_RBX];
	context->rcx = read_register[PR_RCX];
	context->rdx = read_register[PR_RDX];
	context->rsi = read_register[PR_RSI];
	context->rdi = read_register[PR_RDI];
	context->rsp = read_register[PR_RSP];
	context->rbp = read_register[PR_RBP];
	context->rip = read_register[PR_RIP];

	context->xmm0 = read_register[PR_XMM0];
	context->xmm1 = read_register[PR_XMM1];
	context->xmm2 = read_register[PR_XMM2];
	context->xmm3 = read_register[PR_XMM3];
	context->xmm4 = read_register[PR_XMM4];
	context->xmm5 = read_register[PR_XMM5];
	context->xmm6 = read_register[PR_XMM6];
	context->xmm7 = read_register[PR_XMM7];

	context->ymm0 = read_register[PR_YMM0];
	context->ymm1 = read_register[PR_YMM1];
	context->ymm2 = read_register[PR_YMM2];
	context->ymm3 = read_register[PR_YMM3];
	context->ymm4 = read_register[PR_YMM4];
	context->ymm5 = read_register[PR_YMM5];
	context->ymm6 = read_register[PR_YMM6];
	context->ymm7 = read_register[PR_YMM7];

	context->efl = read_register[PR_EFLAGS];
	context->cs = (unsigned short)read_register[PR_REG_CS];
	context->ds = (unsigned short)read_register[PR_REG_DS];
	context->es = (unsigned short)read_register[PR_REG_ES];
	context->fs = (unsigned short)read_register[PR_REG_FS];
	context->gs = (unsigned short)read_register[PR_REG_GS];
	context->ss = (unsigned short)read_register[PR_REG_SS];

	return true;
}

bool __stdcall write_x86_cpu_context(cpu_context_type context)
{
	int x86_register[] = { UC_X86_REGISTER_SET };
	int size = sizeof(x86_register) / sizeof(int);
	unsigned long *write_register = nullptr;
	void **write_ptr = nullptr;

	write_register = (unsigned long *)malloc(sizeof(unsigned long)*size);
	if (!write_register)
		return false;
	std::shared_ptr<void> write_register_closer(write_register, free);
	memset(write_register, 0, sizeof(unsigned long)*size);

	write_ptr = (void **)malloc(sizeof(void **)*size);
	if (!write_ptr)
		return false;
	std::shared_ptr<void> write_ptr_closer(write_ptr, free);
	memset(write_ptr, 0, sizeof(void **)*size);

	for (int i = 0; i < size; ++i)
		write_ptr[i] = &write_register[i];

	write_register[PR_RAX] = (unsigned long)context.rax;
	write_register[PR_RBX] = (unsigned long)context.rbx;
	write_register[PR_RCX] = (unsigned long)context.rcx;
	write_register[PR_RDX] = (unsigned long)context.rdx;
	write_register[PR_RSI] = (unsigned long)context.rsi;
	write_register[PR_RDI] = (unsigned long)context.rdi;
	write_register[PR_RSP] = (unsigned long)context.rsp;
	write_register[PR_RBP] = (unsigned long)context.rbp;
	write_register[PR_RIP] = (unsigned long)context.rip;
	write_register[PR_EFLAGS] = (unsigned long)context.efl;

	write_register[PR_XMM0] = (unsigned long)context.xmm0;
	write_register[PR_XMM1] = (unsigned long)context.xmm1;
	write_register[PR_XMM2] = (unsigned long)context.xmm2;
	write_register[PR_XMM3] = (unsigned long)context.xmm3;
	write_register[PR_XMM4] = (unsigned long)context.xmm4;
	write_register[PR_XMM5] = (unsigned long)context.xmm5;
	write_register[PR_XMM6] = (unsigned long)context.xmm6;
	write_register[PR_XMM7] = (unsigned long)context.xmm7;

	write_register[PR_YMM0] = (unsigned long)context.ymm0;
	write_register[PR_YMM1] = (unsigned long)context.ymm1;
	write_register[PR_YMM2] = (unsigned long)context.ymm2;
	write_register[PR_YMM3] = (unsigned long)context.ymm3;
	write_register[PR_YMM4] = (unsigned long)context.ymm4;
	write_register[PR_YMM5] = (unsigned long)context.ymm5;
	write_register[PR_YMM6] = (unsigned long)context.ymm6;
	write_register[PR_YMM7] = (unsigned long)context.ymm7;

	write_register[PR_REG_CS] = context.cs;
	write_register[PR_REG_DS] = context.ds;
	write_register[PR_REG_ES] = context.es;
	write_register[PR_REG_FS] = context.fs;
	write_register[PR_REG_GS] = context.gs;
	write_register[PR_REG_SS] = context.ss;

	if (uc_reg_write_batch(_uc, x86_register, write_ptr, size) != 0)
		return false;

	return true;
}

bool __stdcall write_x64_cpu_context(cpu_context_type context)
{
#ifdef _WIN64
	int x86_register[] = { UC_X64_REGISTER_SET };
	int size = sizeof(x86_register) / sizeof(int);
	unsigned long long *write_register = nullptr;
	void **write_ptr = nullptr;

	write_register = (unsigned long long *)malloc(sizeof(unsigned long long)*size);
	if (!write_register)
		return false;
	std::shared_ptr<void> write_register_closer(write_register, free);
	memset(write_register, 0, sizeof(unsigned long long)*size);

	write_ptr = (void **)malloc(sizeof(void **)*size);
	if (!write_ptr)
		return false;
	std::shared_ptr<void> write_ptr_closer(write_ptr, free);
	memset(write_ptr, 0, sizeof(void **)*size);

	for (int i = 0; i < size; ++i)
		write_ptr[i] = &write_register[i];

	write_register[PR_RAX] = context.rax;
	write_register[PR_RBX] = context.rbx;
	write_register[PR_RCX] = context.rcx;
	write_register[PR_RDX] = context.rdx;
	write_register[PR_RSI] = context.rsi;
	write_register[PR_RDI] = context.rdi;
	write_register[PR_RSP] = context.rsp;
	write_register[PR_RBP] = context.rbp;
	write_register[PR_RIP] = context.rip;
	write_register[PR_R8] = context.r8;
	write_register[PR_R9] = context.r9;
	write_register[PR_R10] = context.r10;
	write_register[PR_R11] = context.r11;
	write_register[PR_R12] = context.r12;
	write_register[PR_R13] = context.r13;
	write_register[PR_R14] = context.r14;
	write_register[PR_R15] = context.r15;
	write_register[PR_EFLAGS] = (unsigned long)context.efl;

	write_register[PR_XMM0] = context.xmm0;
	write_register[PR_XMM1] = context.xmm1;
	write_register[PR_XMM2] = context.xmm2;
	write_register[PR_XMM3] = context.xmm3;
	write_register[PR_XMM4] = context.xmm4;
	write_register[PR_XMM5] = context.xmm5;
	write_register[PR_XMM6] = context.xmm6;
	write_register[PR_XMM7] = context.xmm7;
	write_register[PR_XMM8] = context.xmm8;
	write_register[PR_XMM9] = context.xmm9;
	write_register[PR_XMM10] = context.xmm10;
	write_register[PR_XMM11] = context.xmm11;
	write_register[PR_XMM12] = context.xmm12;
	write_register[PR_XMM13] = context.xmm13;
	write_register[PR_XMM14] = context.xmm14;
	write_register[PR_XMM15] = context.xmm15;

	write_register[PR_YMM0] = context.ymm0;
	write_register[PR_YMM1] = context.ymm1;
	write_register[PR_YMM2] = context.ymm2;
	write_register[PR_YMM3] = context.ymm3;
	write_register[PR_YMM4] = context.ymm4;
	write_register[PR_YMM5] = context.ymm5;
	write_register[PR_YMM6] = context.ymm6;
	write_register[PR_YMM7] = context.ymm7;
	write_register[PR_YMM8] = context.ymm8;
	write_register[PR_YMM9] = context.ymm9;
	write_register[PR_YMM10] = context.ymm10;
	write_register[PR_YMM11] = context.ymm11;
	write_register[PR_YMM12] = context.ymm12;
	write_register[PR_YMM13] = context.ymm13;
	write_register[PR_YMM14] = context.ymm14;
	write_register[PR_YMM15] = context.ymm15;

	write_register[PR_REG_CS] = context.cs;
	write_register[PR_REG_DS] = context.ds;
	write_register[PR_REG_ES] = context.es;
	write_register[PR_REG_FS] = context.fs;
	write_register[PR_REG_GS] = context.gs;
	write_register[PR_REG_SS] = context.ss;

	if (uc_reg_write_batch(_uc, x86_register, write_ptr, size) != 0)
		return false;
#endif
	return true;
}

bool __stdcall read_x64_cpu_context(cpu_context_type *context)
{
#ifdef _WIN64
	int x86_register[] = { UC_X64_REGISTER_SET };
	int size = sizeof(x86_register) / sizeof(int);
	unsigned long long *read_register = nullptr;
	void **read_ptr = nullptr;

	read_register = (unsigned long long *)malloc(sizeof(unsigned long long)*size);
	if (!read_register)
		return false;
	std::shared_ptr<void> read_register_closer(read_register, free);
	memset(read_register, 0, sizeof(unsigned long long)*size);

	read_ptr = (void **)malloc(sizeof(void **)*size);
	if (!read_ptr)
		return false;
	std::shared_ptr<void> read_ptr_closer(read_ptr, free);
	memset(read_ptr, 0, sizeof(void **)*size);

	for (int i = 0; i < size; ++i)
		read_ptr[i] = &read_register[i];

	if (uc_reg_read_batch(_uc, x86_register, read_ptr, size) != 0)
		return false;

	context->rax = read_register[PR_RAX];
	context->rbx = read_register[PR_RBX];
	context->rcx = read_register[PR_RCX];
	context->rdx = read_register[PR_RDX];
	context->rsi = read_register[PR_RSI];
	context->rdi = read_register[PR_RDI];
	context->rsp = read_register[PR_RSP];
	context->rbp = read_register[PR_RBP];
	context->rip = read_register[PR_RIP];
	context->r8 = read_register[PR_R8];
	context->r9 = read_register[PR_R9];
	context->r10 = read_register[PR_R10];
	context->r11 = read_register[PR_R11];
	context->r12 = read_register[PR_R12];
	context->r13 = read_register[PR_R13];
	context->r14 = read_register[PR_R14];
	context->r15 = read_register[PR_R15];
	context->efl = (unsigned long)read_register[PR_EFLAGS];

	context->xmm0 = read_register[PR_XMM0];
	context->xmm1 = read_register[PR_XMM1];
	context->xmm2 = read_register[PR_XMM2];
	context->xmm3 = read_register[PR_XMM3];
	context->xmm4 = read_register[PR_XMM4];
	context->xmm5 = read_register[PR_XMM5];
	context->xmm6 = read_register[PR_XMM6];
	context->xmm7 = read_register[PR_XMM7];
	context->xmm8 = read_register[PR_XMM8];
	context->xmm9 = read_register[PR_XMM9];
	context->xmm10 = read_register[PR_XMM10];
	context->xmm11 = read_register[PR_XMM11];
	context->xmm12 = read_register[PR_XMM12];
	context->xmm13 = read_register[PR_XMM13];
	context->xmm14 = read_register[PR_XMM14];
	context->xmm15 = read_register[PR_XMM15];

	context->ymm0 = read_register[PR_YMM0];
	context->ymm1 = read_register[PR_YMM1];
	context->ymm2 = read_register[PR_YMM2];
	context->ymm3 = read_register[PR_YMM3];
	context->ymm4 = read_register[PR_YMM4];
	context->ymm5 = read_register[PR_YMM5];
	context->ymm6 = read_register[PR_YMM6];
	context->ymm7 = read_register[PR_YMM7];
	context->ymm8 = read_register[PR_YMM8];
	context->ymm9 = read_register[PR_YMM9];
	context->ymm10 = read_register[PR_YMM10];
	context->ymm11 = read_register[PR_YMM11];
	context->ymm12 = read_register[PR_YMM12];
	context->ymm13 = read_register[PR_YMM13];
	context->ymm14 = read_register[PR_YMM14];
	context->ymm15 = read_register[PR_YMM15];

	context->cs = (unsigned short)read_register[PR_REG_CS];
	context->ds = (unsigned short)read_register[PR_REG_DS];
	context->es = (unsigned short)read_register[PR_REG_ES];
	context->fs = (unsigned short)read_register[PR_REG_FS];
	context->gs = (unsigned short)read_register[PR_REG_GS];
	context->ss = (unsigned short)read_register[PR_REG_SS];
#endif
	return true;
}

void __stdcall print_reg_64(unsigned long long c, unsigned long long b)
{
	if (c != b)
		g_Ext->Dml("<b><col fg=\"changed\">%0*I64x</col></b>", 16, c);
	else
		dprintf("%0*I64x", 16, c);
}

void __stdcall print_reg_32(unsigned long long c, unsigned long long b)
{
	if (c != b)
		g_Ext->Dml("<b><col fg=\"changed\">%08x</col></b>", c);
	else
		dprintf("%08x", c);
}

void __stdcall view_cpu_context()
{
	cpu_context_type context;

#ifdef _WIN64
	read_x64_cpu_context(&context);

	dprintf("	rax=%0*I64x rbx=%0*I64x rcx=%0*I64x rdx=%0*I64x rsi=%0*I64x rdi=%0*I64x\n", 16, context.rax, 16, context.rbx, 16, context.rcx, 16, context.rdx, 16, context.rsi, 16, context.rdi);
	dprintf("	rip=%0*I64x rsp=%0*I64x rbp=%0*I64x efl=%0*I64x\n", 16, context.rip, 16, context.rsp, 16, context.rbp, context.efl);
	dprintf("	r8=%0*I64x r9=%0*I64x r10=%0*I64x r11=%0*I64x r12=%0*I64x r13=%0*I64x r14=%0*I64x r15=%0*I64x\n", 16, context.r8, 16, context.r9, 16, context.r10, 16, context.r11, 16, context.r12, 16, context.r13, 16, context.r14, 16, context.r15);

	dprintf("	cs=%x ds=%x es=%x fs=%x gs=%x %ss\n", context.cs, context.ds, context.es, context.fs, context.gs, context.ss);
#else
	read_x86_cpu_context(&context);

	dprintf("	eax=%08x ebx=%08x ecx=%08x edx=%08x esi=%08x edi=%08x\n", (unsigned long)context.rax, (unsigned long)context.rbx, (unsigned long)context.rcx, (unsigned long)context.rdx, (unsigned long)context.rsi, (unsigned long)context.rdi);
	dprintf("	eip=%08x esp=%08x ebp=%08x efl=%08x\n", (unsigned long)context.rip, (unsigned long)context.rsp, (unsigned long)context.rbp, (unsigned long)context.efl);

	dprintf("	cs=%x ds=%x es=%x fs=%x gs=%x %ss\n", context.cs, context.ds, context.es, context.fs, context.gs, context.ss);
#endif
	dprintf("\n");
	char str[1024] = { 0, };
	Disasm(&context.rip, str, false);
	dprintf("	%s", str);
	dprintf("\n");
}

bool __stdcall create_global_descriptor_table(cpu_context_type context, unsigned long mode)
{
	SegmentDescriptor global_descriptor[31];
	memset(global_descriptor, 0, sizeof(global_descriptor));

	context.ss = 0x88; // rpl = 0
	context.gs = 0x63;

	set_global_descriptor(&global_descriptor[0x33 >> 3], 0, 0xfffff000, 1); // 64 code
	set_global_descriptor(&global_descriptor[context.cs >> 3], 0, 0xfffff000, 1);
	set_global_descriptor(&global_descriptor[context.ds >> 3], 0, 0xfffff000, 0);
	set_global_descriptor(&global_descriptor[context.fs >> 3], 0, 0xfff, 0);
	set_global_descriptor(&global_descriptor[context.gs >> 3], 0, 0xfffff000, 0);
	set_global_descriptor(&global_descriptor[context.ss >> 3], 0, 0xfffff000, 0);
	global_descriptor[context.ss >> 3].dpl = 0; // dpl = 0, cpl = 0

	unsigned long long gdt_base = 0xc0000000;
	uc_x86_mmr gdtr;
	gdtr.base = gdt_base;
	gdtr.limit = (sizeof(SegmentDescriptor) * 31) - 1;

	if (uc_reg_write(_uc, UC_X86_REG_GDTR, &gdtr) != 0)
		return false;

	if (uc_mem_map(_uc, gdt_base, (size_t)0x10000, UC_PROT_ALL) == 0)
	{
		if (uc_mem_write(_uc, gdt_base, global_descriptor, sizeof(global_descriptor)) == 0)
		{
#ifdef _WIN64
			write_x64_cpu_context(context);
#else
			write_x86_cpu_context(context);
#endif
		}
	}

	return true;
}

//
//
//
EXT_CLASS_COMMAND(WindbgEngine, open, "", "{bit;ed,o;bit;;}")
{
	if (!HasArg("bit"))
	{
		return;
	}

	if (_uc)
	{
		uc_close(_uc);
	}

	uc_mode mode;
	unsigned long long bit = GetArgU64("bit", false);
	if (bit == 0x32)
	{
		mode = UC_MODE_32;
	}
	else if (bit == 0x64)
	{
		mode = UC_MODE_64;
	}
	else
	{
		dprintf("unsupported mode\n");
		return;
	}

	if (uc_open(UC_ARCH_X86, mode, &_uc) == 0)
	{
		cpu_context_type context;
		engine_linker linker;
		linker.get_thread_context(&context);

		cpu_context_type segment_context = { 0, };
		segment_context.cs = context.cs;
		segment_context.ds = context.ds;
		segment_context.es = context.es;
		segment_context.fs = 0x88;
		segment_context.gs = 0x63;

		if (create_global_descriptor_table(segment_context, mode))
		{
			dprintf("emulator:: open success\n");
			view_cpu_context();
		}
	}
}

EXT_CLASS_COMMAND(WindbgEngine, alloc, "", "{em;ed,o;em;;}" "{size;ed,o;size;;}" "{copy;b,o;copy;;}")
{
	if (!HasArg("em") || !HasArg("size"))
	{
		return;
	}

	unsigned long long em = GetArgU64("em", false);
	unsigned long long size = GetArgU64("size", false);

	unsigned long long base = alignment(em, 0x1000) - 0x1000;
	unsigned long long base_size = alignment(size, 0x1000);

	if (uc_mem_map(_uc, base, (size_t)base_size, UC_PROT_ALL) == 0)
	{
		dprintf("emulator:: alloc success\n");
		dprintf("	[-] %I64x-%I64x\n", base, base+base_size);
		if (HasArg("copy"))
		{
			unsigned char *dump = (unsigned char *)malloc((size_t)size);
			if (!dump)
			{
				dprintf("emulator:: copy fail\n");
			}
			std::shared_ptr<void> dump_closer(dump, free);
			engine_linker linker;

			unsigned long readn = linker.read_virtual_memory(em, dump, (unsigned long)size);
			if (uc_mem_write(_uc, em, dump, readn) == 0)
			{
				dprintf("emulator:: copy success\n");
			}
		}
	}	
	else
	{
		dprintf("emulator:: copy fail\n");
	}
}

EXT_CLASS_COMMAND(WindbgEngine, write, "", "{em;ed,o;em;;}" "{hex;x,o;hex;;}")
{
	if (!HasArg("em") || !HasArg("hex"))
	{
		return;
	}

	unsigned long long em = GetArgU64("em", false);
	PCSTR hex = GetArgStr("hex", true);
	size_t size_of_hex = strlen(hex);
	unsigned char *hex_dump = (unsigned char *)malloc(size_of_hex);
	if (!hex_dump)
	{
		return;
	}
	std::shared_ptr<void> pattern_closer(hex_dump, free);
	memset(hex_dump, 0, size_of_hex);

	unsigned long long j = 0;
	for (unsigned long long i = 0; i < size_of_hex; ++i)
	{
		if (hex[i] != ' ')
		{
			char *end = nullptr;
			hex_dump[j++] = (unsigned char)strtol(&hex[i], &end, 16);
			i = end - hex;
		}
	}

	if (uc_mem_write(_uc, em, hex_dump, size_of_hex) == 0)
	{
		dprintf("emulator:: write success\n");
	}
}

EXT_CLASS_COMMAND(WindbgEngine, read, "", "{em;ed,o;em;;}" "{size;ed,o;size;;}")
{
	if (!HasArg("em") || !HasArg("size"))
	{
		return;
	}

	unsigned long long em = GetArgU64("em", false);
	unsigned long long size = GetArgU64("size", false);

	unsigned char *dump = (unsigned char *)malloc((size_t)size);
	if (!dump)
		return;
	std::shared_ptr<void> dump_closer(dump, free);
	memset(dump, 0, (size_t)size);

	if (uc_mem_read(_uc, em, dump, (size_t)size) != 0)
	{
		dprintf("emulator:: read fail\n");
		return;
	}

	unsigned int i = 0, j = 0;
	for (i; i < size; ++i)
	{
		if (i == 0)
		{
			dprintf("%08x  ", em);
		}
		else if (i % 16 == 0)
		{
			/*-- ascii --*/
			for (j; j < i; ++j)
			{
				if (helper::is_ascii(dump, (size_t)size))
					dprintf("%c", dump[j]);
				else
					dprintf(".");
			}

			/*-- next line --*/
			dprintf("\n");
			em += 16;
			dprintf("%08x  ", em);
		}

		dprintf("%02x ", dump[i]);
	}

	if (i % 16)
	{
		for (unsigned k = 0; k < i % 16; ++i)
			dprintf("   ");
	}

	for (j; j < i; ++j)
	{
		if (helper::is_ascii(dump, (size_t)size))
			dprintf("%c", dump[j]);
		else
			dprintf(".");
	}
	dprintf("\n");
}

EXT_CLASS_COMMAND(WindbgEngine, query, "", "{em;ed,o;em;;}")
{
	if (!HasArg("em"))
		return;

	unsigned long long em = GetArgU64("em", false);
	unsigned long long base = 0;
	unsigned long long size = 0;
	if (::query(em, &base, &size))
	{
		dprintf("	%I64x-%I64x\n", base, base + size + 1);
	}
}

EXT_CLASS_COMMAND(WindbgEngine, trace, "", "{em;ed,o;em;;}" "{step;ed,o;step;;}")
{
	if (!HasArg("em") || !HasArg("step"))
		return;

	cpu_context_type backup;
	read_x86_cpu_context(&backup);

	unsigned long long em = GetArgU64("em", false);
	unsigned long long step = GetArgU64("step", false);
	unsigned long long base = 0;
	unsigned long long size = 0;
	if (::query(em, &base, &size))
	{
		dprintf("	%I64x:: %I64x-%I64x\n", em, base, base + size + 1);
	}
	else
	{
		dprintf("	%I64x:: not found emulator memory..\n");
	}

	uc_err err = uc_emu_start(_uc, em, em+size, 0, (size_t)step);
	if (err)
	{
		dprintf("emulator:: %d\n", err);
	}
	else
	{
		cpu_context_type context;
#ifdef _WIN64
		read_x64_cpu_context(&context);
#else
		read_x86_cpu_context(&context);
#endif

#ifdef _WIN64
		view_cpu_context();
#else
		view_cpu_context();
#endif
	}
}

EXT_CLASS_COMMAND(WindbgEngine, context, "", "{rax;ed,o;rax;;}" "{rbx;ed,o;rbx;;}" "{rcx;ed,o;rcx;;}" "{rdx;ed,o;rdx;;}"
											 "{rdi;ed,o;rdi;;}" "{rsi;ed,o;rsi;;}" "{rbp;ed,o;rbp;;}" "{rsp;ed,o;rsp;;}"
											 "{r8;ed,o;r8;;}" "{r9;ed,o;r9;;}" "{r10;ed,o;r10;;}" "{r11;ed,o;r11;;}" "{r12;ed,o;r12;;}" "{r13;ed,o;r13;;}" "{r14;ed,o;r14;;}" "{r15;ed,o;r15;;}"
											 "{rip;ed,o;rip;;}"
											 "{efl;ed,o;efl;;}" "{cs;ed,o;cs;;}" "{ds;ed,o;ds;;}" "{es;ed,o;es;;}" "{fs;ed,o;fs;;}" "{gs;ed,o;gs;;}" "{ss;ed,o;ss;;}"
											 "{xmm0;ed,o;xmm0;;}" "{xmm1;ed,o;xmm1;;}" "{xmm2;ed,o;xmm2;;}" "{xmm3;ed,o;xmm3;;}" "{xmm4;ed,o;xmm4;;}" "{xmm5;ed,o;xmm5;;}" "{xmm6;ed,o;xmm6;;}" "{xmm7;ed,o;xmm7;;}"
											 "{xmm8;ed,o;xmm8;;}" "{xmm9;ed,o;xmm9;;}" "{xmm10;ed,o;xmm10;;}" "{xmm11;ed,o;xmm11;;}" "{xmm12;ed,o;xmm12;;}" "{xmm13;ed,o;xmm13;;}" "{xmm14;ed,o;xmm14;;}" "{xmm15;ed,o;xmm15;;}"
											 "{ymm0;ed,o;ymm0;;}" "{ymm1;ed,o;ymm1;;}" "{ymm2;ed,o;ymm2;;}" "{ymm3;ed,o;ymm3;;}" "{ymm4;ed,o;ymm4;;}" "{ymm5;ed,o;ymm5;;}" "{ymm6;ed,o;ymm6;;}" "{ymm7;ed,o;ymm7;;}"
											 "{ymm8;ed,o;ymm8;;}" "{ymm9;ed,o;ymm9;;}" "{ymm10;ed,o;ymm10;;}" "{ymm11;ed,o;ymm11;;}" "{ymm12;ed,o;ymm12;;}" "{ymm13;ed,o;ymm13;;}" "{ymm14;ed,o;ymm14;;}" "{ymm15;ed,o;ymm15;;}"

											 "{view;b,o;view;;}")
{
	if (HasArg("view"))
	{
		view_cpu_context();
	}
	else
	{
		cpu_context_type context;
#ifdef _WIN64
		read_x64_cpu_context(&context);
#else
		read_x86_cpu_context(&context);
#endif

		if (HasArg("rax"))
			context.rax = GetArgU64("rax", false);
		
		if(HasArg("rbx"))
			context.rbx = GetArgU64("rbx", false);
		
		if (HasArg("rcx"))
			context.rcx = GetArgU64("rcx", false);
		
		if (HasArg("rdx"))
			context.rdx = GetArgU64("rdx", false);
		
		if (HasArg("rdi"))
			context.rdi = GetArgU64("rdi", false);
		
		if (HasArg("rsi"))
			context.rsi = GetArgU64("rsi", false);
		
		if (HasArg("rbp"))
			context.rbp = GetArgU64("rbp", false);
		
		if (HasArg("rsp"))
			context.rsp = GetArgU64("rsp", false);

		if (HasArg("rip"))
			context.rsp = GetArgU64("rip", false);
		
		if (HasArg("r8"))
			context.r8 = GetArgU64("r8", false);
		
		if (HasArg("r9"))
			context.r9 = GetArgU64("r9", false);
		
		if (HasArg("r10"))
			context.r10 = GetArgU64("r10", false);
		
		if (HasArg("r11"))
			context.r11 = GetArgU64("r11", false);
		
		if (HasArg("r12"))
			context.r12 = GetArgU64("r12", false);
		
		if (HasArg("r13"))
			context.r13 = GetArgU64("r13", false);
		
		if (HasArg("r14"))
			context.r14 = GetArgU64("r14", false);
		
		if (HasArg("r15"))
			context.r15 = GetArgU64("r15", false);

		if (HasArg("xmm0"))
			context.xmm0 = GetArgU64("xmm0", false);

		if (HasArg("xmm1"))
			context.xmm1 = GetArgU64("xmm1", false);

		if (HasArg("xmm2"))
			context.xmm2 = GetArgU64("xmm2", false);

		if (HasArg("xmm3"))
			context.xmm3 = GetArgU64("xmm3", false);

		if (HasArg("xmm4"))
			context.xmm4 = GetArgU64("xmm4", false);

		if (HasArg("xmm5"))
			context.xmm5 = GetArgU64("xmm5", false);

		if (HasArg("xmm6"))
			context.xmm6 = GetArgU64("xmm6", false);

		if (HasArg("xmm7"))
			context.xmm7 = GetArgU64("xmm7", false);

		if (HasArg("xmm8"))
			context.xmm8 = GetArgU64("xmm8", false);

		if (HasArg("xmm9"))
			context.xmm9 = GetArgU64("xmm9", false);

		if (HasArg("xmm10"))
			context.xmm10 = GetArgU64("xmm10", false);

		if (HasArg("xmm11"))
			context.xmm11 = GetArgU64("xmm11", false);

		if (HasArg("xmm12"))
			context.xmm12 = GetArgU64("xmm12", false);

		if (HasArg("xmm13"))
			context.xmm13 = GetArgU64("xmm13", false);

		if (HasArg("xmm14"))
			context.xmm14 = GetArgU64("xmm14", false);

		if (HasArg("xmm15"))
			context.xmm15 = GetArgU64("xmm15", false);

		if (HasArg("ymm0"))
			context.ymm0 = GetArgU64("ymm0", false);

		if (HasArg("ymm1"))
			context.ymm1 = GetArgU64("ymm1", false);

		if (HasArg("ymm2"))
			context.ymm2 = GetArgU64("ymm2", false);

		if (HasArg("ymm3"))
			context.ymm3 = GetArgU64("ymm3", false);

		if (HasArg("ymm4"))
			context.ymm4 = GetArgU64("ymm4", false);

		if (HasArg("ymm5"))
			context.ymm5 = GetArgU64("ymm5", false);

		if (HasArg("ymm6"))
			context.ymm6 = GetArgU64("ymm6", false);

		if (HasArg("ymm7"))
			context.ymm7 = GetArgU64("ymm7", false);

		if (HasArg("ymm8"))
			context.ymm8 = GetArgU64("ymm8", false);

		if (HasArg("ymm9"))
			context.ymm9 = GetArgU64("ymm9", false);

		if (HasArg("ymm10"))
			context.ymm10 = GetArgU64("ymm10", false);

		if (HasArg("ymm11"))
			context.ymm11 = GetArgU64("ymm11", false);

		if (HasArg("ymm12"))
			context.ymm12 = GetArgU64("ymm12", false);

		if (HasArg("ymm13"))
			context.ymm13 = GetArgU64("ymm13", false);

		if (HasArg("ymm14"))
			context.ymm14 = GetArgU64("ymm14", false);

		if (HasArg("ymm15"))
			context.ymm15 = GetArgU64("ymm15", false);

		if (HasArg("copy"))
		{
			engine_linker linker;
			cpu_context_type current_context = { 0, };

			if (linker.get_thread_context(&current_context))
			{
				context.rax = current_context.rax;
				context.rbx = current_context.rbx;
				context.rcx = current_context.rcx;
				context.rdx = current_context.rdx;

				context.rdi = current_context.rdi;
				context.rsi = current_context.rsi;

				context.rsp = current_context.rsp;
				context.rbp = current_context.rbp;

				context.rip = current_context.rip;

				context.efl = current_context.efl;

				context.r8 = current_context.r8;
				context.r9 = current_context.r9;
				context.r10 = current_context.r10;
				context.r11 = current_context.r11;
				context.r12 = current_context.r12;
				context.r13 = current_context.r13;
				context.r14 = current_context.r14;
				context.r15 = current_context.r15;
			}
		}

#ifdef _WIN64
		write_x64_cpu_context(context);
#else
		write_x86_cpu_context(context);
#endif

		view_cpu_context();
	}
}

