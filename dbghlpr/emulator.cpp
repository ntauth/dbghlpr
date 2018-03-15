#include <emulator.h>

#if 0
emulation_debugger::emulation_debugger()
{
}

emulation_debugger::~emulation_debugger()
{
	uc_close(uc_engine_);
}

bool emulation_debugger::attach(trace_item *ti)
{
}

bool emulation_debugger::attach(trace_item *ti, cpu_context_type *cpu_context)
{
	uc_hook code_hook;
	uc_hook write_unmap_hook;
	uc_hook read_unmap_hook;
	uc_hook fetch_hook;

	if (uc_open(UC_ARCH_X86, (uc_mode)ti->mode, &uc_engine_) != 0)
	{
		return false;
	}
	uc_hook_add(uc_engine_, &code_hook, UC_HOOK_CODE, ti->code_callback, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add(uc_engine_, &write_unmap_hook, UC_HOOK_MEM_WRITE_UNMAPPED, ti->unmap_callback, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add(uc_engine_, &read_unmap_hook, UC_HOOK_MEM_READ_UNMAPPED, ti->unmap_callback, NULL, (uint64_t)1, (uint64_t)0);
	uc_hook_add(uc_engine_, &fetch_hook, UC_HOOK_MEM_FETCH_UNMAPPED, ti->fetch_callback, NULL, (uint64_t)1, (uint64_t)0);

	set_environment_block(ti->mode);
	load((void *)teb_address_);
	load((void *)peb_address_);

	if(!cpu_context)
	{
		memset(&context_, 0, sizeof(context_));
		engine_.get_thread_context(&context_);
	}
	else
	{
		memcpy(&context_, cpu_context, sizeof(cpu_context_type));
	}

	mode_ = ti->mode;
	create_global_descriptor_table(ti->mode);
	load_context(ti->mode);
	load((void *)context_.rip);
	load((void *)context_.rsp);

	return true;
}

bool __stdcall emulation_debugger::trace(void *engine, trace_item item)
{
	uc_err err = (uc_err)0;
	uc_engine *uc = (uc_engine *)engine;
	BYTE dump[1024];

	unsigned long long end_point = context_.rip + 0x1000;
	unsigned long step = 1;

	if (engine_.read_virtual_memory(context_.rip, dump, 1024) && engine_.disasm(context_.rip, dump))
	{
		if (item.break_point)
		{
			end_point = item.break_point;
			step = 0;
		}

		err = uc_emu_start(uc, context_.rip, end_point, 0, step);
		if (err)
		{
			if (err == UC_ERR_WRITE_UNMAPPED || err == UC_ERR_READ_UNMAPPED || err == UC_ERR_FETCH_UNMAPPED)
			{
				unsigned restart_count = 0;
				do
				{
					err = uc_emu_start(uc, context_.rip, end_point, 0, step);
					++restart_count;
				} while ((err == UC_ERR_WRITE_UNMAPPED || err == UC_ERR_READ_UNMAPPED || err == UC_ERR_FETCH_UNMAPPED) && restart_count < 3);
			}
		}
	}
	else
	{
		err = UC_ERR_EXCEPTION;
	}

	if (item.mode == UC_MODE_64)
	{
		if (!read_x64_cpu_context())
		{
			return false;
		}
	}
	else
	{
		if (!read_x86_cpu_context())
		{
			return false;
		}
	}

	if (err)
	{
		return false;
	}

	return true;
}

cpu_context_type emulation_debugger::get_cpu_context()
{
	return context_;
}

engine_linker emulation_debugger::get_engine_linker()
{
	return engine_;
}

size_t __stdcall emulation_debugger::alignment(size_t region_size, unsigned long image_aligin)
{
	unsigned long mod = region_size % image_aligin;
	region_size -= mod;

	return region_size + image_aligin;
}

//
//
//
bool emulation_debugger::set_environment_block(unsigned long mode)
{
	peb_address_ = engine_.get_peb_address();
	teb_address_ = engine_.get_teb_address();

	if (!peb_address_ || !teb_address_)
		return false;

	if (mode == UC_MODE_64)
	{

	}

	//if (is_wow64cpu())
	//{
	//	teb_64_address_ = teb_address_;
	//	NT_TIB64 tib_64;
	//	if (!windbg_linker_.read_memory(teb_64_address_, &tib_64, sizeof(tib_64)))
	//		return false;
	//	teb_address_ = tib_64.ExceptionList;

	//	peb_64_address_ = peb_address_;
	//	unsigned char teb32[1024];
	//	if (!windbg_linker_.read_memory(teb_address_, &teb32, sizeof(teb32)))
	//		return false;

	//	peb_address_ = *((unsigned long long *)&teb32[0x30]);
	//}

	return true;
}

bool emulation_debugger::set_msr(unsigned long long msr, unsigned long long address)
{
	unsigned long long rax = 0;
	unsigned long long rdx = 0;
	unsigned long long rcx = 0;
	unsigned long long rip = 0;

	uc_reg_read(uc_engine_, UC_X86_REG_RAX, &rax);
	uc_reg_read(uc_engine_, UC_X86_REG_RDX, &rdx);
	uc_reg_read(uc_engine_, UC_X86_REG_RCX, &rcx);
	uc_reg_read(uc_engine_, UC_X86_REG_RIP, &rip);

	unsigned char wrmsr[2] = { 0x0f, 0x30 }; // wrmsr code
	load(uc_engine_, 0x80000, 0x1000, wrmsr, 2); // 

	unsigned long long t_rax = address & 0xFFFFFFFF;
	unsigned long long t_rdx = (address >> 32) & 0xFFFFFFFF;
	unsigned long long t_rcx = msr & 0xFFFFFFFF;

	uc_reg_write(uc_engine_, UC_X86_REG_RAX, &t_rax);
	uc_reg_write(uc_engine_, UC_X86_REG_RDX, &t_rdx);
	uc_reg_write(uc_engine_, UC_X86_REG_RCX, &t_rcx);

	uc_err err = uc_emu_start(uc_engine_, 0x80000, 0x80000 + 2, 0, 1);
	if (err)
	{
		return false;
	}

	uc_reg_write(uc_engine_, UC_X86_REG_RAX, &rax);
	uc_reg_write(uc_engine_, UC_X86_REG_RDX, &rdx);
	uc_reg_write(uc_engine_, UC_X86_REG_RCX, &rcx);
	uc_reg_write(uc_engine_, UC_X86_REG_RIP, &rip);

	return true;
}

void emulation_debugger::set_global_descriptor(SegmentDescriptor *desc, uint32_t base, uint32_t limit, uint8_t is_code)
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

bool __stdcall emulation_debugger::create_global_descriptor_table(unsigned long mode)
{
	SegmentDescriptor global_descriptor[31];
	memset(global_descriptor, 0, sizeof(global_descriptor));

	if (context_.ds == context_.ss)
		context_.ss = 0x88; // rpl = 0

	context_.gs = 0x63;

	set_global_descriptor(&global_descriptor[0x33 >> 3], 0, 0xfffff000, 1); // 64 code
	set_global_descriptor(&global_descriptor[context_.cs >> 3], 0, 0xfffff000, 1);
	set_global_descriptor(&global_descriptor[context_.ds >> 3], 0, 0xfffff000, 0);
	
	if (mode == UC_MODE_64)
	{
		//set_msr(FS_MSR, )
		set_global_descriptor(&global_descriptor[context_.fs >> 3], (unsigned long)teb_address_, 0xfff, 0);
		set_global_descriptor(&global_descriptor[context_.gs >> 3], (unsigned long)teb_64_address_, 0xfffff000, 0);
	}
	else
	{
		set_global_descriptor(&global_descriptor[context_.fs >> 3], (unsigned long)teb_address_, 0xfff, 0);
	}
	//set_global_descriptor(&global_descriptor[context_.gs >> 3], (unsigned long)teb_64_address_, 0xfffff000, 0);
	set_global_descriptor(&global_descriptor[context_.ss >> 3], 0, 0xfffff000, 0);
	global_descriptor[context_.ss >> 3].dpl = 0; // dpl = 0, cpl = 0

	gdt_base_ = 0xc0000000;
	uc_x86_mmr gdtr;
	gdtr.base = gdt_base_;
	gdtr.limit = (sizeof(SegmentDescriptor) * 31) - 1;

	if (uc_reg_write(uc_engine_, UC_X86_REG_GDTR, &gdtr) != 0)
		return false;

	if (!load(uc_engine_, gdt_base_, 0x10000, global_descriptor, sizeof(global_descriptor)))
		return false;

	return true;
}

bool __stdcall emulation_debugger::load(void *engine, unsigned long long load_address, size_t load_size, void *dump, size_t write_size)
{
	if (!engine)
	{
		engine = uc_engine_;
	}

	uc_err err;
	if ((err = uc_mem_map((uc_engine *)engine, load_address, load_size, UC_PROT_ALL)) != 0)
	{
		if (err != UC_ERR_MAP)
			return false;
	}

	if ((err = uc_mem_write((uc_engine *)engine, load_address, dump, write_size)) != 0)
	{
		if (err != UC_ERR_MAP)
			return false;
	}
	return true;
}

bool __stdcall emulation_debugger::load(void *address)
{
	if (!uc_engine_)
		return false;

	MEMORY_BASIC_INFORMATION64 mbi;
	memset(&mbi, 0, sizeof(mbi));
	if (!engine_.virtual_query((unsigned long long)address, &mbi))
		return false;

	unsigned char *dump = (unsigned char *)malloc((size_t)mbi.RegionSize);
	if (!dump)
		return false;
	std::shared_ptr<void> dump_closer(dump, free);

	if (!engine_.read_virtual_memory(mbi.BaseAddress, dump, (size_t)mbi.RegionSize))
		return false;

	uc_err err;
	if ((err = uc_mem_map(uc_engine_, mbi.BaseAddress, (size_t)mbi.RegionSize, UC_PROT_ALL)) != 0)
	{
		if (err != UC_ERR_MAP)
			return false;
	}

	if ((err = uc_mem_write(uc_engine_, mbi.BaseAddress, dump, (size_t)mbi.RegionSize)) != 0)
		return false;

	//dprintf("load::%08x-%08x\n", mbi.BaseAddress, mbi.RegionSize);

	return true;
}

bool __stdcall emulation_debugger::query(unsigned long long address, unsigned long long *base, unsigned long long *size)
{
	if (!uc_engine_)
		return false;

	uc_mem_region *um = nullptr;
	uint32_t count = 0;

	if (uc_mem_regions(uc_engine_, &um, &count) != 0)
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

//
//
//
bool __stdcall emulation_debugger::load_context(unsigned long mode)
{
	if ((uc_mode)mode == UC_MODE_64)
	{
		if (!write_x64_cpu_context())
			return false;
	}
	else
	{
		if (!write_x86_cpu_context())
			return false;
	}

	return true;
}

bool __stdcall emulation_debugger::read_x86_cpu_context()
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

	if (uc_reg_read_batch(uc_engine_, x86_register, read_ptr, size) != 0)
		return false;

	context_.rax = read_register[PR_RAX];
	context_.rbx = read_register[PR_RBX];
	context_.rcx = read_register[PR_RCX];
	context_.rdx = read_register[PR_RDX];
	context_.rsi = read_register[PR_RSI];
	context_.rdi = read_register[PR_RDI];
	context_.rsp = read_register[PR_RSP];
	context_.rbp = read_register[PR_RBP];
	context_.rip = read_register[PR_RIP];

	context_.xmm0 = read_register[PR_XMM0];
	context_.xmm1 = read_register[PR_XMM1];
	context_.xmm2 = read_register[PR_XMM2];
	context_.xmm3 = read_register[PR_XMM3];
	context_.xmm4 = read_register[PR_XMM4];
	context_.xmm5 = read_register[PR_XMM5];
	context_.xmm6 = read_register[PR_XMM6];
	context_.xmm7 = read_register[PR_XMM7];

	context_.ymm0 = read_register[PR_YMM0];
	context_.ymm1 = read_register[PR_YMM1];
	context_.ymm2 = read_register[PR_YMM2];
	context_.ymm3 = read_register[PR_YMM3];
	context_.ymm4 = read_register[PR_YMM4];
	context_.ymm5 = read_register[PR_YMM5];
	context_.ymm6 = read_register[PR_YMM6];
	context_.ymm7 = read_register[PR_YMM7];

	context_.efl = read_register[PR_EFLAGS];
	context_.cs = (unsigned short)read_register[PR_REG_CS];
	context_.ds = (unsigned short)read_register[PR_REG_DS];
	context_.es = (unsigned short)read_register[PR_REG_ES];
	context_.fs = (unsigned short)read_register[PR_REG_FS];
	context_.gs = (unsigned short)read_register[PR_REG_GS];
	context_.ss = (unsigned short)read_register[PR_REG_SS];

	return true;
}

bool __stdcall emulation_debugger::write_x86_cpu_context()
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

	write_register[PR_RAX] = (unsigned long)context_.rax;
	write_register[PR_RBX] = (unsigned long)context_.rbx;
	write_register[PR_RCX] = (unsigned long)context_.rcx;
	write_register[PR_RDX] = (unsigned long)context_.rdx;
	write_register[PR_RSI] = (unsigned long)context_.rsi;
	write_register[PR_RDI] = (unsigned long)context_.rdi;
	write_register[PR_RSP] = (unsigned long)context_.rsp;
	write_register[PR_RBP] = (unsigned long)context_.rbp;
	write_register[PR_RIP] = (unsigned long)context_.rip;
	write_register[PR_EFLAGS] = (unsigned long)context_.efl;

	write_register[PR_XMM0] = (unsigned long)context_.xmm0;
	write_register[PR_XMM1] = (unsigned long)context_.xmm1;
	write_register[PR_XMM2] = (unsigned long)context_.xmm2;
	write_register[PR_XMM3] = (unsigned long)context_.xmm3;
	write_register[PR_XMM4] = (unsigned long)context_.xmm4;
	write_register[PR_XMM5] = (unsigned long)context_.xmm5;
	write_register[PR_XMM6] = (unsigned long)context_.xmm6;
	write_register[PR_XMM7] = (unsigned long)context_.xmm7;

	write_register[PR_YMM0] = (unsigned long)context_.ymm0;
	write_register[PR_YMM1] = (unsigned long)context_.ymm1;
	write_register[PR_YMM2] = (unsigned long)context_.ymm2;
	write_register[PR_YMM3] = (unsigned long)context_.ymm3;
	write_register[PR_YMM4] = (unsigned long)context_.ymm4;
	write_register[PR_YMM5] = (unsigned long)context_.ymm5;
	write_register[PR_YMM6] = (unsigned long)context_.ymm6;
	write_register[PR_YMM7] = (unsigned long)context_.ymm7;

	write_register[PR_REG_CS] = context_.cs;
	write_register[PR_REG_DS] = context_.ds;
	write_register[PR_REG_ES] = context_.es;
	write_register[PR_REG_FS] = context_.fs;
	write_register[PR_REG_GS] = context_.gs;
	write_register[PR_REG_SS] = context_.ss;

	if (uc_reg_write_batch(uc_engine_, x86_register, write_ptr, size) != 0)
		return false;

	return true;
}

bool __stdcall emulation_debugger::write_x64_cpu_context()
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

	write_register[PR_RAX] = context_.rax;
	write_register[PR_RBX] = context_.rbx;
	write_register[PR_RCX] = context_.rcx;
	write_register[PR_RDX] = context_.rdx;
	write_register[PR_RSI] = context_.rsi;
	write_register[PR_RDI] = context_.rdi;
	write_register[PR_RSP] = context_.rsp;
	write_register[PR_RBP] = context_.rbp;
	write_register[PR_R8] = context_.r8;
	write_register[PR_R9] = context_.r9;
	write_register[PR_R10] = context_.r10;
	write_register[PR_R11] = context_.r11;
	write_register[PR_R12] = context_.r12;
	write_register[PR_R13] = context_.r13;
	write_register[PR_R14] = context_.r14;
	write_register[PR_R15] = context_.r15;
	write_register[PR_EFLAGS] = (unsigned long)context_.efl;

	write_register[PR_XMM0] = context_.xmm0;
	write_register[PR_XMM1] = context_.xmm1;
	write_register[PR_XMM2] = context_.xmm2;
	write_register[PR_XMM3] = context_.xmm3;
	write_register[PR_XMM4] = context_.xmm4;
	write_register[PR_XMM5] = context_.xmm5;
	write_register[PR_XMM6] = context_.xmm6;
	write_register[PR_XMM7] = context_.xmm7;
	write_register[PR_XMM8] = context_.xmm8;
	write_register[PR_XMM9] = context_.xmm9;
	write_register[PR_XMM10] = context_.xmm10;
	write_register[PR_XMM11] = context_.xmm11;
	write_register[PR_XMM12] = context_.xmm12;
	write_register[PR_XMM13] = context_.xmm13;
	write_register[PR_XMM14] = context_.xmm14;
	write_register[PR_XMM15] = context_.xmm15;

	write_register[PR_YMM0] = context_.ymm0;
	write_register[PR_YMM1] = context_.ymm1;
	write_register[PR_YMM2] = context_.ymm2;
	write_register[PR_YMM3] = context_.ymm3;
	write_register[PR_YMM4] = context_.ymm4;
	write_register[PR_YMM5] = context_.ymm5;
	write_register[PR_YMM6] = context_.ymm6;
	write_register[PR_YMM7] = context_.ymm7;
	write_register[PR_YMM8] = context_.ymm8;
	write_register[PR_YMM9] = context_.ymm9;
	write_register[PR_YMM10] = context_.ymm10;
	write_register[PR_YMM11] = context_.ymm11;
	write_register[PR_YMM12] = context_.ymm12;
	write_register[PR_YMM13] = context_.ymm13;
	write_register[PR_YMM14] = context_.ymm14;
	write_register[PR_YMM15] = context_.ymm15;

	write_register[PR_REG_CS] = context_.cs;
	write_register[PR_REG_DS] = context_.ds;
	write_register[PR_REG_ES] = context_.es;
	write_register[PR_REG_FS] = context_.fs;
	write_register[PR_REG_GS] = context_.gs;
	write_register[PR_REG_SS] = context_.ss;

	if (uc_reg_write_batch(uc_engine_, x86_register, write_ptr, size) != 0)
		return false;
#endif
	return true;
}

bool __stdcall emulation_debugger::read_x64_cpu_context()
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

	if (uc_reg_read_batch(uc_engine_, x86_register, read_ptr, size) != 0)
		return false;

	context_.rax = read_register[PR_RAX];
	context_.rbx = read_register[PR_RBX];
	context_.rcx = read_register[PR_RCX];
	context_.rdx = read_register[PR_RDX];
	context_.rsi = read_register[PR_RSI];
	context_.rdi = read_register[PR_RDI];
	context_.rsp = read_register[PR_RSP];
	context_.rbp = read_register[PR_RBP];
	context_.rip = read_register[PR_RIP];
	context_.r8 = read_register[PR_R8];
	context_.r9 = read_register[PR_R9];
	context_.r10 = read_register[PR_R10];
	context_.r11 = read_register[PR_R11];
	context_.r12 = read_register[PR_R12];
	context_.r13 = read_register[PR_R13];
	context_.r14 = read_register[PR_R14];
	context_.r15 = read_register[PR_R15];
	context_.efl = (unsigned long)read_register[PR_EFLAGS];

	context_.xmm0 = read_register[PR_XMM0];
	context_.xmm1 = read_register[PR_XMM1];
	context_.xmm2 = read_register[PR_XMM2];
	context_.xmm3 = read_register[PR_XMM3];
	context_.xmm4 = read_register[PR_XMM4];
	context_.xmm5 = read_register[PR_XMM5];
	context_.xmm6 = read_register[PR_XMM6];
	context_.xmm7 = read_register[PR_XMM7];
	context_.xmm8 = read_register[PR_XMM8];
	context_.xmm9 = read_register[PR_XMM9];
	context_.xmm10 = read_register[PR_XMM10];
	context_.xmm11 = read_register[PR_XMM11];
	context_.xmm12 = read_register[PR_XMM12];
	context_.xmm13 = read_register[PR_XMM13];
	context_.xmm14 = read_register[PR_XMM14];
	context_.xmm15 = read_register[PR_XMM15];

	context_.ymm0 = read_register[PR_YMM0];
	context_.ymm1 = read_register[PR_YMM1];
	context_.ymm2 = read_register[PR_YMM2];
	context_.ymm3 = read_register[PR_YMM3];
	context_.ymm4 = read_register[PR_YMM4];
	context_.ymm5 = read_register[PR_YMM5];
	context_.ymm6 = read_register[PR_YMM6];
	context_.ymm7 = read_register[PR_YMM7];
	context_.ymm8 = read_register[PR_YMM8];
	context_.ymm9 = read_register[PR_YMM9];
	context_.ymm10 = read_register[PR_YMM10];
	context_.ymm11 = read_register[PR_YMM11];
	context_.ymm12 = read_register[PR_YMM12];
	context_.ymm13 = read_register[PR_YMM13];
	context_.ymm14 = read_register[PR_YMM14];
	context_.ymm15 = read_register[PR_YMM15];

	context_.cs = (unsigned short)read_register[PR_REG_CS];
	context_.ds = (unsigned short)read_register[PR_REG_DS];
	context_.es = (unsigned short)read_register[PR_REG_ES];
	context_.fs = (unsigned short)read_register[PR_REG_FS];
	context_.gs = (unsigned short)read_register[PR_REG_GS];
	context_.ss = (unsigned short)read_register[PR_REG_SS];
#endif
	return true;
}
#endif