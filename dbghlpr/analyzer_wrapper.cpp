#include <analyzer_wrapper.h>

bool analyzer_wrapper::calc_exe_segment(unsigned long long ptr, unsigned long long *alloc_base, unsigned long long *alloc_end)
{
	std::shared_ptr<engine::linker> engine;
	if (!engine::create<engine_linker>(engine))
	{
		return false;
	}

	MEMORY_BASIC_INFORMATION64 mbi = { 0, };
	if (!engine->virtual_query(ptr, &mbi))
	{
		return false;
	}

	unsigned long long base_address = mbi.AllocationBase;
	unsigned long long base = base_address;
	unsigned long long analyze_base = 0;
	unsigned long long analyze_size = 0;

	do
	{
		if (!engine->virtual_query(base, &mbi))
		{
			break;
		}

		if (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY)
		{
			if (analyze_base == 0)
			{
				analyze_base = mbi.BaseAddress;
			}

			analyze_size += mbi.RegionSize;
		}
		else
		{
			if (analyze_base && analyze_size)
			{
				if (analyze_base <= ptr && (analyze_base + analyze_size) >= ptr)
				{
					*alloc_base = analyze_base;
					*alloc_end = analyze_base + analyze_size;

					return true;
				}

				analyze_base = 0;
				analyze_size = 0;
			}
		}

		base = mbi.BaseAddress + mbi.RegionSize;
	} while (base_address == mbi.AllocationBase);

	return false;
}

bool analyzer_wrapper::check(unsigned long long base, unsigned long long end, unsigned long long address)
{
	if (base <= address && end >= address)
	{
		return true;
	}

	return false;
}

//
// 
//
typedef struct _tag_callback_context
{
	unsigned long long ptr;
	unsigned long long entry;
}callback_context, *callback_context_ptr;

bool analyzer_wrapper::find_entry_callback(std::shared_ptr<engine::linker> engine, analyzer *current_analyzer_ptr, unsigned char *memory_dump, unsigned long long entry_point, void *context)
{
	std::set<unsigned long long> visited;
	analyzer::block b;
	memset(b.tag, 0, sizeof(b.tag));

	current_analyzer_ptr->trace(engine, entry_point, memory_dump, visited, b);
	callback_context_ptr cc = (callback_context_ptr)context;

	std::map<unsigned long long, analyzer::detail *>::iterator f = b.address_map.find(cc->ptr);
	if (f == b.address_map.end())
	{
		current_analyzer_ptr->free(&b);
		return true;
	}
	
	cc->entry = entry_point; // find
	current_analyzer_ptr->free(&b);

	return false;
}

unsigned long long analyzer_wrapper::find_entry(unsigned long long ptr, unsigned long long base, unsigned long long size)
{
	std::shared_ptr<engine::linker> engine;
	if (!engine::create<engine_linker>(engine))
	{
		return 0;
	}

	//_entry_point = ptr;
	callback_context cc = { 0, };
	cc.ptr = ptr;
	analyzer an(base, size, find_entry_callback, &cc);
	unsigned char *memory_dump = an.alloc(engine);

	if (!memory_dump)
	{
		return 0;
	}

	std::shared_ptr<void> memory_dump_closer(memory_dump, free);
	std::set<unsigned long long> entry_point_set;
	std::set<unsigned long long> visited;

	an.analyze(engine, memory_dump, entry_point_set);

	return cc.entry;
}

bool analyzer_wrapper::find_all_entry(unsigned long long base, unsigned long long size, std::set<unsigned long long> &entry_set)
{
	std::shared_ptr<engine::linker> engine;
	if (!engine::create<engine_linker>(engine))
	{
		return false;
	}

	analyzer an(base, size);
	unsigned char *memory_dump = an.alloc(engine);
	if (!memory_dump)
	{
		return false;
	}
	std::shared_ptr<void> memory_dump_closer(memory_dump, free);

	std::set<unsigned long long> visited;
	an.analyze(engine, memory_dump, entry_set);

	return true;
}

//
//
//
bool analyzer_wrapper::find_caller(unsigned long long ptr, unsigned long long base, unsigned long long size, std::list<unsigned long long> &caller_list)
{
	std::shared_ptr<engine::linker> engine;
	if (!engine::create<engine_linker>(engine))
	{
		return false;
	}

	analyzer an(base, size);
	unsigned char *memory_dump = an.alloc(engine);
	if (!memory_dump)
	{
		return false;
	}
	std::shared_ptr<void> memory_dump_closer(memory_dump, free);

	std::multimap<unsigned long long, unsigned long long> imm_map;
	unsigned long offset = 0;
	unsigned long long address = base;
	unsigned long long end = base + size;
	do
	{
		unsigned long long offset = address - base;
		cs_insn *insn = (cs_insn *)engine->disasm(address, &memory_dump[offset]);
		if (!insn)
		{
			++address;
			offset = (unsigned long)(address - base);
			if (address > end)
				break;
			continue;
		}

		cs_x86 *x86 = &(insn->detail->x86);
		cs_x86_op *op = x86->operands;
		for (int i = 0; i < x86->op_count; ++i)
		{
			cs_x86_op *op = &(x86->operands[i]);
			switch ((int)op->type)
			{
			case X86_OP_IMM:
				imm_map.insert(std::multimap<unsigned long long, unsigned long long>::value_type(op->imm, insn->address));
				break;
			default:
				break;
			}
		}

		address += insn->size;
	} while (address < end);

	std::pair<std::multimap<unsigned long long, unsigned long long>::iterator, std::multimap<unsigned long long, unsigned long long>::iterator> p;
	p = imm_map.equal_range(ptr);

	std::multimap<unsigned long long, unsigned long long>::iterator imm_set_it = p.first;
	for (imm_set_it; imm_set_it != p.second; ++imm_set_it)
	{
		caller_list.push_back(imm_set_it->second);
	}

	return true;
}

//
//
//
bool analyzer_wrapper::find_reference_value(unsigned long long base, unsigned long long size, std::multimap<unsigned long long, unsigned long long> &ref_map)
{
	std::shared_ptr<engine::linker> engine;
	if (!engine::create<engine_linker>(engine))
	{
		return false;
	}

	analyzer an(base, size);
	unsigned char *memory_dump = an.alloc(engine);
	if (!memory_dump)
	{
		return false;
	}
	std::shared_ptr<void> memory_dump_closer(memory_dump, free);

	std::multimap<unsigned long long, unsigned long long> ref_map_tmp;
	unsigned long offset = 0;
	unsigned long long address = base;
	unsigned long long end = base + size;
	do
	{
		unsigned long long offset = address - base;
		cs_insn *insn = (cs_insn *)engine->disasm(address, &memory_dump[offset]);
		if (!insn)
		{
			++address;
			offset = (unsigned long)(address - base);
			if (address > end)
				break;
			continue;
		}

		cs_x86 *x86 = &(insn->detail->x86);
		cs_x86_op *op = x86->operands;
		unsigned long long x64_disp = 0;
		unsigned long long value = 0;
		unsigned long r = 0;
		for (int i = 0; i < x86->op_count; ++i)
		{
			cs_x86_op *op = &(x86->operands[i]);
			switch ((int)op->type)
			{
			case X86_OP_IMM:
				ref_map_tmp.insert(std::multimap<unsigned long long, unsigned long long>::value_type(op->imm, insn->address));
				break;

			case X86_OP_MEM:
#ifdef _WIN64
				x64_disp = insn->address + op->mem.disp + insn->size;
				r = engine->read_virtual_memory(x64_disp, (unsigned char *)&value, sizeof(unsigned long long));
				if (r == sizeof(unsigned long long))
				{
					ref_map_tmp.insert(std::multimap<unsigned long long, unsigned long long>::value_type(value, insn->address));
				}
#else
				r = engine->read_virtual_memory(op->mem.disp, (unsigned char *)&value, sizeof(unsigned long));
				if (r == sizeof(unsigned long))
				{
					ref_map_tmp.insert(std::multimap<unsigned long long, unsigned long long>::value_type(value, insn->address));
				}
#endif
				break;

			default:
				break;
			}
		}

		address += insn->size;
	} while (address < end);

	std::multimap<unsigned long long, unsigned long long>::iterator ref_map_it = ref_map_tmp.begin();
	for (ref_map_it; ref_map_it != ref_map_tmp.end(); ++ref_map_it)
	{
		ref_map.insert(std::multimap<unsigned long long, unsigned long long>::value_type(ref_map_it->first, ref_map_it->second));
	}

	return true;
}
