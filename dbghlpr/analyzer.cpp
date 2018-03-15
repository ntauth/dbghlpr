#include <analyzer.h>

analyzer::analyzer(unsigned long long base, unsigned long long size) : base_address_(base), end_address_(base + size)
{
	cb_ = nullptr;
	cb_context_ = nullptr;
}

analyzer::analyzer(unsigned long long base, unsigned long long size, analyzer_callback_type cb, void *cb_context) : base_address_(base), end_address_(base + size), cb_(cb), cb_context_(cb_context)
{
}

//
//
//
unsigned char *analyzer::alloc(std::shared_ptr<engine::linker> engine)
{
	unsigned long long size = end_address_ - base_address_;
	unsigned char *memory_dump = (unsigned char *)malloc((size_t)size);

	if (!memory_dump)
	{
		return nullptr;
	}

	memset(memory_dump, 0, (size_t)size);
	unsigned long readn = engine->read_virtual_memory(base_address_, memory_dump, (unsigned long)size);
	if (readn != size)
	{
		::free(memory_dump);
		memory_dump = nullptr;
	}

	return memory_dump;
}

void analyzer::free(analyzer::block *b)
{
	std::map<unsigned long long, analyzer::detail *> address_map = b->address_map;
	std::map<unsigned long long, analyzer::detail *>::iterator dit = address_map.begin();
	for (dit; dit != address_map.end(); ++dit)
	{
		::free(dit->second);
	}
}

void analyzer::free(unsigned char *memory_dump)
{
	::free(memory_dump);
}

bool analyzer::check(unsigned long long address)
{
	if (base_address_ <= address && end_address_ >= address)
	{
		return true;
	}

	return false;
}

//
//
//
unsigned long long analyzer::get_base_address()
{
	return base_address_;
}

unsigned long long analyzer::get_end_address()
{
	return end_address_;
}

unsigned long long analyzer::get_jmp_imm(cs_insn *insn)
{
	cs_x86 *x86 = &(insn->detail->x86);
	unsigned long long return_dest = 0;

	if (x86->op_count > 1)
	{
		return return_dest;
	}

	cs_x86_op *op = &(x86->operands[0]);

	switch ((int)op->type)
	{
	case X86_OP_IMM:
		return_dest |= op->imm;
		break;
	default:
		break;
	}

	return return_dest;
}

//
//
//
void analyzer::analyze(std::shared_ptr<engine::linker> engine, unsigned char *memory_dump, std::set<unsigned long long> &entry_point_set)
{
	unsigned long long address = base_address_;
	unsigned long offset = 0;
	std::set<unsigned long long> visited;

	do
	{
		cs_insn *insn = (cs_insn *)engine->disasm(address, &memory_dump[offset]);
		if (!insn)
		{
			++address;
			offset = (unsigned long)(address - base_address_);
			if (address > end_address_)
				break;
			continue;
		}

		bool is_nop = (insn->id == X86_INS_NOP);
		bool is_int = (insn->id == X86_INS_INT3);
		bool is_add = (insn->id == X86_INS_ADD);

		if ((is_nop || is_int || is_add))
		{
			address += insn->size;
			offset = (unsigned long)(address - base_address_);
			if (address > end_address_)
				break;
			continue;
		}

		std::set<unsigned long long>::iterator mit = visited.find(address);
		if (mit != visited.end())
		{
			address += insn->size;
			offset = (unsigned long)(address - base_address_);
			if (address > end_address_)
				break;
			continue;
		}

		size_t insn_size = insn->size;
		set_entry_point(engine, address, memory_dump, visited);
		entry_point_set.insert(std::set<unsigned long long>::value_type(address));
		if (cb_)
		{
			if (!cb_(engine, this, memory_dump, address, cb_context_))
			{
				break;
			}
		}

		address += insn_size;
		offset = (unsigned long)(address - base_address_);
	} while (address < end_address_);

	visited.clear();
}

void analyzer::set_entry_point(std::shared_ptr<engine::linker> engine, unsigned long long address, unsigned char *memory_dump, std::set<unsigned long long> &visited)
{
	if (address > end_address_)
		return;

	std::list<unsigned long long> backup;
	std::list<unsigned long long>::iterator bit;
	while (address && check(address))
	{
		unsigned long long offset = address - base_address_;
		cs_insn *insn = (cs_insn *)engine->disasm(address, &memory_dump[offset]);
		if (!insn)
		{
			break;
		}
		cs_x86 *x86 = &(insn->detail->x86);
		cs_x86_op *op = x86->operands;
		unsigned long op_count = 0;

		std::set<unsigned long long>::iterator vit = visited.find(address);
		if (vit != visited.end())
		{
			if (backup.size())
			{
				bit = backup.end();
				address = *(--bit);
				backup.pop_back();

				continue;
			}
			else
			{
				break;
			}
		}

		bool is_jmp_code = cs_insn_group((csh)engine->get_disasm_handle(), insn, X86_GRP_JUMP);
		unsigned long long jmp_dset = 0;
		if (is_jmp_code)
		{
			jmp_dset = get_jmp_imm(insn);
			op_count = x86->op_count;
		}

		visited.insert(std::set<unsigned long long>::value_type(address));

		if (jmp_dset)
		{
			MEMORY_BASIC_INFORMATION64 mbi = { 0, };
			if (!engine->virtual_query(jmp_dset, &mbi))
			{
				break;
			}

			if (mbi.State != MEM_COMMIT || !(mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY))
			{
				break;
			}
		}

		if (is_jmp_code && insn->id != X86_INS_JMP) // 분기문
		{
			backup.push_back(address + insn->size);
			address = get_jmp_imm(insn);

			continue;
		}

		if (insn->id == X86_INS_JMP)
		{
			address = get_jmp_imm(insn);

			if (!check(address) && backup.size())
			{
				bit = backup.end();
				address = *(--bit);
				backup.pop_back();
			}
		}
		else if (cs_insn_group((csh)engine->get_disasm_handle(), insn, X86_GRP_RET))
		{
			if (backup.size())
			{
				bit = backup.end();
				address = *(--bit);
				backup.pop_back();
			}
			else
			{
				break;
			}
		}
		else if (!cs_insn_group((csh)engine->get_disasm_handle(), insn, X86_GRP_INT) && !(insn->bytes[0] == 0 && insn->bytes[1] == 0))
		{
			address += insn->size;
		}
		else
		{
			if (backup.size())
			{
				bit = backup.end();
				address = *(--bit);
				backup.pop_back();
			}
			else
			{
				break;
			}
		}
	}
}

analyzer::detail * analyzer::create_address()
{
	analyzer::detail *d = new analyzer::detail;
	memset(d->comment, 0, sizeof(d->comment));

	d->instruction_id = 0;
	d->operand_count = 0;
	d->is_jmp_code = false;

	for (int i = 0; i < 8; ++i)
	{
		d->operands[i].operand_type = 0;
		d->operands[i].value = 0;
	}

	return d;
}

void analyzer::trace(std::shared_ptr<engine::linker> engine, unsigned long long address, unsigned char *memory_dump, std::set<unsigned long long> &visited, block &b)
{
	if (address > end_address_)
		return;

	std::list<unsigned long long> backup;
	std::list<unsigned long long>::iterator bit;
	while (address && check(address))
	{
		unsigned long long offset = address - base_address_;
		cs_insn *insn = (cs_insn *)engine->disasm(address, &memory_dump[offset]);
		if (!insn)
		{
			break;
		}
		cs_x86 *x86 = &(insn->detail->x86);
		cs_x86_op *op = x86->operands;

		std::set<unsigned long long>::iterator vit = visited.find(address);
		if (vit != visited.end())
		{
			if (backup.size())
			{
				bit = backup.end();
				address = *(--bit);
				backup.pop_back();

				continue;
			}
			else
			{
				break;
			}
		}

		bool is_jmp_code = cs_insn_group((csh)engine->get_disasm_handle(), insn, X86_GRP_JUMP);
		
		analyzer::detail *d = create_address();
		d->operand_count = x86->op_count;
		for (int i = 0; i < x86->op_count; ++i)
		{
			cs_x86_op *op = &(x86->operands[i]);
			switch ((int)op->type)
			{
			case X86_OP_IMM:
				d->operands[i].operand_type = X86_OP_IMM;
				d->operands[i].value = op->imm;
				break;

			case X86_OP_MEM:
				d->operands[i].operand_type = X86_OP_MEM;
				d->operands[i].value = op->mem.disp;
				break;

			case X86_OP_REG:
				d->operands[i].operand_type = X86_OP_REG;
				d->operands[i].value = op->reg;
				break;

			default:
				break;
			}
		}

		d->is_jmp_code = is_jmp_code;

		b.address_map.insert(std::map<unsigned long long, analyzer::detail *>::value_type(address, d));
		visited.insert(std::set<unsigned long long>::value_type(address));

		if (is_jmp_code && insn->id != X86_INS_JMP) // 분기문
		{
			backup.push_back(address + insn->size);
			address = get_jmp_imm(insn);

			continue;
		}

		if (insn->id == X86_INS_JMP)
		{
			address = get_jmp_imm(insn);

			if (!check(address) && backup.size())
			{
				bit = backup.end();
				address = *(--bit);
				backup.pop_back();
			}
		}
		else if (cs_insn_group((csh)engine->get_disasm_handle(), insn, X86_GRP_RET))
		{
			if (backup.size())
			{
				bit = backup.end();
				address = *(--bit);
				backup.pop_back();
			}
			else
			{
				break;
			}
		}
		else if (!cs_insn_group((csh)engine->get_disasm_handle(), insn, X86_GRP_INT) && !(insn->bytes[0] == 0 && insn->bytes[1] == 0))
		{
			address += insn->size;
		}
		else
		{
			if (backup.size())
			{
				bit = backup.end();
				address = *(--bit);
				backup.pop_back();
			}
			else
			{
				break;
			}
		}
	}
}

//
//
//
std::map<unsigned long long, analyzer::block> analyzer::get_block_map()
{
	return block_map_;
}

void analyzer::set_imm_multimap(std::multimap<unsigned long long, unsigned long long> &caller_callee_map)
{
	std::map<unsigned long long, block>::iterator it = block_map_.begin();
	std::map<unsigned long long, block>::iterator end_it = block_map_.end();

	for (it; it != end_it; ++it)
	{
		std::map<unsigned long long, detail *>::iterator address_it = it->second.address_map.begin();
		std::map<unsigned long long, detail *>::iterator address__end_it = it->second.address_map.end();

		for (int i = 0; i < address_it->second->operand_count; ++it)
		{
			if (address_it->second->operands[i].operand_type == X86_OP_IMM && check(address_it->second->operands[i].value))
			{
				caller_callee_map.insert(std::multimap<unsigned long long, unsigned long long>::value_type(address_it->first, address_it->second->operands[i].value));
			}
		}
	}
}

