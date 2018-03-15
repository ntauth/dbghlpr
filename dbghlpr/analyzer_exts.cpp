#define _CRT_SECURE_NO_WARNINGS

#include <engextcpp.hpp>
#include <windows.h>

#include <list>
#include <memory>

#include <interface.h>
#include <engine.h>

#include <capstone.h>
#include <engine_linker.h>

#include <analyzer_wrapper.h>

EXT_CLASS_COMMAND(WindbgEngine, calc, "", "{p;ed,o;p;;}" "{exe;b,o;exe;;}")
{
	unsigned long long ptr = GetArgU64("p", FALSE);

	unsigned long long base = 0;
	unsigned long long end = 0;
	analyzer_wrapper::calc_exe_segment(ptr, &base, &end);

	dprintf("%I64x-%I64x, %I64x\n", base, end, end - base);
}

EXT_CLASS_COMMAND(WindbgEngine, fe, "", "{p;ed,o;p;;}") // find entry
{
	unsigned long long ptr = GetArgU64("p", FALSE);
	unsigned long long base = 0;
	unsigned long long end = 0;
	analyzer_wrapper::calc_exe_segment(ptr, &base, &end);

	dprintf(" [+] %I64x\n", ptr);

	ptr = analyzer_wrapper::find_entry(ptr, base, end - base);

	dprintf(" [-] %I64x-%I64x\n", base, end);
	if (ptr)
	{
		dprintf("	[-] %I64x\n", ptr);
	}
	else
	{
		dprintf("	[-] nop\n");
	}
}

EXT_CLASS_COMMAND(WindbgEngine, fae, "", "{p;ed,o;p;;}") // find all entry
{
	unsigned long long ptr = GetArgU64("p", FALSE);
	unsigned long long base = 0;
	unsigned long long end = 0;
	analyzer_wrapper::calc_exe_segment(ptr, &base, &end);

	std::set<unsigned long long> entry_point_set;
	if (analyzer_wrapper::find_all_entry(base, end - base, entry_point_set))
	{
		int i = 0;
		std::set<unsigned long long>::iterator entry_point_set_it = entry_point_set.begin();
		for (entry_point_set_it; entry_point_set_it != entry_point_set.end(); ++entry_point_set_it, ++i)
		{
			if (i % 8 == 0)
			{
				dprintf("\n");
			}

#ifdef _WIN64
			dprintf("%I64x ", *entry_point_set_it);
#else
			dprintf("%08x ", *entry_point_set_it);
#endif
		}
	}
}

EXT_CLASS_COMMAND(WindbgEngine, caller, "", "{p;ed,o;p;;}") // find caller
{
	unsigned long long ptr = GetArgU64("p", FALSE);
	unsigned long long base = 0;
	unsigned long long end = 0;
	std::list<unsigned long long> l;

	analyzer_wrapper::calc_exe_segment(ptr, &base, &end);
	ptr = analyzer_wrapper::find_entry(ptr, base, end - base);
	analyzer_wrapper::find_caller(ptr, base, end - base, l);

	dprintf(" [-] %I64x-%I64x\n", base, end);
	dprintf(" [+] %I64x\n", ptr);

	std::list<unsigned long long>::iterator it = l.begin();
	if (l.size())
	{
		dprintf("	[-] ");
		for (it; it != l.end(); ++it)
		{
			dprintf("%I64x ", *it);
		}
		dprintf("\n");
	}
	else
	{
		dprintf("	[-] nop\n");
	}
}

//
//
//
#include <helper.h>
#include <strsafe.h>

void print_ascii(unsigned char *p, size_t l)
{
	for (size_t i = 0; i < l; ++i)
	{
		if (isprint(p[i]))
			dprintf("%c", p[i]);
	}
}

void print_unicode(unsigned char *p, size_t l)
{
	for (size_t i = 0; i < l * 2; ++i)
	{
		if (isprint(p[i]))
			dprintf("%c", p[i]);
	}
}

EXT_CLASS_COMMAND(WindbgEngine, refstr, "", "{p;ed,o;p;;}" "{a;b,o;a;;}") // ref string
{
	std::shared_ptr<engine::linker> engine;
	if (!engine::create<engine_linker>(engine))
	{
		return;
	}

	unsigned long long ptr = GetArgU64("p", FALSE);
	unsigned long long base = 0;
	unsigned long long end = 0;
	std::multimap<unsigned long long, unsigned long long> ref_map;

	analyzer_wrapper::calc_exe_segment(ptr, &base, &end);
	analyzer_wrapper::find_reference_value(base, end - base, ref_map);

	std::multimap<unsigned long long, unsigned long long>::iterator ref_map_it = ref_map.begin();
	unsigned char str_dump[1024];
	unsigned long long address;
	for (ref_map_it; ref_map_it != ref_map.end(); ++ref_map_it)
	{
		memset(str_dump, 0, sizeof(str_dump));
		unsigned long long readn = engine->read_virtual_memory(ref_map_it->first, (unsigned char*)str_dump, 1024);
		if (readn == 0)
		{
			continue;
		}

		if (helper::is_ascii(str_dump, 512))
		{
			size_t l = strlen((char *)str_dump);

			address = ref_map_it->second;
			char str[1024] = { 0, };
			Disasm(&address, str, false);

			char comment_str[1024];
			StringCbCopyA(comment_str, strlen(str), str);

			dprintf("	[-] %s	; \"", comment_str), print_ascii(str_dump, l), dprintf("\"\n");
		}

		if (helper::is_unicode(str_dump, 512))
		{
			size_t l = wcslen((wchar_t *)str_dump);

			address = ref_map_it->second;
			char str[1024] = { 0, };
			Disasm(&address, str, false);

			char comment_str[1024];
			StringCbCopyA(comment_str, strlen(str), str);

			dprintf("	[-] %s	; \"", comment_str), print_unicode(str_dump, l), dprintf("\"\n");
		}
	}
}

EXT_CLASS_COMMAND(WindbgEngine, refexe, "", "{p;ed,o;p;;}" "{a;b,o;a;;}") // ref exe memory
{
	std::shared_ptr<engine::linker> engine;
	if (!engine::create<engine_linker>(engine))
	{
		return;
	}

	unsigned long long ptr = GetArgU64("p", FALSE);
	unsigned long long base = 0;
	unsigned long long end = 0;
	std::multimap<unsigned long long, unsigned long long> ref_map;

	analyzer_wrapper::calc_exe_segment(ptr, &base, &end);
	analyzer_wrapper::find_reference_value(base, end - base, ref_map);

	std::multimap<unsigned long long, unsigned long long>::iterator ref_map_it = ref_map.begin();
	for (ref_map_it; ref_map_it != ref_map.end(); ++ref_map_it)
	{
		MEMORY_BASIC_INFORMATION64 mbi = { 0, };
		if (!engine->virtual_query(ref_map_it->first, &mbi))
		{
			continue;
		}

		if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY))
		{
			if (analyzer_wrapper::check(base, end, ref_map_it->first))
			{
				continue;
			}

			char symbol[256] = { 0, };
			unsigned long long disp = 0;
			GetSymbol(ref_map_it->first, symbol, &disp);

			char str[1024] = { 0, };
			unsigned long long address = ref_map_it->second;
			Disasm(&address, str, false);

			char comment_str[1024];
			StringCbCopyA(comment_str, strlen(str), str);

			if (disp)
			{
				dprintf("%s	; %s+0x%x\n", comment_str, symbol, disp);
			}
			else
			{
				dprintf("%s	; %s\n", comment_str, symbol);
			}
		}
	}
}