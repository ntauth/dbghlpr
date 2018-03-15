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

//
// pattern
//
void print_pattern_memory(unsigned long long base_virtual_address, unsigned char *base_buffer, unsigned char *find_buffer)
{
	unsigned long long offset = find_buffer - base_buffer;
	unsigned long long find_virtual_address = base_virtual_address + offset;

	unsigned int i = 0, j = 0;
	for (i; i < 17; ++i)
	{
		if (i == 0)
		{
			dprintf("%08x  ", find_virtual_address);
			dprintf("%02x ", find_buffer[i]);
		}
		else if (i % 16 == 0)
		{
			/*-- ascii --*/
			for (j; j < i; ++j)
			{
				if (helper::is_ascii(find_buffer, 512))
					dprintf("%c", find_buffer[j]);
				else
					dprintf(".");
			}

			/*-- next line --*/
			dprintf("\n");

			// find_virtual_address += 16;
			//dprintf("%08x  ", find_virtual_address);
		}
		else
			dprintf("%02x ", find_buffer[i]);
	}
}

EXT_CLASS_COMMAND(WindbgEngine, pattern, "", "{b;ed,o;p;;}" "{l;ed,o;l;;}" "{pattern;x,o;pattern;;}") // bc = break code
{
	if (!g_Ext->HasArg("b"))
		return;
	if (!g_Ext->HasArg("l"))
		return;
	if (!g_Ext->HasArg("pattern"))
		return;

	unsigned long long base = GetArgU64("b", FALSE);
	unsigned long long size = GetArgU64("l", FALSE);
	unsigned long long end = base + size;
	PCSTR pt = GetArgStr("pattern", true);

#ifdef _WIN64
	g_Ext->Dml("<b><col fg=\"changed\">base=%x, end=%x, pattern=%s</col></b>", base, base + size, pt);
#else
	g_Ext->Dml("<b><col fg=\"changed\"> base=%x, end=%x, pattern=%s\n</col></b>", (unsigned long)base, (unsigned long)end, pt);
#endif

	size_t pattern_size = strlen(pt);
	unsigned char *pattern = (unsigned char *)malloc(pattern_size);
	if (!pattern)
	{
		return;
	}
	std::shared_ptr<void> pattern_closer(pattern, free);
	memset(pattern, 0, pattern_size);

	unsigned long long j = 0;
	for (unsigned long long i = 0; i < pattern_size; ++i)
	{
		if (pt[i] == '?')
		{
			pattern[j++] = '?';
		}
		else if (pt[i] != ' ')
		{
			char *end = nullptr;
			pattern[j++] = (unsigned char)strtol(&pt[i], &end, 16);
			i = end - pt;
		}
	}

	//
	//
	//
	engine_linker linker;
	do
	{
		MEMORY_BASIC_INFORMATION64 mbi;
		if (linker.virtual_query(base, &mbi))
		{
			base += mbi.RegionSize;

			unsigned char *buffer = (unsigned char *)malloc((size_t)mbi.RegionSize);
			if (!buffer)
			{
				continue;
			}
			std::shared_ptr<void> buffer_closer(buffer, free);
			memset(buffer, 0, (size_t)mbi.RegionSize);

#ifdef _WIN64
			unsigned long read = linker.read_virtual_memory(mbi.BaseAddress, buffer, mbi.RegionSize);
#else
			unsigned long read = linker.read_virtual_memory(mbi.BaseAddress, buffer, (size_t)mbi.RegionSize);
#endif

			unsigned char *f = nullptr;
			unsigned long long o = 0;
			do
			{
				f = helper::find(&buffer[o], read - o, pattern, j);
				if (f)
				{
					unsigned long long offset = f - buffer;
					print_pattern_memory(mbi.BaseAddress, buffer, f);

					o = offset + j;
				}
			} while (f);
		}
		else
		{
			break;
		}
#ifdef _WIN64
	} while (base < end);
#else
} while ((unsigned long)base < (unsigned long)end);
#endif
dprintf("\n");
}

//
// virtual alloc memory checker
//
#include <DbgHelp.h>

EXT_CLASS_COMMAND(WindbgEngine, chkmem, "", "{exe;b,o;exe;;}") // pea = pe analyzer
{
	engine_linker linker;
	unsigned long long base = linker.get_next_virtual_address(0);
	unsigned long long end = 0x7fffffff;

	dprintf("base=>%I64x\n", base);
	dprintf("end=>%I64x\n", end);

	do
	{
		MEMORY_BASIC_INFORMATION64 mbi = { 0, };
		if (linker.virtual_query(base, &mbi))
		{
			if (g_Ext->HasArg("exe"))
			{
				if (mbi.State == MEM_COMMIT && (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED) &&
					(mbi.Protect == PAGE_EXECUTE || mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_WRITECOPY))
				{
					if (mbi.Type == MEM_PRIVATE || mbi.Type == MEM_MAPPED)
					{
						unsigned long long base = mbi.BaseAddress;
						unsigned long long end = mbi.BaseAddress + mbi.RegionSize;

						g_Ext->Dml("<b><col fg=\"emphfg\"> [ unk mem ]	</col></b>");
						dprintf("%08x - %08x	", (unsigned long)base, (unsigned long)end);
						MEMORY_BASIC_INFORMATION64 mbi2 = { 0, };
						IMAGE_DOS_HEADER dos;
						IMAGE_NT_HEADERS nt;

						if (linker.virtual_query(mbi.AllocationBase, &mbi2))
						{
							unsigned long r = linker.read_virtual_memory(mbi.AllocationBase, (unsigned char *)&dos, sizeof(dos));
							if (r == sizeof(dos) && dos.e_magic == IMAGE_DOS_SIGNATURE)
							{
								r = linker.read_virtual_memory(mbi.AllocationBase + dos.e_lfanew, (unsigned char *)&nt, sizeof(nt));

								if (r == sizeof(nt) && nt.Signature == IMAGE_NT_SIGNATURE)
								{
									g_Ext->Dml("<b><col fg=\"emphfg\">[ PE FILE ] </col></b>");
									g_Ext->Dml("<b><col fg=\"wfg\">[ %I64x ] </col></b>", mbi.AllocationBase);
								}
							}

							unsigned long long offset = mbi2.BaseAddress - mbi2.AllocationBase;
							if (offset == 0x1000)
							{
								g_Ext->Dml("<b><col fg=\"changed\">[ DANGER ]</col></b>");
							}
						}
						dprintf("\n");
					}
					else
					{

						//
						// ldr 링크 제거
						// 
						try
						{
							IMAGEHLP_MODULEW64 im;
							g_Ext->GetModuleImagehlpInfo(mbi.AllocationBase, &im);
						}
						catch (...)
						{
							unsigned long long base = mbi.BaseAddress;
							unsigned long long end = mbi.BaseAddress + mbi.RegionSize;

							g_Ext->Dml("<b><col fg=\"changed\"> [ unk img ]	</col></b>");
							dprintf("%08x - %08x	", (unsigned long)base, (unsigned long)end);
							g_Ext->Dml("<b><col fg=\"changed\">[ DANGER ]\n</col></b>");
						}
					}
				}
			}
			else
			{
				unsigned long long base = mbi.BaseAddress;
				unsigned long long end = mbi.BaseAddress + mbi.RegionSize;

				dprintf(" %08x - %08x	\n", (unsigned long)base, (unsigned long)end);
			}

			//dprintf("%08x %08x\n", (unsigned long)mbi.BaseAddress, (unsigned long)mbi.RegionSize);
			base += mbi.RegionSize;
		}
		else
		{
			unsigned long long next = linker.get_next_virtual_address(base);
			if (next < base)
			{
				break;
			}
			else
			{
				base = next;
				continue;
			}
		}
	} while (base < end);
}
