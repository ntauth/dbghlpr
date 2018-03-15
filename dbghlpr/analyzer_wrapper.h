#ifndef __DEFINE_ANALYZER_WRAPPER__
#define __DEFINE_ANALYZER_WRAPPER__

#include <analyzer.h>
#include <engine_linker.h>

class analyzer_wrapper
{
public:
	static bool calc_exe_segment(unsigned long long ptr, unsigned long long *alloc_base, unsigned long long *alloc_end);
	static bool check(unsigned long long base, unsigned long long end, unsigned long long address);
	static bool find_entry_callback(std::shared_ptr<engine::linker> engine, analyzer *current_analyzer_ptr, unsigned char *memory_dump, unsigned long long entry_point, void *context);
	static unsigned long long find_entry(unsigned long long ptr, unsigned long long base, unsigned long long size);
	static bool find_all_entry(unsigned long long base, unsigned long long size, std::set<unsigned long long> &entry_set);
	static bool find_caller(unsigned long long ptr, unsigned long long base, unsigned long long size, std::list<unsigned long long> &caller_list);
	static bool find_reference_value(unsigned long long base, unsigned long long size, std::multimap<unsigned long long, unsigned long long> &ref_map);
};

#endif