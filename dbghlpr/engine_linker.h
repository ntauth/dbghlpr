#ifndef __DEFINE_DBGSUIT_DUMP_ENGINE__
#define __DEFINE_DBGSUIT_DUMP_ENGINE__

class engine_linker : public engine::linker
{
private:
	void *debug_client_;
	void *debug_data_space_;
	void *debug_data_space_2_;
	void *debug_advanced_;
	void *debug_system_objects_;
	void *debug_control_;
	void *debug_register_;

	csh cs_handle_;
	cs_insn *insn_;

public:
	bool __stdcall open(char *path);
	bool __stdcall virtual_query(unsigned long long virtual_address, void *out_memory_info);
	bool __stdcall query_virtual(unsigned long long virtual_address, void *out_memory_info);

	unsigned long long __stdcall get_next_virtual_address(unsigned long long);
	unsigned long __stdcall read_virtual_memory(unsigned long long virtual_address, unsigned char *out_memory, unsigned long read_size);
	bool __stdcall get_thread_context(cpu_context_type *context);

	void * __stdcall disasm(unsigned long long address, const unsigned char *table);
	void * __stdcall get_disasm_handle();

	unsigned long long __stdcall get_peb_address();
	unsigned long long __stdcall get_teb_address();

public:
	engine_linker();
	~engine_linker();
};

#endif