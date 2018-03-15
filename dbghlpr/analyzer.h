#ifndef __DEFINE_ANALYZER__

#include <Windows.h>
#include <memory>
#include <list>
#include <map>
#include <set>

#include <interface.h>
#include <capstone.h>

class analyzer
{
public:
	//
	// type
	//
	typedef bool(*analyzer_callback_type)(std::shared_ptr<engine::linker>, analyzer *, unsigned char *, unsigned long long, void *context);

	typedef struct __tag_operand_information__
	{
		long operand_type;
		long long value;
	}operand;

	typedef struct __tag_address_information_detail__
	{
		char comment[200];

		bool is_jmp_code;
		unsigned long instruction_id;
		unsigned char operand_count;
		operand operands[8];
	}detail;
	
	typedef struct __tag_block__
	{
		char tag[100];

		std::map<unsigned long long, detail *> address_map; // address, data info
	}block;

private:
	unsigned long long base_address_;
	unsigned long long end_address_;

	std::map<unsigned long long, block> block_map_; // entry point of code block, code block
	analyzer_callback_type cb_;
	void *cb_context_;

private:
	unsigned long long get_jmp_imm(cs_insn *insn);

	void set_entry_point(std::shared_ptr<engine::linker> engine, unsigned long long address, unsigned char *memory_dump, std::set<unsigned long long> &visited);

	detail *create_address();

public:
	analyzer(unsigned long long base, unsigned long long size);
	analyzer(unsigned long long base, unsigned long long size, analyzer_callback_type cb, void *cb_context);

	unsigned char *alloc(std::shared_ptr<engine::linker> engine);
	void free(unsigned char *memory_dump);
	static void free(analyzer::block *b);
	bool check(unsigned long long address);

	void analyze(std::shared_ptr<engine::linker> engine, unsigned char *memory_dump, std::set<unsigned long long> &entry_point_set);
	void trace(std::shared_ptr<engine::linker> engine, unsigned long long address, unsigned char *memory_dump, std::set<unsigned long long> &visited, block &b);

	unsigned long long get_base_address();
	unsigned long long get_end_address();

	std::map<unsigned long long, analyzer::block> get_block_map();
	void set_imm_multimap(std::multimap<unsigned long long, unsigned long long> &caller_callee_map);
};

#endif // !__DEFINE_ANALYZER__
