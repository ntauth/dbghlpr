#ifndef __DEFINE_PEGASUS_EXTERNAL_INTERFACE__
#define __DEFINE_PEGASUS_EXTERNAL_INTERFACE__
///
//
///
#include "register_idx.h"
///
// interface
///
#define get_bit_flag(t, i)		(t >> i) & 1
#define GetFlagBit(eflags, i)	get_bit_flag(eflags, i)

#define CF_INDEX	0
#define PF_INDEX	2
#define AF_INDEX	4
#define ZF_INDEX	6
#define SF_INDEX	7
#define TF_INDEX	8
#define IF_INDEX	9
#define DF_INDEX	10
#define OF_INDEX	11
#define IOPL_INDEX_1	12
#define IOPL_INDEX_2	13
#define NT_INDEX		14
#define RF_INDEX		16
#define VM_INDEX		17
#define AC_INDEX		18
#define VIF_INDEX		19
#define VIP_INDEX		20
#define ID_INDEX		21

#pragma pack(push, 1)
typedef struct _SegmentDescriptor {
	union {
		struct {
			unsigned short limit_low;
			unsigned short base_low;
			unsigned char base_mid;
			unsigned char type : 4;
			unsigned char system : 1;
			unsigned char dpl : 2;
			unsigned char present : 1;
			unsigned char limit_hi : 4;
			unsigned char available : 1;
			unsigned char is_64_code : 1;
			unsigned char db : 1;
			unsigned char granularity : 1;
			unsigned char base_hi;
		};
		unsigned long long descriptor; // resize 8byte.
	};
}SegmentDescriptor, *PSegmentDescriptor;
#pragma pack(pop)

namespace engine
{
	class linker
	{
	public:
		virtual ~linker() {}
		virtual bool __stdcall open(char *path) = 0;
		virtual unsigned long long __stdcall get_next_virtual_address(unsigned long long) = 0;
		virtual bool __stdcall virtual_query(unsigned long long virtual_address, void *out_memory_info) = 0;
		virtual bool __stdcall query_virtual(unsigned long long virtual_address, void *out_memory_info) = 0;
		virtual unsigned long __stdcall read_virtual_memory(unsigned long long virtual_address, unsigned char *out_memory, unsigned long read_size) = 0;
		virtual bool __stdcall get_thread_context(cpu_context_type *context) = 0;

		virtual void * __stdcall disasm(unsigned long long address, const unsigned char *table) = 0;
		virtual void * __stdcall get_disasm_handle() = 0;

		virtual unsigned long long __stdcall get_peb_address() = 0;
		virtual unsigned long long __stdcall get_teb_address() = 0;
	};

	template <typename T1, class T2> bool __stdcall create(std::shared_ptr<T2> &u);
}

///
///
///
template <typename T1, class T2>
bool __stdcall engine::create(std::shared_ptr<T2> &u)
{
	try
	{
		void *o = nullptr;
		T1 *t = new T1;

		o = t;
		u.reset(static_cast<T2 *>(o));
	}
	catch (...)
	{
		return false;
	}

	return true;
}

#endif
