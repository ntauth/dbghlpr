#ifndef __DEFINE_PEGASUS_WINDBG_ENGINE
#define __DEFINE_PEGASUS_WINDBG_ENGINE

class WindbgEngine : public ExtExtension
{
public:
	WindbgEngine();
	virtual HRESULT Initialize(void);

	//
	// analyzer
	//
	void add();
	void segments();
	void select_segment();
	void database();
	void ftrace();
	void xref();
	void iat();

	void merge();
	void divide();
	void tag();
	void comment();

	void danger();

	//
	// debugging
	//
	void suspend();
	void resume();
	void bc();

	//
	// memory
	//
	void pattern();
	void chkmem();

	//
	// emulator
	//
	void open();
	void alloc();
	void write();
	void read();

	void query();
	void trace();
	void context();

	//
	// segments
	//
	void create();
	void head();
	void entrys();
	void uf();
	void ref();

	//
	// simple analyzer
	//
	void fe();
	void fae();
	void caller();
	void refstr();
	void refexe();
	void calc();
};

#endif
