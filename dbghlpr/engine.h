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
	void fe();
	void fae();
	void caller();
	void refstr();
	void refexe();
	void calc();

	void create();

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
};

#endif
