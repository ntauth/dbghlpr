#include <Windows.h>
#include <stdio.h>

void main()
{
	static wchar_t *u_str = L"unicode test string\n";
	static char *a_str = "ascii test string";

	MessageBoxA(nullptr, a_str, "msgboxa", MB_OK);
	MessageBoxW(nullptr, u_str, L"msgboxw", MB_OK);

	for(int i = 0; i<5; ++i)
	{
		printf("step %d\n", i);
		Sleep(1000);
	}
	printf("test end\n");
}