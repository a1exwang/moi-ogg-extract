//===============================================================================================//
// This is a stub for the actuall functionality of the DLL.
//===============================================================================================//
#include "ReflectiveLoader.h"
#include <stdio.h>

// Note: REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR and REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN are
// defined in the project properties (Properties->C++->Preprocessor) so as we can specify our own 
// DllMain and use the LoadRemoteLibraryR() API to inject this DLL.

void *FindMemory(DWORD StartAdd, DWORD EndAdd, void *Data, DWORD DataSize, void **endAddr) {
	MEMORY_BASIC_INFORMATION minfo;

	int first = 1;
	while (StartAdd < EndAdd)
	{
		VirtualQuery((void*)StartAdd, &minfo, sizeof(MEMORY_BASIC_INFORMATION));
		if (!(minfo.AllocationProtect & PAGE_GUARD) /*&& (minfo.AllocationProtect & PAGE_READONLY ||
													minfo.AllocationProtect & PAGE_READWRITE)*/) {

			if (!(minfo.Protect & PAGE_GUARD) /*&& (minfo.Protect & PAGE_READONLY ||
											  minfo.Protect & PAGE_READWRITE)*/) {

				if (minfo.State == MEM_COMMIT) {
					char *s, *e;
					s = (DWORD)StartAdd > (DWORD) minfo.BaseAddress ? (PVOID)StartAdd : minfo.BaseAddress;
					e = (char *)minfo.BaseAddress + minfo.RegionSize;
					for (; s < e && s + DataSize <= e; s++) {
						if (memcmp(s, Data, DataSize) == 0) {
							*endAddr = e;
							return s;
						}
					}
					first = 0;
				}
			}
		}
		StartAdd = (DWORD)minfo.BaseAddress + minfo.RegionSize;
	}
	return 0;
}

#include <stdio.h>
// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;
//===============================================================================================//
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
	int bufferSize = 0x40000;
	char *buffer = (char*)malloc(bufferSize);
	memset(buffer, 0, bufferSize);

	char matchStr[] = { 'O', 'g', 'g', 'S' };
	int matchStrLength = sizeof(matchStr);

	char matchStr1[] = { 'O', 'g', 'g', 'S', 0, 4 };
	int matchStrLength1 = sizeof(matchStr1);

    BOOL bReturnValue = TRUE;
	switch( dwReason ) 
    { 
		case DLL_QUERY_HMODULE:
			if( lpReserved != NULL )
				*(HMODULE *)lpReserved = hAppInstance;
			break;
		case DLL_PROCESS_ATTACH:
			hAppInstance = hinstDLL;

			void *s = 0, *endAddr;
			int offset = 0;
			do {
				s = FindMemory((DWORD)s, 0x8000000, matchStr, matchStrLength, &endAddr);
				if (s) {
					offset += sprintf_s(buffer + offset, bufferSize - offset, "ogg start - start: 0x%08x, end: 0x%08x\n", (DWORD)s, (DWORD)endAddr);
					s = (char*)s + matchStrLength;
				}
			} while (s);

			s = 0;
			do {
				s = FindMemory((DWORD)s, 0x8000000, matchStr1, matchStrLength1, &endAddr);
				if (s) {
					offset += sprintf_s(buffer + offset, bufferSize - offset, "ogg end - start: 0x%08x, end: 0x%08x\n", (DWORD)s, (DWORD)endAddr);
					s = (char*)s + matchStrLength1;
				}
			} while (s);
			//MessageBoxA(NULL, buffer, "reflective", MB_OK);
			FILE *file = fopen("C:\\Users\\Alex Wang\\Desktop\\ogg.txt", "w");
			fwrite(buffer, 1, offset, file);
			fclose(file);
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	free(buffer);
	return bReturnValue;
}