//===============================================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are permitted 
// provided that the following conditions are met:
// 
//     * Redistributions of source code must retain the above copyright notice, this list of 
// conditions and the following disclaimer.
// 
//     * Redistributions in binary form must reproduce the above copyright notice, this list of 
// conditions and the following disclaimer in the documentation and/or other materials provided 
// with the distribution.
// 
//     * Neither the name of Harmony Security nor the names of its contributors may be used to
// endorse or promote products derived from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR 
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR 
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR 
// OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
// POSSIBILITY OF SUCH DAMAGE.
//===============================================================================================//
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "LoadLibraryR.h"

#pragma comment(lib,"Advapi32.lib")

#define BREAK_WITH_ERROR( e ) { printf( "[-] %s. Error=%d", e, GetLastError() ); break; }



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
#include "TlHelp32.h"
DWORD GetProcessList(const WCHAR *processname)
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Take a snapshot of all processes in the system.
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcessSnap) return FALSE;

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return -1;
	}

	do
	{
		if (0 == wcscmp(processname, pe32.szExeFile))
		{
			CloseHandle(hProcessSnap);
			return pe32.th32ProcessID;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return -1;
}

// Simple app to inject a reflective DLL into a process vis its process ID.
int main( int argc, char * argv[] )
{
	HANDLE hFile          = NULL;
	HANDLE hModule        = NULL;
	HANDLE hProcess       = NULL;
	HANDLE hToken         = NULL;
	LPVOID lpBuffer       = NULL;
	DWORD dwLength        = 0;
	DWORD dwBytesRead     = 0;
	DWORD dwProcessId     = 0;
	TOKEN_PRIVILEGES priv = {0};

	char buffer[10000];
	memset(buffer, 0, sizeof(buffer));

	char matchStr[] = { 'M', 'Z' };
	int matchStrLength = sizeof(matchStr);

	char matchStr1[] = { 'O', 'g', 'g', 'S', 0, 4 };
	int matchStrLength1 = sizeof(matchStr1);
	/*
	void *s = 0, *endAddr;
	int offset = 0;
	do {
		s = FindMemory((DWORD)s, 0x8000000, matchStr, matchStrLength, &endAddr);
		if (s) {
			offset += sprintf_s(buffer + offset, sizeof(buffer) - offset, "start: 0x%08x, end: 0x%08x\n", (DWORD)s, (DWORD)endAddr);
			s = (char*)s + matchStrLength;
		}
	} while (s);

	s = 0;
	do {
		s = FindMemory((DWORD)s, 0x8000000, matchStr1, matchStrLength1, &endAddr);
		if (s) {
			offset += sprintf_s(buffer + offset, sizeof(buffer) - offset, "ogg end - start: 0x%08x, end: 0x%08x\n", (DWORD)s, (DWORD)endAddr);
			s = (char*)s + matchStrLength1;
		}
	} while (s);
	MessageBoxA(NULL, buffer, "reflective", MB_OK);
	*/
	do
	{
		// Usage: inject.exe [pid] [dll_file]

		//if( argc == 1 )

			dwProcessId = GetCurrentProcessId();
		//else
			//dwProcessId = atoi( argv[1] );
			
		dwProcessId = GetProcessList(L"MOI.exe");

		char *cpDllFile = "C:\\Users\\Alex Wang\\Desktop\\OMG\\Download\\ReflectiveDLLInjection-master\\ReflectiveDLLInjection-master\\Debug\\reflective_dll.dll";

		hFile = CreateFileA( cpDllFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
		if( hFile == INVALID_HANDLE_VALUE )
			BREAK_WITH_ERROR( "Failed to open the DLL file" );

		dwLength = GetFileSize( hFile, NULL );
		if( dwLength == INVALID_FILE_SIZE || dwLength == 0 )
			BREAK_WITH_ERROR( "Failed to get the DLL file size" );

		lpBuffer = HeapAlloc( GetProcessHeap(), 0, dwLength );
		if( !lpBuffer )
			BREAK_WITH_ERROR( "Failed to get the DLL file size" );

		if( ReadFile( hFile, lpBuffer, dwLength, &dwBytesRead, NULL ) == FALSE )
			BREAK_WITH_ERROR( "Failed to alloc a buffer!" );

		if( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken ) )
		{
			priv.PrivilegeCount           = 1;
			priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		
			if( LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid ) )
				AdjustTokenPrivileges( hToken, FALSE, &priv, 0, NULL, NULL );

			CloseHandle( hToken );
		}

		hProcess = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId );
		if( !hProcess )
			BREAK_WITH_ERROR( "Failed to open the target process" );

		hModule = LoadRemoteLibraryR( hProcess, lpBuffer, dwLength, NULL );
		if( !hModule )
			BREAK_WITH_ERROR( "Failed to inject the DLL" );

		printf( "[+] Injected the '%s' DLL into process %d.", cpDllFile, dwProcessId );
		
		WaitForSingleObject( hModule, -1 );

	} while( 0 );

	if( lpBuffer )
		HeapFree( GetProcessHeap(), 0, lpBuffer );

	if( hProcess )
		CloseHandle( hProcess );

	return 0;
}