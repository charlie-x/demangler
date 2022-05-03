// demangler.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <Dbghelp.h>

#pragma comment(lib,"dbghelp.lib")

#include <iostream>
#include <string>
#include <vector>

extern "C" PSTR __cdecl __unDNameEx(
	PSTR output_buffer,
	PCSTR mangled_name,
	DWORD cb,
	void* (__cdecl* memory_et)(DWORD),
	void(__cdecl* memory_free)(void*),
	PSTR(__cdecl* unk_GetParameter)(long i),
	DWORD un_flags
);

static const DWORD un_dwFlags = UNDNAME_COMPLETE;

static void* __cdecl _dAlloc(ULONG cb)
{
	return new (std::nothrow) char[cb];
}

static void __cdecl _dFree(void* p)
{
	if (p) {
	delete[] p;
	}
}

static PSTR __cdecl _dGetParameter(long ignore)
{
	static char none[] = "";
	return none;
}


bool GetDLLFileExports(const char *szFileName, std::vector<std::string>&pszFunctions)
{
	HANDLE hFile;
	HANDLE hFileMapping;
	LPVOID lpFileBase;
	PIMAGE_DOS_HEADER pImg_DOS_Header;
	PIMAGE_NT_HEADERS pImg_NT_Header;
	PIMAGE_EXPORT_DIRECTORY pImg_Export_Dir;

	hFile = CreateFileA(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if (hFile == INVALID_HANDLE_VALUE) {
		return false;
	}

	hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

	if (hFileMapping == 0) {
		CloseHandle(hFile);
		return false;
	}

	lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);

	if (lpFileBase == 0) {
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return false;
	}

	pImg_DOS_Header = (PIMAGE_DOS_HEADER)lpFileBase;

	pImg_NT_Header = (PIMAGE_NT_HEADERS)((LONG)pImg_DOS_Header + (LONG)pImg_DOS_Header->e_lfanew);


	if (IsBadReadPtr(pImg_NT_Header, sizeof(IMAGE_NT_HEADERS)) || pImg_NT_Header->Signature != IMAGE_NT_SIGNATURE) {
		UnmapViewOfFile(lpFileBase);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return false;
	}

	pImg_Export_Dir = (PIMAGE_EXPORT_DIRECTORY)pImg_NT_Header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	if (!pImg_Export_Dir) {
		UnmapViewOfFile(lpFileBase);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return false;
	}

	pImg_Export_Dir = (PIMAGE_EXPORT_DIRECTORY)ImageRvaToVa(pImg_NT_Header, pImg_DOS_Header, (DWORD)pImg_Export_Dir, 0);

	DWORD **ppdwNames = (DWORD **)pImg_Export_Dir->AddressOfNames;

	ppdwNames = (PDWORD*)ImageRvaToVa(pImg_NT_Header, pImg_DOS_Header, (DWORD)ppdwNames, 0);

	if (!ppdwNames) {
		UnmapViewOfFile(lpFileBase);
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return false;
	}

	unsigned int nNoOfExports = pImg_Export_Dir->NumberOfNames;

	for (unsigned i = 0; i < nNoOfExports; i++) {
		char *szFunc = (PSTR)ImageRvaToVa(pImg_NT_Header, pImg_DOS_Header, (DWORD)* ppdwNames, 0);

		pszFunctions.push_back(szFunc);

		ppdwNames++;
	}

	UnmapViewOfFile(lpFileBase);

	CloseHandle(hFileMapping);
	CloseHandle(hFile);

	return true;
};


int main(int argc,char*argv[])
{
	if (argc < 2) {
		fprintf(stderr,"need a dll to demangle as first parameter\n");
		exit(-1);
	}

	std::vector<std::string>pszFunctions;

	if (GetDLLFileExports(argv[1], pszFunctions)) {

		for (auto s : pszFunctions) {

			// undecorate them
			char* pUndecorated = __unDNameEx(
				NULL, s.data(), 0
				, _dAlloc, _dFree, _dGetParameter, un_dwFlags);

			printf("%s;\r", pUndecorated);

			delete[] pUndecorated;
		}
	}
}
