#include <windows.h>
#include <stdio.h>
#include <Psapi.h>

#define ok(msg, ...) printf("\033[0;32m[+]\033[0;37m " msg "\n", ##__VA_ARGS__)
#define info(msg, ...) printf("\033[0;34m[*]\033[0;37m " msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("\033[0;31m[-]\033[0;37m " msg "\n", ##__VA_ARGS__)

BOOL unhook() {
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

    for (DWORD i = 0; i <imageExportDirectory->NumberOfNames; i++) {
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

int main() {
	// unhook api hooks
	BOOL bIsUnhooked = unhook();
	if (bIsUnhooked != TRUE) {
		warn("dont know how this shit broke");
	}

    return EXIT_SUCCESS;
}