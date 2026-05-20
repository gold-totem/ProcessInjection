#include <iostream>
#include <Windows.h>

bool injectDLL(HANDLE hProc, std::wstring_view dllName) {
	auto sizeOfPath{ (dllName.size() + 1) * sizeof(wchar_t) };
	BYTE* baseAddress{ reinterpret_cast<BYTE*>(
		VirtualAllocEx(hProc, NULL, sizeOfPath, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	) };

	if (!baseAddress) {
		std::cerr << "VirtualAllocEx failed: " << GetLastError() << '\n';
		return false;
	}

	
	SIZE_T numBytesWritten{ 0 };
	if (!WriteProcessMemory(hProc, baseAddress, dllName.data(), sizeOfPath, &numBytesWritten)) {
		std::cerr << "WriteProcessMemory failed: " << GetLastError() << '\n';
		VirtualFree(baseAddress, 0, MEM_RELEASE);
		return false;
	}

	if (numBytesWritten < sizeOfPath) {
		std::cerr << "Error: Partial write\n";
		VirtualFree(baseAddress, 0, MEM_RELEASE);
		return false;
	}

	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(LoadLibraryW), baseAddress, 0, NULL);
	if (!hThread) {
		std::cerr << "CreateRemoteThread failed: " << GetLastError() << '\n';
		VirtualFree(baseAddress, 0, MEM_RELEASE);
		return false;
	}
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	VirtualFree(baseAddress, 0, MEM_RELEASE);
	return true;
}
int wmain(int argc, wchar_t* argv[]) {

	if (argc != 2) {
		std::wcerr << L"Usage:\n\t" << argv[0] << L" <dllPath>\n";
		return EXIT_FAILURE;
	}
	STARTUPINFOW si = {};
	si.cb = sizeof(si);
	PROCESS_INFORMATION victimProcInfo{ 0 };
	if (!CreateProcessW(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &victimProcInfo)) {
		std::cerr << "Victim process creation failed: " << GetLastError() << '\n';
		return EXIT_FAILURE;
	}

	injectDLL(victimProcInfo.hProcess, argv[1]);
	CloseHandle(victimProcInfo.hThread);
	CloseHandle(victimProcInfo.hProcess);
}