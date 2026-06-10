#include <iostream>
#include <filesystem>
#include <fstream>
#include <Windows.h>
#include "PELoader.h"

int main(int argc, char* argv[]) {

	if (argc != 2) {
		std::wcerr << L"Usage:\n\t" << argv[0] << L" <pe_Path>\n";
		return EXIT_FAILURE;
	}

	std::ifstream file(argv[1], std::ios::binary);

	if (!file) {
		std::cerr << "Failed to open file\n";
		return EXIT_FAILURE;
	}

	size_t fileSize = std::filesystem::file_size(argv[1]);
	std::vector<unsigned char> bytes(fileSize);

	file.read(reinterpret_cast<char*>(bytes.data()), fileSize);

	if (!file) {
		std::cerr << "Failed to read file\n";
		return EXIT_FAILURE;
	}


	STARTUPINFOW si = {};
	si.cb = sizeof(si);
	PROCESS_INFORMATION victimProcInfo{ 0 };

	if (!CreateProcessW(L"C:\\Windows\\System32\\SndVol.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &victimProcInfo)) {
		std::cerr << "Victim process creation failed: " << GetLastError() << '\n';
		return EXIT_FAILURE;
	}
	CloseHandle(victimProcInfo.hProcess);
	CloseHandle(victimProcInfo.hThread);
	HANDLE hProcess{ OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_TERMINATE , false, victimProcInfo.dwProcessId) };

	if (!hProcess) {
		std::cerr << "OpenProcessfailed: " << GetLastError() << '\n';
		return EXIT_FAILURE;
	}

	PELdr::PELoader peLoader;


	if (!peLoader.loadPE(hProcess, bytes.data())) {
		std::cerr << "Failed loading the PE\n";
		return EXIT_FAILURE;
	}

	if (!peLoader.callExport("printMsg")) {
		std::cerr << "Failed executing the PE\n";
		return EXIT_FAILURE;
	}

}