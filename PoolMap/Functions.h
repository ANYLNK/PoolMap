#pragma once

#include "PoolStruct.h"

PVOID ShellcodeInject(HANDLE hProcess, unsigned char* shellcode, SIZE_T shellcodesize);
//BOOL AdjustToken();
HANDLE HijackThreadPoolRelatedHandle(std::wstring ObjectType, HANDLE hProcess, DWORD dwDesiredAccess);
BOOL TpWaitInsert(PVOID shellcodeaddress, HANDLE hProcess, HANDLE hIoCompletion);
BOOL TpIoInsert(PVOID shellcodeaddress, HANDLE hProcess, HANDLE hIoCompletion);
BOOL TpAlpcInsert(PVOID shellcodeaddress, HANDLE hProcess, HANDLE hIoCompletion);
BOOL TpJobInsert(PVOID shellcodeaddress, HANDLE hProcess, HANDLE hIoCompletion);
BOOL TpDirectInsert(PVOID shellcodeaddress, HANDLE hProcess, HANDLE hIoCompletion);
BOOL TpTimerInsert(PVOID shellcodeaddress, HANDLE hProcess, HANDLE hWorkerFactory, HANDLE hIRTimer);
BOOL StartRoutineOverwrite(PVOID shellcodeaddress, HANDLE hProcess, HANDLE hWorkerFactory);
BOOL TpWorkInsert(PVOID shellcodeaddress, HANDLE hProcess, HANDLE hWorkerFactory);