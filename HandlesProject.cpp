// HandlesProject.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "windows.h"
#include <Psapi.h>
#include <string>
#include <tchar.h>
#include <fstream>

using namespace std;

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define NT_SUCCESS(x) ((x) >= 0)


typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* _NtQueryObject)(
    HANDLE ObjectHandle,
    ULONG ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_NAME_INFORMATION
{
    UNICODE_STRING Name;

} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef struct _PUBLIC_OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG Reserved[10];    // reserved for internal use
} PUBLIC_OBJECT_BASIC_INFORMATION, * PPUBLIC_OBJECT_BASIC_INFORMATION;

typedef struct _SYSTEM_HANDLE
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

int main(int argc, TCHAR *argv[])
{
    //variables to find relevant processes
    DWORD procs[1024], procNum, totSize;
    DWORD foundProcs[1024], foundProcNum;
    TCHAR* pName;
    TCHAR foundProcNames[1024][MAX_PATH];
    DWORD pid;
    boolean foundPidFlag;
    unsigned int i, j;

    //variables to find handles
    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    _NtQueryObject NtQueryObject = (_NtQueryObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryObject");
    _NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtDuplicateObject");
    ULONG initSize = 1024;
    ULONG actSize = 0;
    PSYSTEM_HANDLE_INFORMATION handleInfo = NULL;

    handleInfo = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc(NULL,
        (SIZE_T)initSize,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);


    if (argc != 2) {
        cout << "Usage: .\\HandlesProject.exe <process id or name>";
        return 1;
    }

    cout << "the required process has name/id: ";
    _tprintf(TEXT("%s"), argv[1]);
    cout << '\n';

    pid = atoi(argv[1]);
    pName = argv[1];

    if (!EnumProcesses(procs, sizeof(procs), &totSize)) {
        return 1;
    }

    procNum = totSize / sizeof(DWORD);

    foundProcNum = 0;
    foundPidFlag = FALSE;

    //find processes with given process name/id
    for (i = 0; i < procNum; i++) {
        if (procs[i] != 0) {
            if (procs[i] == pid) {
                foundProcs[foundProcNum] = procs[i];
                foundProcNum++;
                foundPidFlag = TRUE;
            }
            TCHAR currProcName[MAX_PATH] = TEXT("<unknown>");
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, procs[i]);
            if (hProc != NULL) {
                HMODULE hMod;
                DWORD nameSize;
                if (EnumProcessModulesEx(hProc, &hMod, sizeof(hMod), &nameSize, LIST_MODULES_ALL)) {
                    GetModuleBaseName(hProc, hMod, currProcName, sizeof(currProcName) / sizeof(TCHAR));
                    if (_tcscmp(pName, currProcName) == 0) {
                        if (!foundPidFlag) {
                            foundProcs[foundProcNum] = procs[i];
                            strcpy_s(foundProcNames[foundProcNum], currProcName);
                            foundProcNum++;
                        }
                        else {//pid and name are the same
                            strcpy_s(foundProcNames[foundProcNum - 1], currProcName);
                        }
                    }
                    else if (foundPidFlag) {
                        strcpy_s(foundProcNames[foundProcNum - 1], currProcName);
                    }
                }
            }
            else if(foundPidFlag){
                strcpy_s(foundProcNames[foundProcNum - 1], currProcName);
            }
            CloseHandle(hProc);
            foundPidFlag = FALSE;
        }
    }
    printf("found %d procs with this name/id.\n", foundProcNum);
    //At this point, we have all the procs that have the given name or id as the user input.

    //Get list of handles
    while (NtQuerySystemInformation(SystemHandleInformation, handleInfo, initSize, &actSize) == STATUS_INFO_LENGTH_MISMATCH)
    {
        // Free First the Memory
        VirtualFree(handleInfo,
            (SIZE_T)initSize,
            MEM_DECOMMIT);

        // Update the Guess Size
        initSize = actSize;

        // Allocate Memory Again - Resize
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)VirtualAlloc(NULL,
            (SIZE_T)initSize,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE);
    }

    //get each handles information for each process
    for (i = 0; i < foundProcNum; i++) {
        printf("Process name: %s, Pid: %d\n", foundProcNames[i], foundProcs[i]);
        HANDLE pHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, foundProcs[i]);
        if (pHandle == INVALID_HANDLE_VALUE || pHandle == NULL) {
            cout << "Could not open process.\n\n";
            continue;
        }

        cout << "\nHandles:\n";
        for (j = 0; j < handleInfo->HandleCount; j++) {
            SYSTEM_HANDLE handle = handleInfo->Handles[j];
            HANDLE dupHandle = NULL;
            PVOID objectNameInfo, objectBasicInfo;
            UNICODE_STRING objectName;
            PUBLIC_OBJECT_BASIC_INFORMATION objectBasics;
            //PPUBLIC_OBJECT_BASIC_INFORMATION objectBasicInfo;
            ULONG returnLength;
            NTSTATUS STATUS;

            if (handle.ProcessId != foundProcs[i])
                continue;

            if (GetProcessId(GetCurrentProcess()) != handle.ProcessId)
            {
                STATUS = DuplicateHandle(pHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, STANDARD_RIGHTS_ALL, FALSE, DUPLICATE_SAME_ACCESS);
            }
            else {
                STATUS = DuplicateHandle(GetCurrentProcess(), (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, STANDARD_RIGHTS_ALL, FALSE, DUPLICATE_SAME_ACCESS);
                if (STATUS == 0x1)
                {
                    Sleep(10);
                }
            }

            if (STATUS != STATUS_INVALID_HANDLE) {
                if (dupHandle != INVALID_HANDLE_VALUE && dupHandle != NULL) {
                    ULONG gSize = 1;
                    //objectNameInfo = (PUNICODE_STRING)VirtualAlloc(NULL, (SIZE_T)gSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                    objectNameInfo = (POBJECT_NAME_INFORMATION)VirtualAlloc(NULL, (SIZE_T)gSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                    boolean tooLong = FALSE;
                    while (NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, gSize, &returnLength) == STATUS_INFO_LENGTH_MISMATCH && !tooLong) {
                        VirtualFree(objectNameInfo, gSize, MEM_DECOMMIT);
                        gSize++;
                        if (gSize > 0x1000) {
                            tooLong = TRUE;
                            gSize--;
                            //continue;
                        }
                        objectNameInfo = (PUNICODE_STRING)VirtualAlloc(NULL, (SIZE_T)gSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                    }
                    objectName = ((POBJECT_NAME_INFORMATION)objectNameInfo)->Name;

                    //find object pointer and handle count
                    ULONG basicSize = 0;
                    objectBasicInfo = (PPUBLIC_OBJECT_BASIC_INFORMATION)VirtualAlloc(NULL, (SIZE_T)basicSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                    while (NtQueryObject(dupHandle, ObjectBasicInformation, objectBasicInfo, basicSize, &returnLength) == STATUS_INFO_LENGTH_MISMATCH) {
                        VirtualFree(objectBasicInfo, basicSize, MEM_DECOMMIT);
                        basicSize++;
                        objectBasicInfo = (PPUBLIC_OBJECT_BASIC_INFORMATION)VirtualAlloc(NULL, (SIZE_T)basicSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                    }
                    objectBasics = *(PPUBLIC_OBJECT_BASIC_INFORMATION)objectBasicInfo;

                    //print info including name

                    if (objectName.Length)
                    {
                        /* The object has a name. */
                        printf(
                            "handle: [%#x], name: %.*S, pointers: %lu, handles: %lu\n",
                            handle.Handle,
                            objectName.Length / 2,
                            objectName.Buffer,
                            objectBasics.PointerCount,
                            objectBasics.HandleCount - 1 //the duplication of the handle raised the actual handle count by 1
                        );
                    }
                    else
                    {
                        //print info not including name
                        printf(
                            "handle: [%#x], name (unnamed), pointers: %lu, handles: %lu\n",
                            handle.Handle,
                            objectBasics.PointerCount,
                            objectBasics.HandleCount
                        );
                    }

                    VirtualFree(objectBasicInfo, gSize, MEM_DECOMMIT);
                    VirtualFree(objectBasicInfo, basicSize, MEM_DECOMMIT);
                    CloseHandle(dupHandle);
                }
            }
        }
        CloseHandle(pHandle);
    }

    return 0;
}


