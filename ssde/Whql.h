/*++

Module Name:

    whql.h

Abstract:

    This file contains the device definitions.

Environment:

    Kernel-mode Driver Framework

--*/

#ifndef _H_WHQLSSDE_H_
#define _H_WHQLSSDE_H_

#define CODEINTEGRITY_POLICY_STR L"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy"
#define CODEINTEGRITY_WHQL_SETTINGS_STR L"WhqlSettings"

typedef struct _WHQLSSDEWORKER
{
    HANDLE WorkerHandle;
    PVOID WorkerObject;
    PKSTART_ROUTINE pFunc;
    HANDLE UnloadEventHandle;
    PKEVENT UnloadEventObject;
    HANDLE CodeIntegrityPolicyKeyChangeEventHandle;
    PKEVENT CodeIntegrityPolicyKeyChangeEventObject;
    HANDLE CodeIntegrityPolicyKey;
    PKEY_VALUE_PARTIAL_INFORMATION CodeIntegrityWhqlSettingsValueInfo;
    ULONG CodeIntegrityWhqlSettingsValueInfoSize;
} WHQLSSDEWORKER, *PWHQLSSDEWORKER;

NTSTATUS
WhqlWorker_Delete(PWHQLSSDEWORKER *);

VOID
WhqlWorker_Work(PWHQLSSDEWORKER *);

NTSTATUS
WhqlWorker_MakeAndInitialize(PWHQLSSDEWORKER *);

NTSTATUS
WhqlInitializeWorker();

VOID
WhqlUninitializeWorker();

#endif