/*++

Module Name:

    licensed.h

Abstract:

    This file contains the device definitions.

Environment:

    Kernel-mode Driver Framework

--*/

#ifndef _H_LICENSEDSSDE_H_
#define _H_LICENSEDSSDE_H_

#define CODEINTEGRITY_PROTECTED_STR L"SYSTEM\\CurrentControlSet\\Control\\CI\\Protected"
#define CODEINTEGRITY_LICENSED_STR L"Licensed"

typedef struct _LICENSEDSSDEWORKER
{
    HANDLE WorkerHandle;
    PVOID WorkerObject;
    PKSTART_ROUTINE pFunc;
    HANDLE UnloadEventHandle;
    PKEVENT UnloadEventObject;
    HANDLE CodeIntegrityProtectedKeyChangeEventHandle;
    PKEVENT CodeIntegrityProtectedKeyChangeEventObject;
    HANDLE CodeIntegrityProtectedKey;
    PKEY_VALUE_PARTIAL_INFORMATION CodeIntegrityLicensedValueInfo;
    ULONG CodeIntegrityLicensedValueInfoSize;
} LICENSEDSSDEWORKER, *PLICENSEDSSDEWORKER;

NTSTATUS
LicensedWorker_Delete(PLICENSEDSSDEWORKER *);

NTSTATUS
EnsureProtectedIsLicensed(PLICENSEDSSDEWORKER *);

VOID
LicensedWorker_Work(PLICENSEDSSDEWORKER *);

NTSTATUS
LicensedWorker_MakeAndInitialize(PLICENSEDSSDEWORKER *);

NTSTATUS
LicensedInitializeWorker();

VOID
LicensedUninitializeWorker();

#endif