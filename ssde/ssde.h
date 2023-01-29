/*++

Module Name:

    ssde.h

Abstract:

    This file contains the device definitions.

Environment:

    Kernel-mode Driver Framework

--*/

#ifndef _H_SSDE_H_
#define _H_SSDE_H_

#define PRODUCT_OPTIONS_STR L"SYSTEM\\CurrentControlSet\\Control\\ProductOptions"
#define PRODUCT_POLICY_STR L"ProductPolicy"

typedef struct _PPBinaryHeader
{
    ULONG TotalSize;
    ULONG DataSize;
    ULONG EndMarkerSize;
    ULONG Reserved;
    ULONG Revision;
} PPBinaryHeader, *PPPBinaryHeader;

typedef struct _PPBinaryValue
{
    USHORT TotalSize;
    USHORT NameSize;
    USHORT DataType;
    USHORT DataSize;
    ULONG Flags;
    ULONG Reserved;
} PPBinaryValue, *PPPBinaryValue;

LONG
HandlePolicyBinary(_In_ ULONG, _In_ PUCHAR, _In_ PULONG);

typedef struct _SSDEWORKER
{
    HANDLE WorkerHandle;
    PVOID WorkerObject;
    PKSTART_ROUTINE pFunc;
    HANDLE UnloadEventHandle;
    PKEVENT UnloadEventObject;
    HANDLE ProductOptionsKeyChangeEventHandle;
    PKEVENT ProductOptionsKeyChangeEventObject;
    HANDLE ProductOptionsKey;
    PKEY_VALUE_PARTIAL_INFORMATION ProductPolicyValueInfo;
    ULONG ProductPolicyValueInfoSize;
} SSDEWORKER, *PSSDEWORKER;

NTSTATUS NTAPI
ZwQueryLicenseValue(
    _In_ PUNICODE_STRING ValueName,
    _Out_opt_ PULONG Type,
    _Out_writes_bytes_to_opt_(DataSize, *ResultDataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PULONG ResultDataSize);

NTSTATUS NTAPI
ExUpdateLicenseData(_In_ ULONG cbBytes, _In_reads_bytes_(cbBytes) PVOID lpBytes);

NTSTATUS
Worker_Delete(PSSDEWORKER *);

NTSTATUS
EnsureCksIsLicensed(PSSDEWORKER *);

VOID
Worker_Work(PSSDEWORKER *);

NTSTATUS
Worker_MakeAndInitialize(PSSDEWORKER *);

NTSTATUS
InitializeWorker();

VOID
UninitializeWorker();

#endif