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

typedef struct _ProductPolicyHeader
{
    ULONG cbSize;
    ULONG cbDataSize;
    ULONG cbEndMarker;
    ULONG Reserved;
    ULONG Revision;
} ProductPolicyHeader, *PProductPolicyHeader;

typedef struct _ProductPolicyValue
{
    USHORT cbSize;
    USHORT cbName;
    USHORT SlDataType;
    USHORT cbData;
    ULONG Flags;
    ULONG Reserved;
} ProductPolicyValue, *PProductPolicyValue;

#define PPV_TYPE_NONE 0
#define PPV_TYPE_SZ 1
#define PPV_TYPE_BINARY 3
#define PPV_TYPE_DWORD 4
#define PPV_TYPE_MULTI_SZ 7

NTSTATUS
EnableCustomKernelSigners(_In_ ULONG ProductOptionsBufferSize, _In_ PUCHAR ProductOptionsBuffer, _In_ PULONG uEdit);

ULONG IsCksLicensed();

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