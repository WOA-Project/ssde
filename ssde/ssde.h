#ifndef _H_SSDE_H_
#define _H_SSDE_H_

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

    HANDLE CodeIntegrityProtectedKeyChangeEventHandle;
    PKEVENT CodeIntegrityProtectedKeyChangeEventObject;
    HANDLE CodeIntegrityProtectedKey;
    PKEY_VALUE_PARTIAL_INFORMATION CodeIntegrityLicensedValueInfo;
    ULONG CodeIntegrityLicensedValueInfoSize;

    HANDLE CodeIntegrityPolicyKeyChangeEventHandle;
    PKEVENT CodeIntegrityPolicyKeyChangeEventObject;
    HANDLE CodeIntegrityPolicyKey;
    PKEY_VALUE_PARTIAL_INFORMATION CodeIntegrityWhqlSettingsValueInfo;
    ULONG CodeIntegrityWhqlSettingsValueInfoSize;
} SSDEWORKER, *PSSDEWORKER;

UNICODE_STRING gProductOptionsKeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\" PRODUCT_OPTIONS_STR);

UNICODE_STRING gProductPolicyValueName = RTL_CONSTANT_STRING(PRODUCT_POLICY_STR);

UNICODE_STRING gCiAcpCksName = RTL_CONSTANT_STRING(L"CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners");

UNICODE_STRING gCodeIntegrityProtectedKeyName =
    RTL_CONSTANT_STRING(L"\\Registry\\Machine\\" CODEINTEGRITY_PROTECTED_STR);

UNICODE_STRING gCodeIntegrityLicensedValueName = RTL_CONSTANT_STRING(CODEINTEGRITY_LICENSED_STR);

UNICODE_STRING gCodeIntegrityPolicyKeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\" CODEINTEGRITY_POLICY_STR);

UNICODE_STRING gCodeIntegrityWhqlSettingsValueName = RTL_CONSTANT_STRING(CODEINTEGRITY_WHQL_SETTINGS_STR);

NTSTATUS NTAPI
ZwQueryLicenseValue(
    _In_ PUNICODE_STRING ValueName,
    _Out_opt_ PULONG Type,
    _Out_writes_bytes_to_opt_(DataSize, *ResultDataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PULONG ResultDataSize);

NTSTATUS NTAPI
ExUpdateLicenseData(_In_ ULONG cbBytes, _In_reads_bytes_(cbBytes) PVOID lpBytes);

BOOLEAN
ExGetLicenseTamperState(ULONG *TamperState);

DRIVER_INITIALIZE DriverEntry;

__drv_dispatchType(IRP_MJ_CREATE) DRIVER_DISPATCH_PAGED OnCreate;
__drv_dispatchType(IRP_MJ_CLOSE) DRIVER_DISPATCH_PAGED OnClose;
__drv_dispatchType(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH OnDeviceControl;
__drv_dispatchType_other DRIVER_DISPATCH OnOther;

DRIVER_UNLOAD OnUnload;

NTSTATUS CreateApiDevice(PDRIVER_OBJECT);
VOID DestroyApiDevice(PDRIVER_OBJECT);

NTSTATUS
OnApiGetInfo(PVOID, ULONG, ULONG, ULONG *);

NTSTATUS
Worker_Delete(PSSDEWORKER *);
VOID
Worker_Work(PSSDEWORKER *);
NTSTATUS
Worker_MakeAndInitialize(PSSDEWORKER *);
#endif