#ifndef _H_SSDE_H_
#define _H_SSDE_H_

typedef struct _SSDEWORKER {
    HANDLE                          WorkerHandle;
    PVOID                           WorkerObject;
    PKSTART_ROUTINE                 pFunc;
    HANDLE                          UnloadEventHandle;
    PKEVENT                         UnloadEventObject;

    HANDLE                          ProductOptionsKeyChangeEventHandle;
    PKEVENT                         ProductOptionsKeyChangeEventObject;
    HANDLE                          ProductOptionsKey;
    PKEY_VALUE_PARTIAL_INFORMATION  ProductPolicyValueInfo;
    ULONG                           ProductPolicyValueInfoSize;

    HANDLE                          CodeIntegrityProtectedKeyChangeEventHandle;
    PKEVENT                         CodeIntegrityProtectedKeyChangeEventObject;
    HANDLE                          CodeIntegrityProtectedKey;
    PKEY_VALUE_PARTIAL_INFORMATION  CodeIntegrityLicensedValueInfo;
    ULONG                           CodeIntegrityLicensedValueInfoSize;

    HANDLE                          CodeIntegrityPolicyKeyChangeEventHandle;
    PKEVENT                         CodeIntegrityPolicyKeyChangeEventObject;
    HANDLE                          CodeIntegrityPolicyKey;
    PKEY_VALUE_PARTIAL_INFORMATION  CodeIntegrityWhqlSettingsValueInfo;
    ULONG                           CodeIntegrityWhqlSettingsValueInfoSize;
} SSDEWORKER, * PSSDEWORKER;

UNICODE_STRING gProductOptionsKeyName =
RTL_CONSTANT_STRING(L"\\Registry\\Machine\\" PRODUCT_OPTIONS_STR);

UNICODE_STRING gProductPolicyValueName =
RTL_CONSTANT_STRING(PRODUCT_POLICY_STR);

UNICODE_STRING gCiAcpCksName =
RTL_CONSTANT_STRING(L"CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners");


UNICODE_STRING gCodeIntegrityProtectedKeyName =
RTL_CONSTANT_STRING(L"\\Registry\\Machine\\" CODEINTEGRITY_PROTECTED_STR);

UNICODE_STRING gCodeIntegrityLicensedValueName =
RTL_CONSTANT_STRING(CODEINTEGRITY_LICENSED_STR);


UNICODE_STRING gCodeIntegrityPolicyKeyName =
RTL_CONSTANT_STRING(L"\\Registry\\Machine\\" CODEINTEGRITY_POLICY_STR);

UNICODE_STRING gCodeIntegrityWhqlSettingsValueName =
RTL_CONSTANT_STRING(CODEINTEGRITY_WHQL_SETTINGS_STR);


NTSTATUS NTAPI ZwQueryLicenseValue(
    _In_ PUNICODE_STRING ValueName,
    _Out_opt_ PULONG Type,
    _Out_writes_bytes_to_opt_(DataSize, *ResultDataSize) PVOID Data,
    _In_ ULONG DataSize,
    _Out_ PULONG ResultDataSize
);

NTSTATUS NTAPI ExUpdateLicenseData(
    _In_ ULONG cbBytes,
    _In_reads_bytes_(cbBytes) PVOID lpBytes
);

BOOLEAN ExGetLicenseTamperState(ULONG* TamperState);
#endif