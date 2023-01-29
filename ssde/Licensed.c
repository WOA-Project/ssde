/*++

Module Name:

    licensed.c - Device handling events for example driver.

Abstract:

   This file contains the device entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "licensed.tmh"

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(PAGE, LicensedWorker_Delete)
#    pragma alloc_text(PAGE, LicensedWorker_Work)
#    pragma alloc_text(PAGE, LicensedWorker_MakeAndInitialize)
#    pragma alloc_text(PAGE, EnsureProtectedIsLicensed)
#endif

UNICODE_STRING gCodeIntegrityProtectedKeyName =
    RTL_CONSTANT_STRING(L"\\Registry\\Machine\\" CODEINTEGRITY_PROTECTED_STR);

UNICODE_STRING gCodeIntegrityLicensedValueName = RTL_CONSTANT_STRING(CODEINTEGRITY_LICENSED_STR);

PLICENSEDSSDEWORKER LicensedWorker = NULL;

NTSTATUS
LicensedWorker_Delete(PLICENSEDSSDEWORKER *__this)
{
    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    NTSTATUS Status = STATUS_SUCCESS;
    ULONG uTag = 'ssde';
    PLICENSEDSSDEWORKER _this = *__this;

    if (_this)
    {
        if (_this->CodeIntegrityLicensedValueInfo)
        {
            ExFreePoolWithTag(_this->CodeIntegrityLicensedValueInfo, uTag);
            _this->CodeIntegrityLicensedValueInfo = NULL;
            _this->CodeIntegrityLicensedValueInfoSize = 0;
        }
        if (_this->CodeIntegrityProtectedKey)
        {
            ZwClose(_this->CodeIntegrityProtectedKey);
            _this->CodeIntegrityProtectedKey = NULL;
        }
        if (_this->CodeIntegrityProtectedKeyChangeEventHandle)
        {
            ObDereferenceObject(_this->CodeIntegrityProtectedKeyChangeEventObject);
            _this->CodeIntegrityProtectedKeyChangeEventObject = NULL;

            ZwClose(_this->CodeIntegrityProtectedKeyChangeEventHandle);
            _this->CodeIntegrityProtectedKeyChangeEventHandle = NULL;
        }
        if (_this->UnloadEventHandle)
        {
            ObDereferenceObject(_this->UnloadEventObject);
            _this->UnloadEventObject = NULL;

            ZwClose(_this->UnloadEventHandle);
            _this->UnloadEventHandle = NULL;
        }
        if (_this->WorkerHandle)
        {
            _this->WorkerObject = NULL;

            _this->WorkerHandle = NULL;
        }
        _this->pFunc = NULL;
        ExFreePoolWithTag(_this, uTag);
        *__this = NULL;
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", Status);

    return Status;
}

NTSTATUS
LicensedZwQueryValueKey2(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName,
    _In_ ULONG Type,
    _In_opt_ PVOID Data,
    _In_ ULONG DataSize)
{
    PKEY_VALUE_PARTIAL_INFORMATION pinfo;
    NTSTATUS status;
    ULONG len, reslen;

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    len = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + DataSize;

    pinfo = ExAllocatePoolWithTag(NonPagedPool, len, 'ssde');

    status = ZwQueryValueKey(KeyHandle, ValueName, KeyValuePartialInformation, pinfo, len, &reslen);

    if ((NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) &&
        reslen >= (sizeof(KEY_VALUE_PARTIAL_INFORMATION) - 1) && (!Type || pinfo->Type == Type))
    {
        reslen = pinfo->DataLength;
        memcpy(Data, pinfo->Data, min(DataSize, reslen));
    }
    else
    {
        reslen = 0;
    }

    ExFreePool(pinfo);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", status);

    return status;
}

NTSTATUS
EnsureProtectedIsLicensed(_In_ PLICENSEDSSDEWORKER *__this)
{
    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    NTSTATUS Status = STATUS_SUCCESS;
    PLICENSEDSSDEWORKER _this = *__this;
    ULONG Licensed = 0;
    ULONG ResultLength = 0;
    ULONG uTag = 'ssde';
    IO_STATUS_BLOCK IoStatusBlock;

    Status = LicensedZwQueryValueKey2(
        _this->CodeIntegrityProtectedKey, &gCodeIntegrityLicensedValueName, REG_DWORD, &Licensed, sizeof(Licensed));
    if (!NT_SUCCESS(Status))
    {
        // break;
        Status = STATUS_SUCCESS;
        Licensed = 1;
    }

    if (Licensed == 0)
    {
        while (1)
        {
            Status = ZwQueryValueKey(
                _this->CodeIntegrityProtectedKey,
                &gCodeIntegrityLicensedValueName,
                KeyValuePartialInformation,
                _this->CodeIntegrityLicensedValueInfo,
                _this->CodeIntegrityLicensedValueInfoSize,
                &ResultLength);
            if (NT_SUCCESS(Status))
            {
                break;
            }
            else if (Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL)
            {
#pragma warning(disable : 6387)
                ExFreePoolWithTag(_this->CodeIntegrityLicensedValueInfo, uTag);
#pragma warning(default : 6387)
                _this->CodeIntegrityLicensedValueInfo =
                    (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, ResultLength, uTag);
                if (_this->CodeIntegrityLicensedValueInfo)
                {
                    _this->CodeIntegrityLicensedValueInfoSize = ResultLength;
                }
                else
                {
                    _this->CodeIntegrityLicensedValueInfoSize = 0;
                    Status = STATUS_NO_MEMORY;
                    break;
                }
            }
            else
            {
                break;
            }
        }

        Licensed = 1;

        Status = ZwSetValueKey(
            _this->CodeIntegrityProtectedKey, &gCodeIntegrityLicensedValueName, 0, REG_DWORD, &Licensed, sizeof(ULONG));
    }

    Status = ZwNotifyChangeKey(
        _this->CodeIntegrityProtectedKey,
        _this->CodeIntegrityProtectedKeyChangeEventHandle,
        NULL,
        NULL,
        &IoStatusBlock,
        REG_NOTIFY_CHANGE_LAST_SET,
        FALSE,
        NULL,
        0,
        TRUE);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", Status);

    return Status;
}

VOID
LicensedWorker_Work(_In_ PLICENSEDSSDEWORKER *__this)
{
    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    NTSTATUS Status = STATUS_SUCCESS;
    PLICENSEDSSDEWORKER _this = *__this;

    PVOID objects[2];
    objects[0] = _this->UnloadEventObject;
    objects[1] = _this->CodeIntegrityProtectedKeyChangeEventObject;

    while (1)
    {
        Status = EnsureProtectedIsLicensed(__this);
        if (!NT_SUCCESS(Status))
        {
            break;
        }

        Status = KeWaitForMultipleObjects(2, objects, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
        if (Status != STATUS_WAIT_1)
        {
            break;
        }
    }

    LicensedWorker_Delete(__this);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", Status);

    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS
LicensedWorker_MakeAndInitialize(PLICENSEDSSDEWORKER *__this)
{
    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    NTSTATUS Status = STATUS_SUCCESS;
    ULONG uTag = 'ssde';
    OBJECT_ATTRIBUTES ThreadAttribute;
    PLICENSEDSSDEWORKER _this = NULL;

    if (*__this)
    {
        Status = STATUS_INVALID_PARAMETER;
        goto finalize;
    }

    _this = (PLICENSEDSSDEWORKER)ExAllocatePoolWithTag(PagedPool, sizeof(LICENSEDSSDEWORKER), uTag);
    if (_this == NULL)
    {
        Status = STATUS_NO_MEMORY;
        goto finalize;
    }
    *__this = _this;

    Status = ZwCreateEvent(
        &(_this->CodeIntegrityProtectedKeyChangeEventHandle), EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
    if (!NT_SUCCESS(Status))
    {
        goto finalize;
    }
    Status = ObReferenceObjectByHandle(
        _this->CodeIntegrityProtectedKeyChangeEventHandle,
        EVENT_ALL_ACCESS,
        *ExEventObjectType,
        KernelMode,
        &(_this->CodeIntegrityProtectedKeyChangeEventObject),
        NULL);
    if (!NT_SUCCESS(Status))
    {
        goto finalize;
    }

    Status = ZwCreateEvent(&(_this->UnloadEventHandle), EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
    if (!NT_SUCCESS(Status))
    {
        goto finalize;
    }
    Status = ObReferenceObjectByHandle(
        _this->UnloadEventHandle, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, &(_this->UnloadEventObject), NULL);
    if (!NT_SUCCESS(Status))
    {
        goto finalize;
    }

    OBJECT_ATTRIBUTES KeyAttribute;
    InitializeObjectAttributes(&KeyAttribute, &gCodeIntegrityProtectedKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwOpenKey(&(_this->CodeIntegrityProtectedKey), KEY_READ, &KeyAttribute);
    if (!NT_SUCCESS(Status))
    {
        goto finalize;
    }

    ULONG ResultLength = 0;
    KEY_VALUE_PARTIAL_INFORMATION KeyInfo;
    Status = ZwQueryValueKey(
        _this->CodeIntegrityProtectedKey,
        &gCodeIntegrityLicensedValueName,
        KeyValuePartialInformation,
        &KeyInfo,
        sizeof(KeyInfo),
        &ResultLength);
    if (Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_SUCCESS)
    {
        goto finalize;
    }
    _this->CodeIntegrityLicensedValueInfo =
        (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ResultLength, uTag);
    if (_this->CodeIntegrityLicensedValueInfo == NULL)
    {
        Status = STATUS_NO_MEMORY;
        goto finalize;
    }
    _this->CodeIntegrityLicensedValueInfoSize = ResultLength;

    EnsureProtectedIsLicensed(__this);

    _this->pFunc = LicensedWorker_Work;

    InitializeObjectAttributes(&ThreadAttribute, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = PsCreateSystemThread(
        &(_this->WorkerHandle), THREAD_ALL_ACCESS, &ThreadAttribute, NULL, NULL, _this->pFunc, __this);
    if (!NT_SUCCESS(Status))
    {
        goto finalize;
    }

    Status = ObReferenceObjectByHandle(
        _this->WorkerHandle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &(_this->WorkerObject), NULL);
    if (!NT_SUCCESS(Status))
    {
        goto finalize;
    }

    Status = STATUS_SUCCESS;

finalize:
    if (!NT_SUCCESS(Status))
    {
        if (_this)
        {
            LicensedWorker_Delete(__this);
        }
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", Status);

    return Status;
}

NTSTATUS
LicensedInitializeWorker()
{
    NTSTATUS status;

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    status = LicensedWorker_MakeAndInitialize(&LicensedWorker);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", status);

    return status;
}

VOID
LicensedUninitializeWorker()
{
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    if (LicensedWorker)
    {
        PVOID WorkerObject = LicensedWorker->WorkerObject;
        HANDLE WorkerHandle = LicensedWorker->WorkerHandle;
        KeSetEvent(LicensedWorker->UnloadEventObject, IO_NO_INCREMENT, TRUE);
        KeWaitForSingleObject(WorkerObject, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(WorkerObject);
        ZwClose(WorkerHandle);
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");
}