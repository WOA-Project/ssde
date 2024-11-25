/*++

Module Name:

    whql.c - Device handling events for example driver.

Abstract:

   This file contains the device entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "whql.tmh"

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(PAGE, WhqlWorker_Delete)
#    pragma alloc_text(PAGE, WhqlWorker_Work)
#    pragma alloc_text(PAGE, WhqlWorker_MakeAndInitialize)
#    pragma alloc_text(PAGE, EnsureWhqlIsLicensed)
#endif

#define WHQL_POOL_TAG_0 '0qhw'
#define WHQL_POOL_TAG_1 '1qhw'

UNICODE_STRING gCodeIntegrityPolicyKeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\" CODEINTEGRITY_POLICY_STR);

UNICODE_STRING gCodeIntegrityWhqlSettingsValueName = RTL_CONSTANT_STRING(CODEINTEGRITY_WHQL_SETTINGS_STR);

PWHQLSSDEWORKER WhqlWorker = NULL;

NTSTATUS
WhqlWorker_Delete(PWHQLSSDEWORKER *__this)
{
    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    NTSTATUS Status = STATUS_SUCCESS;
    PWHQLSSDEWORKER _this = *__this;

    if (_this)
    {
        if (_this->CodeIntegrityWhqlSettingsValueInfo)
        {
            ExFreePoolWithTag(_this->CodeIntegrityWhqlSettingsValueInfo, WHQL_POOL_TAG_1);
            _this->CodeIntegrityWhqlSettingsValueInfo = NULL;
            _this->CodeIntegrityWhqlSettingsValueInfoSize = 0;
        }
        if (_this->CodeIntegrityPolicyKey)
        {
            ZwClose(_this->CodeIntegrityPolicyKey);
            _this->CodeIntegrityPolicyKey = NULL;
        }
        if (_this->CodeIntegrityPolicyKeyChangeEventHandle)
        {
            ObDereferenceObject(_this->CodeIntegrityPolicyKeyChangeEventObject);
            _this->CodeIntegrityPolicyKeyChangeEventObject = NULL;

            ZwClose(_this->CodeIntegrityPolicyKeyChangeEventHandle);
            _this->CodeIntegrityPolicyKeyChangeEventHandle = NULL;
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
        ExFreePoolWithTag(_this, WHQL_POOL_TAG_0);
        *__this = NULL;
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", Status);

    return Status;
}

NTSTATUS
WhqlZwQueryValueKey2(
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

    pinfo = ExAllocatePoolWithTag(NonPagedPool, len, WHQL_POOL_TAG_1);

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

    ExFreePoolWithTag(pinfo, WHQL_POOL_TAG_1);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", status);

    return status;
}

NTSTATUS
EnsureWhqlIsLicensed(_In_ PWHQLSSDEWORKER *__this)
{
    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    NTSTATUS Status = STATUS_SUCCESS;
    PWHQLSSDEWORKER _this = *__this;
    ULONG Whql = 0;
    ULONG ResultLength = 0;
    IO_STATUS_BLOCK IoStatusBlock;

    Status = WhqlZwQueryValueKey2(
        _this->CodeIntegrityPolicyKey, &gCodeIntegrityWhqlSettingsValueName, REG_DWORD, &Whql, sizeof(Whql));
    if (!NT_SUCCESS(Status))
    {
        // break;
        Status = STATUS_SUCCESS;
        Whql = 1;
    }

    if (Whql == 0)
    {
        while (1)
        {
            Status = ZwQueryValueKey(
                _this->CodeIntegrityPolicyKey,
                &gCodeIntegrityWhqlSettingsValueName,
                KeyValuePartialInformation,
                _this->CodeIntegrityWhqlSettingsValueInfo,
                _this->CodeIntegrityWhqlSettingsValueInfoSize,
                &ResultLength);
            if (NT_SUCCESS(Status))
            {
                break;
            }
            else if (Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL)
            {
#pragma warning(disable : 6387)
                ExFreePoolWithTag(_this->CodeIntegrityWhqlSettingsValueInfo, WHQL_POOL_TAG_1);
#pragma warning(default : 6387)
                _this->CodeIntegrityWhqlSettingsValueInfo =
                    (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, ResultLength, WHQL_POOL_TAG_1);
                if (_this->CodeIntegrityWhqlSettingsValueInfo)
                {
                    _this->CodeIntegrityWhqlSettingsValueInfoSize = ResultLength;
                }
                else
                {
                    _this->CodeIntegrityWhqlSettingsValueInfoSize = 0;
                    Status = STATUS_NO_MEMORY;
                    break;
                }
            }
            else
            {
                break;
            }
        }

        Whql = 1;

        Status = ZwSetValueKey(
            _this->CodeIntegrityPolicyKey, &gCodeIntegrityWhqlSettingsValueName, 0, REG_DWORD, &Whql, sizeof(ULONG));
    }

    Status = ZwNotifyChangeKey(
        _this->CodeIntegrityPolicyKey,
        _this->CodeIntegrityPolicyKeyChangeEventHandle,
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
WhqlWorker_Work(_In_ PWHQLSSDEWORKER *__this)
{
    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    NTSTATUS Status = STATUS_SUCCESS;
    PWHQLSSDEWORKER _this = *__this;

    PVOID objects[2];
    objects[0] = _this->UnloadEventObject;
    objects[1] = _this->CodeIntegrityPolicyKeyChangeEventObject;

    while (1)
    {
        Status = EnsureWhqlIsLicensed(__this);
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

    WhqlWorker_Delete(__this);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", Status);

    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS
WhqlWorker_MakeAndInitialize(PWHQLSSDEWORKER *__this)
{
    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    NTSTATUS Status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ThreadAttribute;
    PWHQLSSDEWORKER _this = NULL;

    if (*__this)
    {
        Status = STATUS_INVALID_PARAMETER;
        goto finalize;
    }

    _this = (PWHQLSSDEWORKER)ExAllocatePoolWithTag(PagedPool, sizeof(WHQLSSDEWORKER), WHQL_POOL_TAG_0);
    if (_this == NULL)
    {
        Status = STATUS_NO_MEMORY;
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! ExAllocatePoolWithTag failed: %!STATUS!", Status);
        goto finalize;
    }

    RtlZeroMemory(_this, sizeof(WHQLSSDEWORKER));

    *__this = _this;

    Status = ZwCreateEvent(
        &(_this->CodeIntegrityPolicyKeyChangeEventHandle), EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
    if (!NT_SUCCESS(Status))
    {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! ZwCreateEvent failed: %!STATUS!", Status);
        goto finalize;
    }
    Status = ObReferenceObjectByHandle(
        _this->CodeIntegrityPolicyKeyChangeEventHandle,
        EVENT_ALL_ACCESS,
        *ExEventObjectType,
        KernelMode,
        &(_this->CodeIntegrityPolicyKeyChangeEventObject),
        NULL);
    if (!NT_SUCCESS(Status))
    {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! ObReferenceObjectByHandle failed: %!STATUS!", Status);
        goto finalize;
    }

    Status = ZwCreateEvent(&(_this->UnloadEventHandle), EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
    if (!NT_SUCCESS(Status))
    {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! ZwCreateEvent failed: %!STATUS!", Status);
        goto finalize;
    }
    Status = ObReferenceObjectByHandle(
        _this->UnloadEventHandle, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, &(_this->UnloadEventObject), NULL);
    if (!NT_SUCCESS(Status))
    {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! ObReferenceObjectByHandle failed: %!STATUS!", Status);
        goto finalize;
    }

    OBJECT_ATTRIBUTES KeyAttribute;
    InitializeObjectAttributes(&KeyAttribute, &gCodeIntegrityPolicyKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwOpenKey(&(_this->CodeIntegrityPolicyKey), KEY_READ, &KeyAttribute);
    if (!NT_SUCCESS(Status))
    {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! ZwOpenKey failed: %!STATUS!", Status);
        goto finalize;
    }

    ULONG ResultLength = 0;
    KEY_VALUE_PARTIAL_INFORMATION KeyInfo;
    Status = ZwQueryValueKey(
        _this->CodeIntegrityPolicyKey,
        &gCodeIntegrityWhqlSettingsValueName,
        KeyValuePartialInformation,
        &KeyInfo,
        sizeof(KeyInfo),
        &ResultLength);
    if (Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_SUCCESS)
    {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! ZwQueryValueKey failed: %!STATUS!", Status);
        goto finalize;
    }
    _this->CodeIntegrityWhqlSettingsValueInfo =
        (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ResultLength, WHQL_POOL_TAG_1);
    if (_this->CodeIntegrityWhqlSettingsValueInfo == NULL)
    {
        Status = STATUS_NO_MEMORY;
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! ExAllocatePoolWithTag failed: %!STATUS!", Status);
        goto finalize;
    }
    _this->CodeIntegrityWhqlSettingsValueInfoSize = ResultLength;

    EnsureWhqlIsLicensed(__this);

    _this->pFunc = WhqlWorker_Work;

    InitializeObjectAttributes(&ThreadAttribute, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    Status = PsCreateSystemThread(
        &(_this->WorkerHandle), THREAD_ALL_ACCESS, &ThreadAttribute, NULL, NULL, _this->pFunc, __this);
    if (!NT_SUCCESS(Status))
    {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! PsCreateSystemThread failed: %!STATUS!", Status);
        goto finalize;
    }

    Status = ObReferenceObjectByHandle(
        _this->WorkerHandle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &(_this->WorkerObject), NULL);
    if (!NT_SUCCESS(Status))
    {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! ObReferenceObjectByHandle failed: %!STATUS!", Status);
        goto finalize;
    }

    Status = STATUS_SUCCESS;

finalize:
    if (!NT_SUCCESS(Status))
    {
        if (_this)
        {
            WhqlWorker_Delete(__this);
        }
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", Status);

    return Status;
}

NTSTATUS
WhqlInitializeWorker()
{
    NTSTATUS status;

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    status = WhqlWorker_MakeAndInitialize(&WhqlWorker);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", status);

    return status;
}

VOID
WhqlUninitializeWorker()
{
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    if (WhqlWorker)
    {
        PVOID WorkerObject = WhqlWorker->WorkerObject;
        HANDLE WorkerHandle = WhqlWorker->WorkerHandle;
        KeSetEvent(WhqlWorker->UnloadEventObject, IO_NO_INCREMENT, TRUE);
        KeWaitForSingleObject(WorkerObject, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(WorkerObject);
        ZwClose(WorkerHandle);
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");
}