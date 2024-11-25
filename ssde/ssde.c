/*++

Module Name:

    ssde.c - Device handling events for example driver.

Abstract:

   This file contains the device entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "ssde.tmh"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, EnableCustomKernelSigners)
#pragma alloc_text(PAGE, IsCksLicensed)
#pragma alloc_text(PAGE, Worker_Delete)
#pragma alloc_text(PAGE, Worker_Work)
#pragma alloc_text(PAGE, Worker_MakeAndInitialize)
#pragma alloc_text(PAGE, EnsureCksIsLicensed)
#endif

#define SSDE_POOL_TAG_0 '0dss'
#define SSDE_POOL_TAG_1 '1dss'

#define CI_ACP_CUSTOMKERNELSIGNERS L"CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners"

PSSDEWORKER Worker = NULL;

UNICODE_STRING gProductOptionsKeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\" PRODUCT_OPTIONS_STR);
UNICODE_STRING gProductPolicyValueName = RTL_CONSTANT_STRING(PRODUCT_POLICY_STR);
UNICODE_STRING gCiAcpCksName = RTL_CONSTANT_STRING(CI_ACP_CUSTOMKERNELSIGNERS);

NTSTATUS
EnableCustomKernelSigners(_In_ ULONG ProductOptionsBufferSize, _In_ PUCHAR ProductOptionsBuffer, _In_ PULONG uEdit)
{
    NTSTATUS Status = STATUS_SUCCESS;

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    if (ProductOptionsBuffer == NULL)
    {
        Status = STATUS_INVALID_PARAMETER;
        goto exit;
    }

    PProductPolicyHeader pProductPolicyHeader = (PProductPolicyHeader)ProductOptionsBuffer;

    if (pProductPolicyHeader->cbSize < sizeof(ProductPolicyHeader))
    {
        Status = STATUS_INVALID_PARAMETER;
        goto exit;
    }

    if (pProductPolicyHeader->cbSize != ProductOptionsBufferSize || pProductPolicyHeader->cbDataSize + sizeof(ProductPolicyHeader) + sizeof(ULONG) != pProductPolicyHeader->cbSize)
    {
        Status = STATUS_INVALID_PARAMETER;
        goto exit;
    }

    PUCHAR EndPtr = ProductOptionsBuffer + ProductOptionsBufferSize;

    EndPtr -= sizeof(ULONG);
    if (*(PULONG)EndPtr != 0x45) // Product policy end-mark
    {
        Status = STATUS_INVALID_PARAMETER;
        goto exit;
    }

    for (PProductPolicyValue pVal = (PProductPolicyValue)(pProductPolicyHeader + 1); (PUCHAR)pVal + sizeof(ProductPolicyValue) < EndPtr; pVal = (PProductPolicyValue)((PUCHAR)pVal + pVal->cbSize))
    {
        if (pVal->cbName % 2 != 0)
        {
            Status = STATUS_INVALID_PARAMETER;
            goto exit;
        }

        PWSTR pValName = (PWSTR)(pVal + 1);
        PVOID pValData = (PUCHAR)pValName + pVal->cbName;

        if ((PUCHAR)pValData + pVal->cbData > EndPtr)
        {
            Status = STATUS_INVALID_PARAMETER;
            goto exit;
        }

        if (_wcsnicmp(pValName, CI_ACP_CUSTOMKERNELSIGNERS, pVal->cbName / 2) == 0)
        {
            if (pVal->SlDataType == PPV_TYPE_DWORD && pVal->cbData == 4)
            {
                if (*uEdit)
                {
                    *(PULONG)pValData = *uEdit;
                    *uEdit = 0;
                }
                else
                {
                    *uEdit = *(PULONG)pValData;
                }

                goto exit;
            }

            Status = STATUS_INVALID_PARAMETER;
            goto exit;
        }
    }

exit:
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", Status);
    return Status;
}

NTSTATUS
Worker_Delete(PSSDEWORKER *pWorkerContext)
{
    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    NTSTATUS Status = STATUS_SUCCESS;
    PSSDEWORKER WorkerContext = *pWorkerContext;

    if (WorkerContext)
    {
        if (WorkerContext->ProductPolicyValueInfo)
        {
            ExFreePoolWithTag(WorkerContext->ProductPolicyValueInfo, SSDE_POOL_TAG_1);
            WorkerContext->ProductPolicyValueInfo = NULL;
            WorkerContext->ProductPolicyValueInfoSize = 0;
        }

        if (WorkerContext->ProductOptionsKey)
        {
            ZwClose(WorkerContext->ProductOptionsKey);
            WorkerContext->ProductOptionsKey = NULL;
        }

        if (WorkerContext->ProductOptionsKeyChangeEventHandle)
        {
            ObDereferenceObject(WorkerContext->ProductOptionsKeyChangeEventObject);
            WorkerContext->ProductOptionsKeyChangeEventObject = NULL;

            ZwClose(WorkerContext->ProductOptionsKeyChangeEventHandle);
            WorkerContext->ProductOptionsKeyChangeEventHandle = NULL;
        }

        if (WorkerContext->UnloadEventHandle)
        {
            ObDereferenceObject(WorkerContext->UnloadEventObject);
            WorkerContext->UnloadEventObject = NULL;

            ZwClose(WorkerContext->UnloadEventHandle);
            WorkerContext->UnloadEventHandle = NULL;
        }

        if (WorkerContext->WorkerHandle)
        {
            WorkerContext->WorkerObject = NULL;

            WorkerContext->WorkerHandle = NULL;
        }

        WorkerContext->pFunc = NULL;
        ExFreePoolWithTag(WorkerContext, SSDE_POOL_TAG_0);
        *pWorkerContext = NULL;
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", Status);
    return Status;
}

ULONG IsCksLicensed()
{
    PAGED_CODE();

    NTSTATUS Status = STATUS_SUCCESS;
    ULONG PolicyValueType = 0;
    ULONG CiAcpCks = 0;
    ULONG ResultLength = 0;

    Status = ZwQueryLicenseValue(&gCiAcpCksName, &PolicyValueType, &CiAcpCks, sizeof(CiAcpCks), &ResultLength);

    if (!NT_SUCCESS(Status))
    {
        // If any failure occurs, the value may be missing or garbled, in this case, the feature would be enabled anyway by CI.
        return TRUE;
    }

    if (PolicyValueType != PPV_TYPE_DWORD || ResultLength != sizeof(ULONG))
    {
        // If any failure occurs, the value may be missing or garbled, in this case, the feature would be enabled anyway by CI.
        return TRUE;
    }

    if (CiAcpCks == 1)
    {
        return TRUE;
    }

    return FALSE;
}

NTSTATUS
EnsureCksIsLicensed(_In_ PSSDEWORKER *pWorkerContext)
{
    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    NTSTATUS Status = STATUS_SUCCESS;
    ULONG ResultLength = 0;
    PSSDEWORKER WorkerContext = *pWorkerContext;
    IO_STATUS_BLOCK IoStatusBlock;

    if (!IsCksLicensed())
    {
        while (TRUE)
        {
            Status = ZwQueryValueKey(
                WorkerContext->ProductOptionsKey,
                &gProductPolicyValueName,
                KeyValuePartialInformation,
                WorkerContext->ProductPolicyValueInfo,
                WorkerContext->ProductPolicyValueInfoSize,
                &ResultLength);

            if (NT_SUCCESS(Status))
            {
                break;
            }

            if (Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL)
            {
                break;
            }

#pragma warning(disable : 6387)
            ExFreePoolWithTag(WorkerContext->ProductPolicyValueInfo, SSDE_POOL_TAG_1);
#pragma warning(default : 6387)
            WorkerContext->ProductPolicyValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, ResultLength, SSDE_POOL_TAG_1);

            if (!WorkerContext->ProductPolicyValueInfo)
            {
                WorkerContext->ProductPolicyValueInfoSize = 0;
                Status = STATUS_NO_MEMORY;
                goto exit;
            }

            WorkerContext->ProductPolicyValueInfoSize = ResultLength;
        }

        ULONG uEdit = 1;
#pragma warning(disable : 6011)
        Status = EnableCustomKernelSigners(WorkerContext->ProductPolicyValueInfo->DataLength, WorkerContext->ProductPolicyValueInfo->Data, &uEdit);
#pragma warning(default : 6011)
        if (!NT_SUCCESS(Status))
        {
            goto exit;
        }

        Status = ExUpdateLicenseData(WorkerContext->ProductPolicyValueInfo->DataLength, WorkerContext->ProductPolicyValueInfo->Data);
        if (!NT_SUCCESS(Status))
        {
            TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! ExUpdateLicenseData failed: %!STATUS!", Status);
            //goto exit;
        }
    }

    Status = ZwNotifyChangeKey(
        WorkerContext->ProductOptionsKey,
        WorkerContext->ProductOptionsKeyChangeEventHandle,
        NULL,
        NULL,
        &IoStatusBlock,
        REG_NOTIFY_CHANGE_LAST_SET,
        FALSE,
        NULL,
        0,
        TRUE);

    if (!NT_SUCCESS(Status))
    {
        goto exit;
    }

exit:
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", Status);
    return Status;
}

VOID Worker_Work(_In_ PSSDEWORKER *pWorkerContext)
{
    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    NTSTATUS Status = STATUS_SUCCESS;
    PSSDEWORKER WorkerContext = *pWorkerContext;

    PVOID objects[2];
    objects[0] = WorkerContext->UnloadEventObject;
    objects[1] = WorkerContext->ProductOptionsKeyChangeEventObject;

    while (TRUE)
    {
        Status = EnsureCksIsLicensed(pWorkerContext);

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

    Worker_Delete(pWorkerContext);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", Status);

    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS
Worker_MakeAndInitialize(PSSDEWORKER *pWorkerContext)
{
    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    NTSTATUS Status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES ThreadAttribute;
    OBJECT_ATTRIBUTES KeyAttribute;
    ULONG ResultLength = 0;
    KEY_VALUE_PARTIAL_INFORMATION KeyInfo;
    PSSDEWORKER WorkerContext = NULL;

    if (*pWorkerContext)
    {
        Status = STATUS_INVALID_PARAMETER;
        goto finalize;
    }

    WorkerContext = (PSSDEWORKER)ExAllocatePoolWithTag(PagedPool, sizeof(SSDEWORKER), SSDE_POOL_TAG_0);

    if (WorkerContext == NULL)
    {
        Status = STATUS_NO_MEMORY;
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! ExAllocatePoolWithTag failed: %!STATUS!", Status);
        goto finalize;
    }
    
    RtlZeroMemory(WorkerContext, sizeof(SSDEWORKER));

    *pWorkerContext = WorkerContext;

    Status = ZwCreateEvent(
        &(WorkerContext->ProductOptionsKeyChangeEventHandle), EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);

    if (!NT_SUCCESS(Status))
    {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! ZwCreateEvent failed: %!STATUS!", Status);
        goto finalize;
    }

    Status = ObReferenceObjectByHandle(
        WorkerContext->ProductOptionsKeyChangeEventHandle,
        EVENT_ALL_ACCESS,
        *ExEventObjectType,
        KernelMode,
        &(WorkerContext->ProductOptionsKeyChangeEventObject),
        NULL);

    if (!NT_SUCCESS(Status))
    {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! ObReferenceObjectByHandle failed: %!STATUS!", Status);
        goto finalize;
    }

    Status = ZwCreateEvent(&(WorkerContext->UnloadEventHandle), EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);

    if (!NT_SUCCESS(Status))
    {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! ZwCreateEvent failed: %!STATUS!", Status);
        goto finalize;
    }

    Status = ObReferenceObjectByHandle(
        WorkerContext->UnloadEventHandle, EVENT_ALL_ACCESS, *ExEventObjectType, KernelMode, &(WorkerContext->UnloadEventObject), NULL);

    if (!NT_SUCCESS(Status))
    {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! ObReferenceObjectByHandle failed: %!STATUS!", Status);
        goto finalize;
    }

    InitializeObjectAttributes(&KeyAttribute, &gProductOptionsKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    Status = ZwOpenKey(&(WorkerContext->ProductOptionsKey), KEY_READ, &KeyAttribute);

    if (!NT_SUCCESS(Status))
    {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! ZwOpenKey failed: %!STATUS!", Status);
        goto finalize;
    }

    Status = ZwQueryValueKey(
        WorkerContext->ProductOptionsKey,
        &gProductPolicyValueName,
        KeyValuePartialInformation,
        &KeyInfo,
        sizeof(KeyInfo),
        &ResultLength);

    if (Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_SUCCESS)
    {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! ZwQueryValueKey failed: %!STATUS!", Status);
        goto finalize;
    }

    WorkerContext->ProductPolicyValueInfo =
        (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ResultLength, SSDE_POOL_TAG_1);

    if (WorkerContext->ProductPolicyValueInfo == NULL)
    {
        Status = STATUS_NO_MEMORY;
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! ExAllocatePoolWithTag failed: %!STATUS!", Status);
        goto finalize;
    }

    WorkerContext->ProductPolicyValueInfoSize = ResultLength;

    EnsureCksIsLicensed(pWorkerContext);

    WorkerContext->pFunc = Worker_Work;

    InitializeObjectAttributes(&ThreadAttribute, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = PsCreateSystemThread(
        &(WorkerContext->WorkerHandle), THREAD_ALL_ACCESS, &ThreadAttribute, NULL, NULL, WorkerContext->pFunc, pWorkerContext);

    if (!NT_SUCCESS(Status))
    {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! PsCreateSystemThread failed: %!STATUS!", Status);
        goto finalize;
    }

    Status = ObReferenceObjectByHandle(
        WorkerContext->WorkerHandle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, &(WorkerContext->WorkerObject), NULL);

    if (!NT_SUCCESS(Status))
    {
        TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! ObReferenceObjectByHandle failed: %!STATUS!", Status);
        goto finalize;
    }

    Status = STATUS_SUCCESS;

finalize:
    if (!NT_SUCCESS(Status))
    {
        if (WorkerContext)
        {
            Worker_Delete(pWorkerContext);
        }
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", Status);
    return Status;
}

NTSTATUS
InitializeWorker()
{
    NTSTATUS status;

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    status = Worker_MakeAndInitialize(&Worker);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", status);
    return status;
}

VOID UninitializeWorker()
{
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    if (Worker)
    {
        PVOID WorkerObject = Worker->WorkerObject;
        HANDLE WorkerHandle = Worker->WorkerHandle;
        KeSetEvent(Worker->UnloadEventObject, IO_NO_INCREMENT, TRUE);
        KeWaitForSingleObject(WorkerObject, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(WorkerObject);
        ZwClose(WorkerHandle);
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");
}