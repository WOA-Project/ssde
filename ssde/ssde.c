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
#    pragma alloc_text(PAGE, HandlePolicyBinary)
#    pragma alloc_text(PAGE, Worker_Delete)
#    pragma alloc_text(PAGE, Worker_Work)
#    pragma alloc_text(PAGE, Worker_MakeAndInitialize)
#endif

UNICODE_STRING gProductOptionsKeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\" PRODUCT_OPTIONS_STR);

UNICODE_STRING gProductPolicyValueName = RTL_CONSTANT_STRING(PRODUCT_POLICY_STR);

UNICODE_STRING gCiAcpCksName = RTL_CONSTANT_STRING(L"CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners");

LONG
HandlePolicyBinary(_In_ ULONG cbBytes, _In_ PUCHAR lpBytes, _In_ PULONG uEdit)
{
    BOOLEAN AllowConfigurablePolicyCustomKernelSignerSet = FALSE;
    PPPBinaryHeader pHeader = (PPPBinaryHeader)lpBytes;
    PUCHAR EndPtr = lpBytes + cbBytes;
    PPPBinaryValue pVal;

    if (cbBytes < sizeof(PPBinaryHeader) || cbBytes != pHeader->TotalSize ||
        cbBytes != sizeof(PPBinaryHeader) + sizeof(ULONG) + pHeader->DataSize)
    {
        return 0xC0000004L;
    }

    EndPtr -= sizeof(ULONG);
    if (*(PULONG)EndPtr != 0x45) // Product policy end-mark
        return STATUS_INVALID_PARAMETER;

    for (pVal = (PPPBinaryValue)(pHeader + 1); (PUCHAR)pVal + sizeof(PPBinaryValue) < EndPtr;
         pVal = (PPPBinaryValue)((PUCHAR)pVal + pVal->TotalSize))
    {
        PWSTR pValName;
        PVOID pValData;

        if (pVal->NameSize % 2 != 0)
            return STATUS_INVALID_PARAMETER;

        pValName = (PWSTR)(pVal + 1);
        pValData = (PUCHAR)pValName + pVal->NameSize;

        if ((PUCHAR)pValData + pVal->DataSize > EndPtr)
            return STATUS_INVALID_PARAMETER;

        if (AllowConfigurablePolicyCustomKernelSignerSet == FALSE &&
            _wcsnicmp(pValName, L"CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners", pVal->NameSize / 2) == 0)
        {
            if (pVal->DataType == REG_DWORD && pVal->DataSize == 4)
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
                AllowConfigurablePolicyCustomKernelSignerSet = TRUE;
                break;
            }
            else
            {
                return STATUS_INVALID_PARAMETER;
            }
        }
    }

    return 0;
}

PSSDEWORKER Worker = NULL;

NTSTATUS
Worker_Delete(PSSDEWORKER *__this)
{
    PAGED_CODE();

    NTSTATUS Status = STATUS_SUCCESS;
    ULONG uTag = 'ssde';
    PSSDEWORKER _this = *__this;

    if (_this)
    {
        if (_this->ProductPolicyValueInfo)
        {
            ExFreePoolWithTag(_this->ProductPolicyValueInfo, uTag);
            _this->ProductPolicyValueInfo = NULL;
            _this->ProductPolicyValueInfoSize = 0;
        }
        if (_this->ProductOptionsKey)
        {
            ZwClose(_this->ProductOptionsKey);
            _this->ProductOptionsKey = NULL;
        }
        if (_this->ProductOptionsKeyChangeEventHandle)
        {
            ObDereferenceObject(_this->ProductOptionsKeyChangeEventObject);
            _this->ProductOptionsKeyChangeEventObject = NULL;

            ZwClose(_this->ProductOptionsKeyChangeEventHandle);
            _this->ProductOptionsKeyChangeEventHandle = NULL;
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

    return Status;
}

VOID
Worker_Work(_In_ PSSDEWORKER *__this)
{
    PAGED_CODE();

    NTSTATUS Status = STATUS_SUCCESS;
    PSSDEWORKER _this = *__this;
    ULONG PolicyValueType = 0;
    ULONG CiAcpCks = 0;
    ULONG ResultLength = 0;
    ULONG uTag = 'ssde';
    IO_STATUS_BLOCK IoStatusBlock;

    PVOID objects[2];
    objects[0] = _this->UnloadEventObject;
    objects[1] = _this->ProductOptionsKeyChangeEventObject;

    while (1)
    {
        Status = ZwQueryLicenseValue(&gCiAcpCksName, &PolicyValueType, &CiAcpCks, sizeof(CiAcpCks), &ResultLength);
        if (!NT_SUCCESS(Status))
        {
            break;
        }
        if (PolicyValueType != REG_DWORD || ResultLength != sizeof(ULONG))
        {
            Status = STATUS_OBJECT_TYPE_MISMATCH;
            break;
        }

        if (CiAcpCks == 0)
        {
            while (1)
            {
                Status = ZwQueryValueKey(
                    _this->ProductOptionsKey,
                    &gProductPolicyValueName,
                    KeyValuePartialInformation,
                    _this->ProductPolicyValueInfo,
                    _this->ProductPolicyValueInfoSize,
                    &ResultLength);
                if (NT_SUCCESS(Status))
                {
                    break;
                }
                else if (Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL)
                {
#pragma warning(disable : 6387)
                    ExFreePoolWithTag(_this->ProductPolicyValueInfo, uTag);
#pragma warning(default : 6387)
                    _this->ProductPolicyValueInfo =
                        (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolZero(PagedPool, ResultLength, uTag);
                    if (_this->ProductPolicyValueInfo)
                    {
                        _this->ProductPolicyValueInfoSize = ResultLength;
                    }
                    else
                    {
                        _this->ProductPolicyValueInfoSize = 0;
                        Status = STATUS_NO_MEMORY;
                        break;
                    }
                }
                else
                {
                    break;
                }
            }

            ULONG uEdit = 1;
#pragma warning(disable : 6011)
            Status = HandlePolicyBinary(
                _this->ProductPolicyValueInfo->DataLength, _this->ProductPolicyValueInfo->Data, &uEdit);
#pragma warning(default : 6011)
            if (!NT_SUCCESS(Status))
            {
                break;
            }

            Status =
                ExUpdateLicenseData(_this->ProductPolicyValueInfo->DataLength, _this->ProductPolicyValueInfo->Data);
        }

        Status = ZwNotifyChangeKey(
            _this->ProductOptionsKey,
            _this->ProductOptionsKeyChangeEventHandle,
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
            break;
        }

        Status = KeWaitForMultipleObjects(2, objects, WaitAny, Executive, KernelMode, FALSE, NULL, NULL);
        if (Status != STATUS_WAIT_1)
        {
            break;
        }
    }

    Worker_Delete(__this);

    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS
Worker_MakeAndInitialize(PSSDEWORKER *__this)
{
    PAGED_CODE();

    NTSTATUS Status = STATUS_SUCCESS;
    ULONG uTag = 'ssde';
    OBJECT_ATTRIBUTES ThreadAttribute;
    PSSDEWORKER _this = NULL;

    if (*__this)
    {
        Status = STATUS_INVALID_PARAMETER;
        goto finalize;
    }

    _this = (PSSDEWORKER)ExAllocatePoolZero(PagedPool, sizeof(SSDEWORKER), uTag);
    if (_this == NULL)
    {
        Status = STATUS_NO_MEMORY;
        goto finalize;
    }
    *__this = _this;

    Status = ZwCreateEvent(
        &(_this->ProductOptionsKeyChangeEventHandle), EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
    if (!NT_SUCCESS(Status))
    {
        goto finalize;
    }
    Status = ObReferenceObjectByHandle(
        _this->ProductOptionsKeyChangeEventHandle,
        EVENT_ALL_ACCESS,
        *ExEventObjectType,
        KernelMode,
        &(_this->ProductOptionsKeyChangeEventObject),
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
    InitializeObjectAttributes(&KeyAttribute, &gProductOptionsKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwOpenKey(&(_this->ProductOptionsKey), KEY_READ, &KeyAttribute);
    if (!NT_SUCCESS(Status))
    {
        goto finalize;
    }

    ULONG ResultLength = 0;
    KEY_VALUE_PARTIAL_INFORMATION KeyInfo;
    Status = ZwQueryValueKey(
        _this->ProductOptionsKey,
        &gProductPolicyValueName,
        KeyValuePartialInformation,
        &KeyInfo,
        sizeof(KeyInfo),
        &ResultLength);
    if (Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_SUCCESS)
    {
        goto finalize;
    }
    _this->ProductPolicyValueInfo =
        (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolZero(NonPagedPool, ResultLength, uTag);
    if (_this->ProductPolicyValueInfo == NULL)
    {
        Status = STATUS_NO_MEMORY;
        goto finalize;
    }
    _this->ProductPolicyValueInfoSize = ResultLength;

    _this->pFunc = Worker_Work;

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
            Worker_Delete(__this);
        }
    }
    return Status;
}

NTSTATUS
InitializeWorker()
{
    return Worker_MakeAndInitialize(&Worker);
}

VOID
UninitializeWorker()
{
    if (Worker)
    {
        PVOID WorkerObject = Worker->WorkerObject;
        HANDLE WorkerHandle = Worker->WorkerHandle;
        KeSetEvent(Worker->UnloadEventObject, IO_NO_INCREMENT, TRUE);
        KeWaitForSingleObject(WorkerObject, Executive, KernelMode, FALSE, NULL);
        ObDereferenceObject(WorkerObject);
        ZwClose(WorkerHandle);
    }
}