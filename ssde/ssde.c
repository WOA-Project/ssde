#include <Ntifs.h>
#include <wdm.h>

#include "../common.h"
#include "ssde.h"

#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, Worker_Delete)
#pragma alloc_text(PAGE, Worker_Work)
#pragma alloc_text(PAGE, Worker_MakeAndInitialize)
#pragma alloc_text(PAGE, OnUnload)
#pragma alloc_text(PAGE, OnCreate)
#pragma alloc_text(PAGE, OnClose)
#pragma alloc_text(PAGE, EnsureCustomKernelSignersIsLicensed)
#pragma alloc_text(PAGE, EnsureCodeIntegrityProtectedIsLicensed)
#pragma alloc_text(PAGE, EnsureCodeIntegrityWhqlSettingsIsSet)

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
        if (_this->CodeIntegrityWhqlSettingsValueInfo)
        {
            ExFreePoolWithTag(_this->CodeIntegrityWhqlSettingsValueInfo, uTag);
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
        ExFreePoolWithTag(_this, uTag);
        *__this = NULL;
    }

    return Status;
}

NTSTATUS
EnsureCustomKernelSignersIsLicensed(_In_ PSSDEWORKER *__this)
{
    PAGED_CODE();

    NTSTATUS Status = STATUS_SUCCESS;
    PSSDEWORKER _this = *__this;
    ULONG PolicyValueType = 0;
    ULONG CiAcpCks = 0;
    ULONG ResultLength = 0;
    ULONG uTag = 'ssde';
    IO_STATUS_BLOCK IoStatusBlock;

    Status = ZwQueryLicenseValue(&gCiAcpCksName, &PolicyValueType, &CiAcpCks, sizeof(CiAcpCks), &ResultLength);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }
    if (PolicyValueType != REG_DWORD || ResultLength != sizeof(ULONG))
    {
        Status = STATUS_OBJECT_TYPE_MISMATCH;
        return Status;
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
                ExFreePoolWithTag(_this->ProductPolicyValueInfo, uTag);
                _this->ProductPolicyValueInfo =
                    (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, ResultLength, uTag);
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
        Status =
            HandlePolicyBinary(_this->ProductPolicyValueInfo->DataLength, _this->ProductPolicyValueInfo->Data, &uEdit);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }

        Status = ExUpdateLicenseData(_this->ProductPolicyValueInfo->DataLength, _this->ProductPolicyValueInfo->Data);
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
        return Status;
    }

    return Status;
}

NTSTATUS
EnsureCodeIntegrityProtectedIsLicensed(_In_ PSSDEWORKER *__this)
{
    PAGED_CODE();

    NTSTATUS Status = STATUS_SUCCESS;
    PSSDEWORKER _this = *__this;
    ULONG CiLicensed = 1;
    ULONG ResultLength = 0;
    ULONG uTag = 'ssde';
    IO_STATUS_BLOCK IoStatusBlock;

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
            ExFreePoolWithTag(_this->CodeIntegrityLicensedValueInfo, uTag);
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

    if (_this->CodeIntegrityLicensedValueInfo == NULL ||
        _this->CodeIntegrityLicensedValueInfo->DataLength != sizeof(ULONG) ||
        (*(PULONG)_this->CodeIntegrityLicensedValueInfo->Data) == 0)
    {
        Status = ZwSetValueKey(
            _this->CodeIntegrityProtectedKey,
            &gCodeIntegrityLicensedValueName,
            0,
            REG_DWORD,
            &CiLicensed,
            sizeof(ULONG));
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
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    return Status;
}

NTSTATUS
EnsureCodeIntegrityWhqlSettingsIsSet(_In_ PSSDEWORKER *__this)
{
    PAGED_CODE();

    NTSTATUS Status = STATUS_SUCCESS;
    PSSDEWORKER _this = *__this;
    ULONG CiWhqlSettings = 1;
    ULONG ResultLength = 0;
    ULONG uTag = 'ssde';
    IO_STATUS_BLOCK IoStatusBlock;

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
            ExFreePoolWithTag(_this->CodeIntegrityWhqlSettingsValueInfo, uTag);
            _this->CodeIntegrityWhqlSettingsValueInfo =
                (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, ResultLength, uTag);
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

    if (_this->CodeIntegrityWhqlSettingsValueInfo == NULL ||
        _this->CodeIntegrityWhqlSettingsValueInfo->DataLength != sizeof(ULONG) ||
        (*(PULONG)_this->CodeIntegrityWhqlSettingsValueInfo->Data) == 0)
    {
        Status = ZwSetValueKey(
            _this->CodeIntegrityPolicyKey,
            &gCodeIntegrityWhqlSettingsValueName,
            0,
            REG_DWORD,
            &CiWhqlSettings,
            sizeof(ULONG));
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
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    return Status;
}

VOID
Worker_Work(_In_ PSSDEWORKER *__this)
{
    PAGED_CODE();

    NTSTATUS Status = STATUS_SUCCESS;
    PSSDEWORKER _this = *__this;
    ULONG uTag = 'ssde';
    PKWAIT_BLOCK waitBlocks = NULL;

    PVOID objects[4];
    objects[0] = _this->UnloadEventObject;
    objects[1] = _this->ProductOptionsKeyChangeEventObject;
    objects[2] = _this->CodeIntegrityProtectedKeyChangeEventObject;
    objects[3] = _this->CodeIntegrityPolicyKeyChangeEventObject;

    ULONG objectsCount = (sizeof(objects) / sizeof(PVOID));

    while (1)
    {
        EnsureCustomKernelSignersIsLicensed(__this);
        EnsureCodeIntegrityProtectedIsLicensed(__this);
        EnsureCodeIntegrityWhqlSettingsIsSet(__this);

        if (objects && objectsCount)
        {
            if (objectsCount > THREAD_WAIT_OBJECTS)
            {
                waitBlocks =
                    (PKWAIT_BLOCK)ExAllocatePoolWithTag(NonPagedPool, objectsCount * sizeof(KWAIT_BLOCK), uTag);

                if (waitBlocks == NULL)
                {
                    Status = STATUS_NO_MEMORY;
                    break;
                }
            }
        }

        Status =
            KeWaitForMultipleObjects(objectsCount, objects, WaitAny, Executive, KernelMode, FALSE, NULL, waitBlocks);
        if (Status != STATUS_WAIT_1 && Status != STATUS_WAIT_2 && Status != STATUS_WAIT_3)
        {
            break;
        }

        if (waitBlocks != NULL)
        {
            ExFreePoolWithTag(waitBlocks, uTag);
            waitBlocks = NULL;
        }
    }

    if (waitBlocks != NULL)
    {
        ExFreePoolWithTag(waitBlocks, uTag);
        waitBlocks = NULL;
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

    _this = (PSSDEWORKER)ExAllocatePoolWithTag(PagedPool, sizeof(SSDEWORKER), uTag);
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

    Status = ZwCreateEvent(
        &(_this->CodeIntegrityPolicyKeyChangeEventHandle), EVENT_ALL_ACCESS, NULL, SynchronizationEvent, FALSE);
    if (!NT_SUCCESS(Status))
    {
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

    InitializeObjectAttributes(&KeyAttribute, &gCodeIntegrityProtectedKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwOpenKey(&(_this->CodeIntegrityProtectedKey), KEY_READ, &KeyAttribute);
    if (!NT_SUCCESS(Status))
    {
        goto finalize;
    }
    InitializeObjectAttributes(&KeyAttribute, &gCodeIntegrityPolicyKeyName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = ZwOpenKey(&(_this->CodeIntegrityPolicyKey), KEY_READ, &KeyAttribute);
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
        (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ResultLength, uTag);
    if (_this->ProductPolicyValueInfo == NULL)
    {
        Status = STATUS_NO_MEMORY;
        goto finalize;
    }
    _this->ProductPolicyValueInfoSize = ResultLength;

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

    Status = ZwQueryValueKey(
        _this->CodeIntegrityPolicyKey,
        &gCodeIntegrityWhqlSettingsValueName,
        KeyValuePartialInformation,
        &KeyInfo,
        sizeof(KeyInfo),
        &ResultLength);
    if (Status != STATUS_BUFFER_OVERFLOW && Status != STATUS_BUFFER_TOO_SMALL && Status != STATUS_SUCCESS)
    {
        goto finalize;
    }
    _this->CodeIntegrityWhqlSettingsValueInfo =
        (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, ResultLength, uTag);
    if (_this->CodeIntegrityWhqlSettingsValueInfo == NULL)
    {
        Status = STATUS_NO_MEMORY;
        goto finalize;
    }
    _this->CodeIntegrityWhqlSettingsValueInfoSize = ResultLength;

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
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status = STATUS_SUCCESS;

    for (int n = 0; n <= IRP_MJ_MAXIMUM_FUNCTION; n++)
    {
        DriverObject->MajorFunction[n] = OnOther;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = OnCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = OnClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnDeviceControl;

    DriverObject->DriverUnload = OnUnload;

    Status = Worker_MakeAndInitialize(&Worker);
    if (!NT_SUCCESS(Status))
    {
        goto finalize;
    }

finalize:
    return Status;
}

VOID
OnUnload(PDRIVER_OBJECT DriverObject)
{
    PAGED_CODE(); // keep the static analysis tools happy

    UNREFERENCED_PARAMETER(DriverObject);

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

FORCEINLINE
NTSTATUS
IrpDispatchDone(PIRP Irp, NTSTATUS Status)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

FORCEINLINE
NTSTATUS
IrpDispatchDoneEx(PIRP Irp, NTSTATUS Status, ULONG Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS
OnCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION sl = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT fileobj = sl->FileObject;
    PUNICODE_STRING filename = &(fileobj->FileName);
    NTSTATUS status = filename->Length != 0 ? STATUS_INVALID_PARAMETER : STATUS_SUCCESS;

    return IrpDispatchDone(Irp, status);
}

NTSTATUS
OnClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DeviceObject);

    return IrpDispatchDone(Irp, STATUS_SUCCESS);
}

NTSTATUS
OnDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    return IrpDispatchDoneEx(Irp, STATUS_INVALID_PARAMETER, 0);
}

NTSTATUS
OnOther(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    return IrpDispatchDone(Irp, STATUS_INVALID_DEVICE_REQUEST);
}