/*++

Module Name:

    driver.c

Abstract:

    This file contains the driver entry points and callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "driver.h"
#include "driver.tmh"

#ifdef ALLOC_PRAGMA
#    pragma alloc_text(INIT, DriverEntry)
#    pragma alloc_text(PAGE, OnCreate)
#    pragma alloc_text(PAGE, OnUnload)
#    pragma alloc_text(PAGE, OnClose)
#endif

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
/*++

Routine Description:
    DriverEntry initializes the driver and is the first routine called by the
    system after the driver is loaded. DriverEntry specifies the other entry
    points in the function driver, such as EvtDevice and DriverUnload.

Parameters Description:

    DriverObject - represents the instance of the function driver that is loaded
    into memory. DriverEntry must initialize members of DriverObject before it
    returns to the caller. DriverObject is allocated by the system before the
    driver is loaded, and it is released by the system after the system unloads
    the function driver from memory.

    RegistryPath - represents the driver specific path in the Registry.
    The function driver can use the path to store driver related data between
    reboots. The path does not store hardware instance specific data.

Return Value:

    STATUS_SUCCESS if successful,
    STATUS_UNSUCCESSFUL otherwise.

--*/
{
    NTSTATUS status;

    //
    // Initialize WPP Tracing
    //
    WPP_INIT_TRACING(DriverObject, RegistryPath);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    for (int n = 0; n <= IRP_MJ_MAXIMUM_FUNCTION; n++) {
        DriverObject->MajorFunction[n] = OnOther;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = OnCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = OnClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnDeviceControl;

    DriverObject->DriverUnload = OnUnload;

    status = InitializeWorker();
    if (!NT_SUCCESS(status))
    {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "InitializeWorker failed %!STATUS!", status);
        return status;
    }

    status = LicensedInitializeWorker();
    if (!NT_SUCCESS(status))
    {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "LicensedInitializeWorker failed %!STATUS!", status);
        return status;
    }

    status = WhqlInitializeWorker();
    if (!NT_SUCCESS(status))
    {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WhqlInitializeWorker failed %!STATUS!", status);
        return status;
    }

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");

    return status;
}

VOID OnUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    UninitializeWorker();
    LicensedUninitializeWorker();
    WhqlUninitializeWorker();
}

FORCEINLINE
NTSTATUS IrpDispatchDone(
    PIRP Irp, 
    NTSTATUS Status
)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

FORCEINLINE
NTSTATUS IrpDispatchDoneEx(
    PIRP Irp,
    NTSTATUS Status,
    ULONG Information
)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

NTSTATUS OnCreate(
    PDEVICE_OBJECT DeviceObject, 
    PIRP Irp
)
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION sl = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT fileobj = sl->FileObject;
    PUNICODE_STRING filename = &(fileobj->FileName);
    NTSTATUS status = filename->Length != 0
        ? STATUS_INVALID_PARAMETER
        : STATUS_SUCCESS;

    return IrpDispatchDone(Irp, status);
}

NTSTATUS OnClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    //
    // Stop WPP Tracing
    //
    WPP_CLEANUP(DeviceObject->DriverObject);

    return IrpDispatchDone(Irp, STATUS_SUCCESS);
}

NTSTATUS OnDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    return IrpDispatchDoneEx(Irp, STATUS_INVALID_PARAMETER, 0);
}

NTSTATUS OnOther(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    return IrpDispatchDone(Irp, STATUS_INVALID_DEVICE_REQUEST);
}