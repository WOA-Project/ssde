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
#    pragma alloc_text(PAGE, DriverCreate)
#    pragma alloc_text(PAGE, DriverUnload)
#    pragma alloc_text(PAGE, DriverClose)
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
        DriverObject->MajorFunction[n] = DriverStub;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = OnDeviceControl;

    DriverObject->DriverUnload = DriverUnload;

    status = InitializeWorker();
    if (!NT_SUCCESS(status))
    {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "InitializeWorker failed %!STATUS!", status);
        goto exit;
    }

    status = LicensedInitializeWorker();
    if (!NT_SUCCESS(status))
    {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "LicensedInitializeWorker failed %!STATUS!", status);
        goto exit;
    }

    status = WhqlInitializeWorker();
    if (!NT_SUCCESS(status))
    {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_DRIVER, "WhqlInitializeWorker failed %!STATUS!", status);
        goto exit;
    }

exit:
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", status);

    return status;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    UNREFERENCED_PARAMETER(DriverObject);

    UninitializeWorker();
    LicensedUninitializeWorker();
    WhqlUninitializeWorker();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit");
}

NTSTATUS IrpDispatchDone(
    PIRP Irp, 
    NTSTATUS Status
)
{
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", Status);

    return Status;
}

NTSTATUS IrpDispatchDoneEx(
    PIRP Irp,
    NTSTATUS Status,
    ULONG Information
)
{
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", Status);

    return Status;
}

NTSTATUS DriverCreate(
    PDEVICE_OBJECT DeviceObject, 
    PIRP Irp
)
{
    PAGED_CODE();

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION sl = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT fileobj = sl->FileObject;
    PUNICODE_STRING filename = &(fileobj->FileName);
    NTSTATUS status = filename->Length != 0
        ? STATUS_INVALID_PARAMETER
        : STATUS_SUCCESS;

    status = IrpDispatchDone(Irp, status);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", status);

    return status;
}

NTSTATUS DriverClose(
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
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = IrpDispatchDoneEx(Irp, STATUS_INVALID_PARAMETER, 0);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", status);

    return status;
}

NTSTATUS DriverStub(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Entry");

    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = IrpDispatchDone(Irp, STATUS_INVALID_DEVICE_REQUEST);

    TraceEvents(TRACE_LEVEL_INFORMATION, TRACE_DRIVER, "%!FUNC! Exit %!STATUS!", status);

    return status;
}