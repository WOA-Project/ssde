/*++

Module Name:

    driver.h

Abstract:

    This file contains the driver definitions.

Environment:

    Kernel-mode Driver Framework

--*/

#include <Ntifs.h>
#include <wdm.h>
#include <ntddk.h>
#include <wdf.h>
#include <initguid.h>

#include "ssde.h"
#include "licensed.h"
#include "whql.h"
#include "trace.h"

EXTERN_C_START

//
// WDFDRIVER Events
//

DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD ssdeEvtDeviceAdd;
EVT_WDF_DRIVER_UNLOAD ssdeEvtUnload;
EVT_WDF_OBJECT_CONTEXT_CLEANUP ssdeEvtDriverContextCleanup;

EXTERN_C_END
