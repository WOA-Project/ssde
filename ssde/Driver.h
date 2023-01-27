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

__drv_dispatchType(IRP_MJ_CREATE) DRIVER_DISPATCH_PAGED OnCreate;
__drv_dispatchType(IRP_MJ_CLOSE) DRIVER_DISPATCH_PAGED OnClose;
__drv_dispatchType(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH OnDeviceControl;
__drv_dispatchType_other DRIVER_DISPATCH OnOther;

DRIVER_UNLOAD OnUnload;

EXTERN_C_END
