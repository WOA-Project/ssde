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

#define POOL_ZERO_DOWN_LEVEL_SUPPORT

PVOID
NTAPI
ExAllocatePoolZero(
    _In_ __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag);

PVOID
NTAPI
ExAllocatePoolQuotaZero(
    _In_ __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag);

PVOID
NTAPI
ExAllocatePoolPriorityZero(
    _In_ __drv_strictTypeMatch(__drv_typeExpr) POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag,
    _In_ EX_POOL_PRIORITY Priority);

EXTERN_C_END
