#include <tchar.h>
#include <stdio.h>
#include <windows.h>
#include <winternl.h>
#include "OwnedResource.hpp"
#include "ProductPolicy.hpp"
#include "ProductPolicyParser.hpp"

#pragma comment(lib, "ntdll.lib")

struct GenericHandleTraits
{
    using HandleType = HANDLE;
    static inline const HandleType InvalidValue = NULL;
    static constexpr auto &Releasor = CloseHandle;
};

struct RegistryKeyTraits
{
    using HandleType = HKEY;
    static inline const HandleType InvalidValue = NULL;
    static constexpr auto &Releasor = RegCloseKey;
};

int
EnableCksSetupMode()
{
    LSTATUS Status;
    OwnedResource<RegistryKeyTraits> hKey;
    DWORD ValueType;
    DWORD ValueSize;
    ProductPolicy Policy;

    Status = RegOpenKeyEx(
        HKEY_LOCAL_MACHINE,
        TEXT("SYSTEM\\CurrentControlSet\\Control\\ProductOptions"),
        NULL,
        KEY_READ | KEY_WRITE,
        hKey.GetAddress());
    if (Status != ERROR_SUCCESS)
    {
        _tprintf_s(
            TEXT("[-] Failed to open \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\ProductOptions\". CODE: 0x%.8X\n"),
            Status);
        return -1;
    }
    else
    {
        _tprintf_s(TEXT("[+] Succeeded to open \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\ProductOptions\".\n"));
    }

    Status = RegQueryValueEx(hKey, TEXT("ProductPolicy"), NULL, &ValueType, NULL, &ValueSize);
    if (Status != ERROR_SUCCESS)
    {
        _tprintf_s(TEXT("[-] Failed to get size of \"ProductPolicy\" value. CODE: 0x%.8X\n"), Status);
        return -1;
    }
    else
    {
        _tprintf_s(
            TEXT("[+] Succeeded to get size of \"ProductPolicy\" value. SIZE: %d(0x%.8X)\n"), ValueSize, ValueSize);
    }

    if (ValueType != REG_BINARY)
    {
        _tprintf_s(TEXT("[-] The type of \"ProductPolicy\" value mismatches. Abort!\n"));
        return -1;
    }

    std::vector<uint8_t> Value(ValueSize);

    Status = RegQueryValueEx(hKey, TEXT("ProductPolicy"), NULL, &ValueType, Value.data(), &ValueSize);
    if (Status != ERROR_SUCCESS)
    {
        _tprintf_s(TEXT("[-] Failed to get \"ProductPolicy\" value data. CODE: 0x%.8x\n"), Status);
        return -1;
    }
    else
    {
        _tprintf_s(TEXT("[+] Succeeded to get \"ProductPolicy\" value data.\n"));
    }

    try
    {
        Policy = ProductPolicyParser::FromBinary(Value);
    }
    catch (std::exception &ex)
    {
        _tprintf_s(
            TEXT("[-] Failed to parse \"ProductPolicy\" value.\n"
                 "    REASON: %hs\n"),
            ex.what());
        return -1;
    }

    // Policy[L"CodeIntegrity-AllowConfigurablePolicy"].GetData<PolicyValue::TypeOfUInt32>() = 1;
    //_tprintf_s(TEXT("[*] Enable CodeIntegrity-AllowConfigurablePolicy\n"));

    Policy[L"CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners"].GetData<PolicyValue::TypeOfUInt32>() = 1;
    _tprintf_s(TEXT("[*] Enable CodeIntegrity-AllowConfigurablePolicy-CustomKernelSigners\n"));

    try
    {
        Value = ProductPolicyParser::ToBinary(Policy);
    }
    catch (std::exception &ex)
    {
        _tprintf_s(
            TEXT("[-] Failed to parse Policy to binary.\n"
                 "    REASON: %hs\n"),
            ex.what());
        return -1;
    }

    Status =
        RegSetValueEx(hKey, TEXT("ProductPolicy"), NULL, REG_BINARY, Value.data(), static_cast<DWORD>(Value.size()));
    if (Status != ERROR_SUCCESS)
    {
        _tprintf_s(TEXT("[-] Failed to set \"ProductPolicy\" value, CODE: 0x%.8x\n"), Status);
        return -1;
    }
    else
    {
        _tprintf_s(TEXT("[+] Succeeded to set \"ProductPolicy\" value.\n"));
    }

    _tprintf_s(TEXT("[*] Checking......\n"));
    SleepEx(1000, FALSE);

    Status = RegQueryValueEx(hKey, TEXT("ProductPolicy"), NULL, &ValueType, NULL, &ValueSize);
    if (Status != ERROR_SUCCESS)
    {
        _tprintf_s(TEXT("[-] Failed to get size of \"ProductPolicy\" value. CODE: 0x%.8X\n"), Status);
        return -1;
    }

    std::vector<uint8_t> Value2(ValueSize);

    Status = RegQueryValueEx(hKey, TEXT("ProductPolicy"), NULL, &ValueType, Value2.data(), &ValueSize);
    if (Status != ERROR_SUCCESS)
    {
        _tprintf_s(TEXT("[-] Failed to get \"ProductPolicy\" value data. CODE: 0x%.8x\n"), Status);
        return -1;
    }

    if (Value.size() == Value2.size() && memcmp(Value.data(), Value2.data(), Value2.size()) == 0)
    {
        _tprintf_s(TEXT("[+] Checking...... Pass!\n"));
    }
    else
    {
        _tprintf_s(TEXT("[-] Checking...... Fail! Are you sure you are in Setup Mode?\n"));
        return -1;
    }

    hKey.Release();

    return 0;
}

int
_tmain(int argc, PTSTR argv[])
{
    return EnableCksSetupMode();
}
