#pragma once

#include <fwpmtypes.h>
#include <fwptypes.h>
#include <fwpvi.h>
#include <vector>
#include <windows.h>

#define APP_NAME L"killswitchsample"
#define APP_NAME_SHORT L"killswitchsample"
#define FILTER_NAME_BLOCK_CONNECTION L"BlockConnection"
#define FILTER_NAME_BLOCK_CONNECTION_REDIRECT L"BlockConnectionRedirect"

#define EXIT_ON_ERROR(fnName) \
   if (result != ERROR_SUCCESS) \
   { \
      printf(#fnName " = 0x%08X\n", result); \
      goto CLEANUP; \
   }

const GUID ProviderKey =
{
   0x5fb216a8,
   0xe2e8,
   0x4024,
   { 0xb8, 0x53, 0x39, 0x1a, 0x41, 0x68, 0x64, 0x1e }
};

// {827E8AD5-7106-4D6B-B921-DA861F65ACFF}
const GUID SublayerKey =
{ 0x827e8ad5, 0x7106, 0x4d6b, { 0xb9, 0x21, 0xda, 0x86, 0x1f, 0x65, 0xac, 0xff } };


#define SESSION_NAME L"SDK Examples"

class WfpProvider
{
private:
    HANDLE m_engine = NULL;
    std::vector<GUID> m_filderIds;
private:
    void ConfigOutboundTraffic(bool isBlock);
    unsigned long Createfilter(_In_ HANDLE hengine, _In_opt_ LPCWSTR name,
        _In_count_(count) FWPM_FILTER_CONDITION* lpcond, _In_ UINT32 count, _In_ UINT8 weight,
        _In_opt_ LPCGUID layer_id, _In_opt_ LPCGUID callout_id, _In_ FWP_ACTION_TYPE action,
        _In_ UINT32 flags, std::vector<GUID> guids);
public:
    DWORD Install();
	
    DWORD Uninstall(
        __in const GUID* providerKey,
        __in const GUID* subLayerKey
    );

    static DWORD FilterByUserAndApp(
        __in HANDLE engine,
        __in PCWSTR filterName,
        __in_opt const GUID* providerKey,
        __in const GUID* layerKey,
        __in_opt const GUID* subLayerKey,
        __in_opt PCWSTR userName,
        __in_opt PCWSTR appPath,
        __in FWP_ACTION_TYPE actionType,
        __out_opt UINT64* filterId
    );
};

