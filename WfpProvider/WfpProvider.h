#pragma once

#include <fwpmtypes.h>
#include <fwptypes.h>
#include <fwpvi.h>

#include <accctrl.h>
#include <aclapi.h>
#include <stdio.h>
#include <fwpmu.h>

#include <string>
#include <vector>
#include <filesystem>

#define APP_NAME_SHORT L"killswitchsample"

#define FILTER_NAME_ICMP_ERROR L"BlockIcmpError"
#define FILTER_NAME_TCP_RST_ONCLOSE L"BlockTcpRstOnClose"
#define FILTER_NAME_BLOCK_CONNECTION L"BlockConnection"
#define FILTER_NAME_BLOCK_CONNECTION_REDIRECT L"BlockConnectionRedirect"
#define FILTER_NAME_BLOCK_RECVACCEPT L"BlockRecvAccept"

// filter weights
#define FILTER_WEIGHT_HIGHEST_IMPORTANT 0x0F
#define FILTER_WEIGHT_HIGHEST 0x0E
#define FILTER_WEIGHT_BLOCKLIST 0x0D
#define FILTER_WEIGHT_CUSTOM_BLOCK 0x0C
#define FILTER_WEIGHT_CUSTOM 0x0B
#define FILTER_WEIGHT_SYSTEM 0x0A
#define FILTER_WEIGHT_APPLICATION 0x09
#define FILTER_WEIGHT_LOWEST 0x08

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
    static HANDLE m_engine;
    static std::vector<GUID> m_filderIds;
    static std::vector<GUID> m_AppFilderIds;
    static std::wstring m_appName;

private:
    static void ConfigOutboundTraffic(bool isBlock);
    static void ApplyConditionalFilters(const std::wstring& appPath, UINT8 protocol, const std::wstring& remoteRule, const std::wstring& localRule);
    static unsigned long Createfilter(_In_ HANDLE hengine, _In_opt_ LPCWSTR name,
        _In_count_(count) FWPM_FILTER_CONDITION* lpcond, _In_ UINT32 count, _In_ UINT8 weight,
        _In_opt_ LPCGUID layer_id, _In_opt_ LPCGUID callout_id, _In_ FWP_ACTION_TYPE action,
        _In_ UINT32 flags, std::vector<GUID> guids);
public:
    static DWORD Install();
	
    static DWORD Uninstall(
        __in const GUID* providerKey,
        __in const GUID* subLayerKey
    );
	
    static void CreateAllFilters(std::vector<std::wstring> appsToPermit);
};


