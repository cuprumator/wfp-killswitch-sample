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

class WfpProvider
{
private:
    static HANDLE m_engine;
    static std::vector<GUID> m_filderIds;
    static std::vector<GUID> m_AppFilderIds;
    static std::wstring m_appName;
    static const GUID m_providerKey;
    static const GUID m_sublayerKey;

private:
    static void ConfigOutboundTraffic(bool isBlock);
    static void ApplyConditionalFilters(const std::wstring& appPath, UINT8 protocol, const std::wstring& remoteRule, const std::wstring& localRule);
    static DWORD CreateFilter(_In_ HANDLE hengine, _In_opt_ LPCWSTR name,
                              _In_count_(count) FWPM_FILTER_CONDITION* lpcond, _In_ UINT32 count, _In_ UINT8 weight,
                              _In_opt_ LPCGUID layer_id, _In_opt_ LPCGUID callout_id, _In_ FWP_ACTION_TYPE action,
                              _In_ UINT32 flags, std::vector<GUID> guids);
public:
    static void Install();
    static void Uninstall();
    static void CreateAllFilters(std::vector<std::wstring> appsToPermit);
    static DWORD DeleteAllFilters();
};


