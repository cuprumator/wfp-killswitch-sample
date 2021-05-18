#include "pch.h"

#include "WfpProvider.h"

#include <combaseapi.h>

#include <ScopeExit/ScopeExit.h>
#include <exceptxx/PrecondException.h>
#include <exceptxx/Win32Exception.h>

using namespace std;
namespace fs = std::filesystem;

HANDLE WfpProvider::m_engine = nullptr;
std::vector<GUID> WfpProvider::m_filderIds;
std::vector<GUID> WfpProvider::m_AppFilderIds;

std::wstring WfpProvider::m_appName = L"killswitchsample";

const GUID WfpProvider::m_providerKey = {
	0x5fb216a8,
	0xe2e8,
	0x4024,
	{ 0xb8, 0x53, 0x39, 0x1a, 0x41, 0x68, 0x64, 0x1e }
};

const GUID WfpProvider::m_sublayerKey = {
	0x827e8ad5,
	0x7106,
	0x4d6b,
	{ 0xb9, 0x21, 0xda, 0x86, 0x1f, 0x65, 0xac, 0xff }
};

void WfpProvider::Install()
{
    DWORD result = ERROR_SUCCESS;
    FWPM_SESSION0 session;

    memset(&session, 0, sizeof(session));
    session.txnWaitTimeoutInMSec = INFINITE;
    session.displayData.name = m_appName.data();
    session.displayData.description = m_appName.data();

    // The authentication service should always be RPC_C_AUTHN_DEFAULT.
    CHECK_WIN32(FwpmEngineOpen0(
	    nullptr,
        RPC_C_AUTHN_DEFAULT,
	    nullptr,
        &session,
        &m_engine));
  
    CHECK_WIN32(FwpmTransactionBegin0(m_engine, 0));
    SCOPE_EXIT
    {
        CHECK_WIN32(FwpmTransactionCommit0(m_engine));
    };
	
    FWPM_PROVIDER0 provider;

    memset(&provider, 0, sizeof(provider));
    provider.providerKey = m_providerKey;
    provider.displayData.name = m_appName.data();
    provider.displayData.description = m_appName.data();

    result = FwpmProviderAdd0(m_engine, &provider, nullptr);
    // Ignore FWP_E_ALREADY_EXISTS
    CHECK_PRECOND(result == ERROR_SUCCESS || result == FWP_E_ALREADY_EXISTS);

    FWPM_SUBLAYER0 subLayer;

    memset(&subLayer, 0, sizeof(subLayer));

    subLayer.displayData.name = m_appName.data();
    subLayer.displayData.description = m_appName.data();
    subLayer.subLayerKey = m_sublayerKey;
    subLayer.providerKey = const_cast<GUID*>(&m_providerKey);
    subLayer.weight = 0xFFFE;

    result = FwpmSubLayerAdd0(m_engine, &subLayer, nullptr);
    CHECK_PRECOND(result == ERROR_SUCCESS || result == FWP_E_ALREADY_EXISTS);
}

void WfpProvider::Uninstall()
{
    DWORD result = ERROR_SUCCESS;
    FWPM_SESSION0 session;

    SCOPE_EXIT
    {
       CHECK_WIN32(FwpmEngineClose0(m_engine));
    };

    memset(&session, 0, sizeof(session));
    session.txnWaitTimeoutInMSec = INFINITE;

    CHECK_WIN32(FwpmTransactionBegin0(m_engine, 0));

    result = FwpmSubLayerDeleteByKey0(m_engine, &m_sublayerKey);
    CHECK_PRECOND(result == FWP_E_SUBLAYER_NOT_FOUND || result == ERROR_SUCCESS);

    result = FwpmProviderDeleteByKey0(m_engine, &m_providerKey);
    CHECK_PRECOND(result == FWP_E_PROVIDER_NOT_FOUND || result == ERROR_SUCCESS);

    CHECK_WIN32(FwpmTransactionCommit0(m_engine));
}

DWORD WfpProvider::CreateFilter(_In_ HANDLE hengine, _In_opt_ LPCWSTR name,
                                _In_count_(count) FWPM_FILTER_CONDITION* lpcond, _In_ UINT32 count, _In_ UINT8 weight,
                                _In_opt_ LPCGUID layer_id, _In_opt_ LPCGUID callout_id, _In_ FWP_ACTION_TYPE action,
                                _In_ UINT32 flags, vector<GUID> guids)
{
    FWPM_FILTER filter = { 0 };

    wstring filter_name;
    wstring filter_description;
    UINT64 filter_id;
    ULONG code;

    // create filter guid
    auto hr = CoCreateGuid(&filter.filterKey);

    if (FAILED(hr))
    {
        return hr;
    }

    filter_name = m_appName;
	
    if (name) 
    {
        filter_description = m_appName + wstring(name);
    }

    filter.flags |= FWPM_FILTER_FLAG_INDEXED;

    if (flags)
    {
        filter.flags |= flags;
    }

    filter.displayData.name = _wcsdup(filter_name.c_str());
    filter.displayData.description = _wcsdup(filter_description.c_str());
    filter.providerKey = const_cast<LPGUID>(&m_providerKey);
    filter.subLayerKey = m_sublayerKey;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = weight;
    filter.action.type = action;

    if (count)
    {
        filter.numFilterConditions = count;
        filter.filterCondition = lpcond;
    }

    if (layer_id)
    {
        memcpy(&filter.layerKey, layer_id, sizeof(GUID));
    }

    if (callout_id)
    {
        memcpy(&filter.action.calloutKey, callout_id, sizeof(GUID));
    }

    code = FwpmFilterAdd(hengine, &filter, nullptr, &filter_id);
    CHECK_WIN32(code);
	
    guids.push_back(filter.filterKey);

    return code;
}


void WfpProvider::ConfigOutboundTraffic(bool isBlock)
{
    FWPM_FILTER_CONDITION fwfc[3] = { 0 };

    // add loopback connections permission

    fwfc[0].fieldKey = FWPM_CONDITION_FLAGS;
    fwfc[0].matchType = FWP_MATCH_FLAGS_ALL_SET;
    fwfc[0].conditionValue.type = FWP_UINT32;
    fwfc[0].conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
    fwfc[0].matchType = FWP_MATCH_FLAGS_ANY_SET;
    fwfc[0].conditionValue.uint32 |= FWP_CONDITION_FLAG_IS_APPCONTAINER_LOOPBACK;

    CreateFilter(m_engine, nullptr, fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);
    CreateFilter(m_engine, nullptr, fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);
                           
    // win7+               
    CreateFilter(m_engine, nullptr, fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);
    CreateFilter(m_engine, nullptr, fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);
                           
    CreateFilter(m_engine, nullptr, fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);
    CreateFilter(m_engine, nullptr, fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);
                           
    CreateFilter(m_engine, nullptr, fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);
    CreateFilter(m_engine, nullptr, fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);

    // ipv4/ipv6 loopback
    vector<wstring> ipList = {
        L"0.0.0.0/8",
        L"10.0.0.0/8",
        L"100.64.0.0/10",
        L"127.0.0.0/8",
        L"169.254.0.0/16",
        L"172.16.0.0/12",
        L"192.0.0.0/24",
        L"192.0.2.0/24",
        L"192.88.99.0/24",
        L"192.168.0.0/16",
        L"198.18.0.0/15",
        L"198.51.100.0/24",
        L"203.0.113.0/24",
        L"224.0.0.0/4",
        L"240.0.0.0/4",
        L"255.255.255.255/32",
        L"[::]/0",
        L"[::]/128",
        L"[::1]/128",
        L"[::ffff:0:0]/96",
        L"[::ffff:0:0:0]/96",
        L"[64:ff9b::]/96",
        L"[100::]/64",
        L"[2001::]/32",
        L"[2001:20::]/28",
        L"[2001:db8::]/32",
        L"[2002::]/16",
        L"[fc00::]/7",
        L"[fe80::]/10",
        L"[ff00::]/8"
    };

	// process address list

    ULONG types = NET_STRING_ANY_ADDRESS | NET_STRING_ANY_SERVICE | NET_STRING_IP_NETWORK | NET_STRING_ANY_ADDRESS_NO_SCOPE | NET_STRING_ANY_SERVICE_NO_SCOPE;

    USHORT port;
    BYTE prefix_length;

    NET_ADDRESS_INFO ni;
	
	for(const auto& ip: ipList)
	{
		const auto code = ParseNetworkString(ip.c_str(), types, &ni, &port, &prefix_length);

        if (code != ERROR_SUCCESS)
        {
	        continue;
        }

        fwfc[1].matchType = FWP_MATCH_EQUAL;
		
        if (ni.Format == NET_ADDRESS_IPV4)
        {
            FWP_V4_ADDR_AND_MASK addr4;
            memset(&addr4, 0, sizeof(addr4));
        	
            ULONG mask = 0;
        	
            if (ConvertLengthToIpv4Mask(prefix_length, &mask) == NOERROR)
            {
                mask = _byteswap_ulong(mask);
            }

            addr4.addr = _byteswap_ulong(ni.Ipv4Address.sin_addr.S_un.S_addr);
            addr4.mask = mask;

            fwfc[1].conditionValue.type = FWP_V4_ADDR_MASK;
            fwfc[1].conditionValue.v4AddrMask = &addr4;

            fwfc[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        	
            CreateFilter(m_engine, nullptr, fwfc, 2, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);
            // win7+
            CreateFilter(m_engine, nullptr, fwfc, 2, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);

            fwfc[1].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
            CreateFilter(m_engine, nullptr, fwfc, 2, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);
            CreateFilter(m_engine, nullptr, fwfc, 2, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);
        }
        else if (ni.Format == NET_ADDRESS_IPV6)
        {
            FWP_V6_ADDR_AND_MASK addr6;
            memset(&addr6, 0, sizeof(addr6));
        	
            memcpy(addr6.addr, ni.Ipv6Address.sin6_addr.u.Byte, FWP_V6_ADDR_SIZE);
            addr6.prefixLength = min(prefix_length, 128);

            fwfc[1].conditionValue.type = FWP_V6_ADDR_MASK;
            fwfc[1].conditionValue.v6AddrMask = &addr6;

            fwfc[1].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;

            CreateFilter(m_engine, nullptr, fwfc, 2, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);

            // win7+
            CreateFilter(m_engine, nullptr, fwfc, 2, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);

            fwfc[1].fieldKey = FWPM_CONDITION_IP_LOCAL_ADDRESS;
            CreateFilter(m_engine, nullptr, fwfc, 2, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);
            CreateFilter(m_engine, nullptr, fwfc, 2, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);
        }
		
	}

    // firewall service rules
    // https://msdn.microsoft.com/en-us/library/gg462153.aspx
    {
        // allows 6to4 tunneling, which enables ipv6 to run over an ipv4 network
        fwfc[0].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        fwfc[0].matchType = FWP_MATCH_EQUAL;
        fwfc[0].conditionValue.type = FWP_UINT8;
        fwfc[0].conditionValue.uint8 = IPPROTO_IPV6; // ipv6 header

        CreateFilter(m_engine,L"Allow6to4", fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);

        // allows icmpv6 router solicitation messages, which are required for the ipv6 stack to work properly
        fwfc[0].fieldKey = FWPM_CONDITION_ICMP_TYPE;
        fwfc[0].matchType = FWP_MATCH_EQUAL;
        fwfc[0].conditionValue.type = FWP_UINT16;
        fwfc[0].conditionValue.uint16 = 0x85;

        CreateFilter(m_engine, L"AllowIcmpV6Type133", fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);

        // allows icmpv6 router advertise messages, which are required for the ipv6 stack to work properly
        fwfc[0].conditionValue.uint16 = 0x86;
        CreateFilter(m_engine, L"AllowIcmpV6Type134", fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);

        // allows icmpv6 neighbor solicitation messages, which are required for the ipv6 stack to work properly
        fwfc[0].conditionValue.uint16 = 0x87;
        CreateFilter(m_engine,  L"AllowIcmpV6Type135", fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);

        // allows icmpv6 neighbor advertise messages, which are required for the ipv6 stack to work properly
        fwfc[0].conditionValue.uint16 = 0x88;
        CreateFilter(m_engine, L"AllowIcmpV6Type136", fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);
    }

    // prevent port scanning using stealth discards and silent drops
    // https://docs.microsoft.com/ru-ru/windows/desktop/FWP/preventing-port-scanning
    {
        // blocks udp port scanners
        fwfc[0].fieldKey = FWPM_CONDITION_FLAGS;
        fwfc[0].matchType = FWP_MATCH_FLAGS_NONE_SET;
        fwfc[0].conditionValue.type = FWP_UINT32;
        fwfc[0].conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;

        // tests if the network traffic is (non-)app container loopback traffic (win8+)
        fwfc[0].conditionValue.uint32 |= FWP_CONDITION_FLAG_IS_APPCONTAINER_LOOPBACK;

        fwfc[1].fieldKey = FWPM_CONDITION_ICMP_TYPE;
        fwfc[1].matchType = FWP_MATCH_EQUAL;
        fwfc[1].conditionValue.type = FWP_UINT16;
        fwfc[1].conditionValue.uint16 = 0x03; // destination unreachable

        CreateFilter(m_engine, FILTER_NAME_ICMP_ERROR, fwfc, 2, FILTER_WEIGHT_HIGHEST, &FWPM_LAYER_OUTBOUND_ICMP_ERROR_V4, nullptr, FWP_ACTION_BLOCK, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, m_filderIds);
        CreateFilter(m_engine, FILTER_NAME_ICMP_ERROR, fwfc, 2, FILTER_WEIGHT_HIGHEST, &FWPM_LAYER_OUTBOUND_ICMP_ERROR_V6, nullptr, FWP_ACTION_BLOCK, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, m_filderIds);

        // blocks tcp port scanners (exclude loopback)
        fwfc[0].conditionValue.uint32 |= FWP_CONDITION_FLAG_IS_IPSEC_SECURED;

        CreateFilter(m_engine, FILTER_NAME_TCP_RST_ONCLOSE, fwfc, 1, FILTER_WEIGHT_HIGHEST, &FWPM_LAYER_INBOUND_TRANSPORT_V4_DISCARD, &FWPM_CALLOUT_WFP_TRANSPORT_LAYER_V4_SILENT_DROP, FWP_ACTION_CALLOUT_TERMINATING, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, m_filderIds);
        CreateFilter(m_engine, FILTER_NAME_TCP_RST_ONCLOSE, fwfc, 1, FILTER_WEIGHT_HIGHEST, &FWPM_LAYER_INBOUND_TRANSPORT_V6_DISCARD, &FWPM_CALLOUT_WFP_TRANSPORT_LAYER_V6_SILENT_DROP, FWP_ACTION_CALLOUT_TERMINATING, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, m_filderIds);
    }
	
    FWP_ACTION_TYPE action = isBlock ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;

    // configure outbound layer
    CreateFilter(m_engine, FILTER_NAME_BLOCK_CONNECTION, nullptr, 0, FILTER_WEIGHT_LOWEST, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, nullptr, action, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, m_filderIds);
    CreateFilter(m_engine, FILTER_NAME_BLOCK_CONNECTION, nullptr, 0, FILTER_WEIGHT_LOWEST, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, nullptr, action, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, m_filderIds);

    // win7+
    CreateFilter(m_engine, FILTER_NAME_BLOCK_CONNECTION_REDIRECT, nullptr, 0, FILTER_WEIGHT_LOWEST, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, nullptr, action, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, m_filderIds);
    CreateFilter(m_engine, FILTER_NAME_BLOCK_CONNECTION_REDIRECT, nullptr, 0, FILTER_WEIGHT_LOWEST, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, nullptr, action, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, m_filderIds);

    // configure inbound layer
    CreateFilter(m_engine, FILTER_NAME_BLOCK_RECVACCEPT, nullptr, 0, FILTER_WEIGHT_LOWEST, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, nullptr, action, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, m_filderIds);
    CreateFilter(m_engine, FILTER_NAME_BLOCK_RECVACCEPT, nullptr, 0, FILTER_WEIGHT_LOWEST, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, nullptr, action, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, m_filderIds);
}

void WfpProvider::ApplyConditionalFilters(const wstring& appPath, UINT8 protocol = 0, const wstring& remoteRule = L"", const wstring& localRule = L"")
{
    UINT32 count = 0;
    FWPM_FILTER_CONDITION fwfc[8] = { 0 };
    FWP_BYTE_BLOB* fwpApplicationByteBlob = nullptr;

    if (!appPath.empty())
    {
        fwpApplicationByteBlob = (FWP_BYTE_BLOB*)malloc(sizeof(FWP_BYTE_BLOB));
        CHECK_WIN32(FwpmGetAppIdFromFileName0(appPath.c_str(), &fwpApplicationByteBlob));
    	
        fwfc[count].fieldKey = FWPM_CONDITION_ALE_APP_ID;
        fwfc[count].matchType = FWP_MATCH_EQUAL;
        fwfc[count].conditionValue.type = FWP_BYTE_BLOB_TYPE;
        fwfc[count].conditionValue.byteBlob = fwpApplicationByteBlob;

        count += 1;
    }

    const vector<wstring> rules = { remoteRule, localRule };

    for (const auto& rule : rules)
    {
        if (rule.empty())
        {
            continue;
        }

        const auto port = static_cast<UINT16>(stoi(rule));

        fwfc[count].fieldKey = ((count == 1) ? FWPM_CONDITION_IP_REMOTE_PORT : FWPM_CONDITION_IP_LOCAL_PORT);
        fwfc[count].matchType = FWP_MATCH_EQUAL;
        fwfc[count].conditionValue.type = FWP_UINT16;
        fwfc[count].conditionValue.uint16 = port;

        count += 1;
    }

    if (protocol)
    {
        fwfc[count].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
        fwfc[count].matchType = FWP_MATCH_EQUAL;
        fwfc[count].conditionValue.type = FWP_UINT8;
        fwfc[count].conditionValue.uint8 = protocol;

        count += 1;
    }
	
    FWP_ACTION_TYPE action = FWP_ACTION_PERMIT;

	// weight for app filter
    const UINT8 weight = 0x09;

    const wstring path_string{ fs::path(appPath).filename().wstring() };
    const auto* name = path_string.c_str();
	
	// outbound layer filter
	// permit ipv4 for app
    CreateFilter(m_engine, name, fwfc, count, weight, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, nullptr, action, 0, m_AppFilderIds);

    // win7+
    CreateFilter(m_engine, name, fwfc, count, weight, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, nullptr, action, 0, m_AppFilderIds);
   
    // permit ipv6 for app
    CreateFilter(m_engine, name, fwfc, count, weight, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, nullptr, action, 0, m_AppFilderIds);

    // win7+
    CreateFilter(m_engine, name, fwfc, count, weight, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, nullptr, action, 0, m_AppFilderIds);

	// inbound layer filter
    CreateFilter(m_engine, name, fwfc, count, weight, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, nullptr, action, 0, m_AppFilderIds);
    CreateFilter(m_engine, name, fwfc, count, weight, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, nullptr, action, 0, m_AppFilderIds);

    if (fwpApplicationByteBlob)
    {
        FwpmFreeMemory0(reinterpret_cast<void**>(&fwpApplicationByteBlob));
    }
}

void WfpProvider::CreateAllFilters(vector<wstring> appsToPermit)
{
    CHECK_WIN32(FwpmTransactionBegin0(m_engine, 0));

    SCOPE_EXIT
    {
        CHECK_WIN32(FwpmTransactionCommit0(m_engine));
    };

	// internal filter rules
    ConfigOutboundTraffic(true);

	for(const auto& path: appsToPermit)
	{
        ApplyConditionalFilters(path);
	}

	// apply system filter rules for DNS
    ApplyConditionalFilters(L"C:\\Windows\\System32\\\ntoskrnl.exe", '\x11', L"53");
    ApplyConditionalFilters(L"C:\\Windows\\System32\\svchost.exe", '\x11',L"53");

    ApplyConditionalFilters(L"", '\x11', L"53");
}

DWORD WfpProvider::DeleteAllFilters()
{
    DWORD result = ERROR_SUCCESS;
	for (auto filterId : m_filderIds)
	{
        result = FwpmFilterDeleteByKey(m_engine, &filterId);
	}

    m_filderIds.clear();

    return result;
}
