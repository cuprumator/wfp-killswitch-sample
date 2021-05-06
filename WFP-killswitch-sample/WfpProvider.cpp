#include "WfpProvider.h"

using namespace std;
namespace fs = std::filesystem;

DWORD WfpProvider::Install()
{
    DWORD result = ERROR_SUCCESS;
    FWPM_SESSION0 session;

    memset(&session, 0, sizeof(session));
    // The session name isn't required but may be useful for diagnostics.
    //session.displayData.name = SESSION_NAME;
    // Set an infinite wait timeout, so we don't have to handle FWP_E_TIMEOUT
    // errors while waiting to acquire the transaction lock.
    session.txnWaitTimeoutInMSec = INFINITE;
    session.displayData.name = APP_NAME;
    session.displayData.description = APP_NAME;

    // The authentication service should always be RPC_C_AUTHN_DEFAULT.
    result = FwpmEngineOpen0(
	    nullptr,
        RPC_C_AUTHN_DEFAULT,
	    nullptr,
        &session,
        &m_engine
    );
    EXIT_ON_ERROR(FwpmEngineOpen0);

    // We add the provider and sublayer from within a single transaction to make
    // it easy to clean up partial results in error paths.
    result = FwpmTransactionBegin0(m_engine, 0);
    EXIT_ON_ERROR(FwpmTransactionBegin0);

    FWPM_PROVIDER0 provider;

    memset(&provider, 0, sizeof(provider));
    // The provider and sublayer keys are going to be used repeatedly when
    // adding filters and other objects. It's easiest to use well-known GUIDs
    // defined in a header somewhere, rather than having BFE generate the keys.
    provider.providerKey = ProviderKey;
    // For MUI compatibility, object names should be indirect strings. See
    // SHLoadIndirectString for details.
    provider.displayData.name = APP_NAME;
    provider.displayData.description = APP_NAME;
    // Since we always want the provider and sublayer to be present, it's
    // easiest to add them as persistent objects during install.  Alternatively,
    // we could add non-persistent objects every time our service starts.
    //provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;

    result = FwpmProviderAdd0(m_engine, &provider, nullptr);
    // Ignore FWP_E_ALREADY_EXISTS. This allows install to be re-run as needed
    // to repair a broken configuration.
    if (result != FWP_E_ALREADY_EXISTS)
    {
        EXIT_ON_ERROR(FwpmProviderAdd0);
    }

    FWPM_SUBLAYER0 subLayer;

    memset(&subLayer, 0, sizeof(subLayer));

    subLayer.displayData.name = APP_NAME;
    subLayer.displayData.description = APP_NAME;
	
    subLayer.subLayerKey = SublayerKey;
 
    //subLayer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
    // Link all our other objects to our provider. When multiple providers are
    // installed on a computer, this makes it easy to determine who added what.
    subLayer.providerKey = const_cast<GUID*>(&ProviderKey);
    // We don't care what our sublayer weight is, so we pick a weight in the
    // middle and let BFE assign the closest available.
    subLayer.weight = 0xFFFE;

    result = FwpmSubLayerAdd0(m_engine, &subLayer, nullptr);
	
    if (result != FWP_E_ALREADY_EXISTS)
    {
        EXIT_ON_ERROR(FwpmSubLayerAdd0);
    }

    // Once all the adds have succeeded, we commit the transaction to persist
    // the new objects.
    result = FwpmTransactionCommit0(m_engine);
    EXIT_ON_ERROR(FwpmTransactionCommit0);

CLEANUP:
    // FwpmEngineClose0 accepts null m_engine handles, so we needn't precheck for
    // null. Also, when closing an m_engine handle, any transactions still in
    // progress are automatically aborted, so we needn't explicitly abort the
    // transaction in error paths.
    //FwpmEngineClose0(m_engine);
    return result;
}

DWORD WfpProvider::Uninstall(__in const GUID* providerKey, __in const GUID* subLayerKey)
{
    DWORD result = ERROR_SUCCESS;
    FWPM_SESSION0 session;

    memset(&session, 0, sizeof(session));
    // The session name isn't required but may be useful for diagnostics.
    //session.displayData.name = SESSION_NAME;
    // Set an infinite wait timeout, so we don't have to handle FWP_E_TIMEOUT
    // errors while waiting to acquire the transaction lock.
    session.txnWaitTimeoutInMSec = INFINITE;

    // The authentication service should always be RPC_C_AUTHN_DEFAULT.
    result = FwpmEngineOpen0(
	    nullptr,
        RPC_C_AUTHN_DEFAULT,
	    nullptr,
        &session,
        &m_engine
    );
    EXIT_ON_ERROR(FwpmEngineOpen0);

    // We delete the provider and sublayer from within a single transaction, so
    // that we always leave the system in a consistent state even in error
    // paths.
    result = FwpmTransactionBegin0(m_engine, 0);
    EXIT_ON_ERROR(FwpmTransactionBegin0);

    // We have to delete the sublayer first since it references the provider. If
    // we tried to delete the provider first, it would fail with FWP_E_IN_USE.
    result = FwpmSubLayerDeleteByKey0(m_engine, subLayerKey);
    if (result != FWP_E_SUBLAYER_NOT_FOUND)
    {
        // Ignore FWP_E_SUBLAYER_NOT_FOUND. This allows uninstall to succeed even
        // if the current configuration is broken.
        EXIT_ON_ERROR(FwpmSubLayerDeleteByKey0);
    }

    result = FwpmProviderDeleteByKey0(m_engine, providerKey);
    if (result != FWP_E_PROVIDER_NOT_FOUND)
    {
        EXIT_ON_ERROR(FwpmProviderDeleteByKey0);
    }

    // Once all the deletes have succeeded, we commit the transaction to
    // atomically delete all the objects.
    result = FwpmTransactionCommit0(m_engine);
    EXIT_ON_ERROR(FwpmTransactionCommit0);

CLEANUP:
    // FwpmEngineClose0 accepts null m_engine handles, so we needn't precheck for
    // null. Also, when closing an m_engine handle, any transactions still in
    // progress are automatically aborted, so we needn't explicitly abort the
    // transaction in error paths.
    FwpmEngineClose0(m_engine);
    return result;
}

unsigned long WfpProvider::Createfilter(_In_ HANDLE hengine, _In_opt_ LPCWSTR name,
                                _In_count_(count) FWPM_FILTER_CONDITION* lpcond, _In_ UINT32 count, _In_ UINT8 weight,
                                _In_opt_ LPCGUID layer_id, _In_opt_ LPCGUID callout_id, _In_ FWP_ACTION_TYPE action,
                                _In_ UINT32 flags, vector<GUID> guids)
{
    FWPM_FILTER filter = { 0 };

    wstring filter_name;
    UINT64 filter_id;
    ULONG code;

    // create filter guid
    HRESULT hr = CoCreateGuid(&filter.filterKey);

    if (FAILED(hr))
    {
        return hr;
    }

    filter_name = APP_NAME + wstring(name);

    filter.flags |= FWPM_FILTER_FLAG_INDEXED;

    if (flags)
        filter.flags |= flags;

    filter.displayData.name = _wcsdup(filter_name.c_str());
    filter.displayData.description = _wcsdup(filter_name.c_str());
    filter.providerKey = const_cast<LPGUID>(&ProviderKey);
    filter.subLayerKey = SublayerKey;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = weight;
    filter.action.type = action;

    if (count)
    {
        filter.numFilterConditions = count;
        filter.filterCondition = lpcond;
    }

    if (layer_id)
        memcpy(&filter.layerKey, layer_id, sizeof(GUID));

    if (callout_id)
        memcpy(&filter.action.calloutKey, callout_id, sizeof(GUID));

    code = FwpmFilterAdd(hengine, &filter, nullptr, &filter_id);

    if (code == ERROR_SUCCESS)
    {
        guids.push_back(filter.filterKey);
    }

    return code;
}


void WfpProvider::ConfigOutboundTraffic(bool isBlock)
{
    FWP_ACTION_TYPE action = isBlock ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT;

    FWPM_FILTER_CONDITION fwfc[3] = { 0 };

    // add loopback connections permission

    fwfc[0].fieldKey = FWPM_CONDITION_FLAGS;
    fwfc[0].matchType = FWP_MATCH_FLAGS_ALL_SET;
    fwfc[0].conditionValue.type = FWP_UINT32;
    fwfc[0].conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;

    // tests if the network traffic is (non-)app container loopback traffic (win8+)

    {
        fwfc[0].matchType = FWP_MATCH_FLAGS_ANY_SET;
        fwfc[0].conditionValue.uint32 |= FWP_CONDITION_FLAG_IS_APPCONTAINER_LOOPBACK;
    }

    Createfilter(m_engine, nullptr, fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);
    Createfilter(m_engine, nullptr, fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);
                           
    // win7+               
    Createfilter(m_engine, nullptr, fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);
    Createfilter(m_engine, nullptr, fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);
                           
    Createfilter(m_engine, nullptr, fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);
    Createfilter(m_engine, nullptr, fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);
                           
    Createfilter(m_engine, nullptr, fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);
    Createfilter(m_engine, nullptr, fwfc, 1, FILTER_WEIGHT_HIGHEST_IMPORTANT, &FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6, nullptr, FWP_ACTION_PERMIT, 0, m_filderIds);

    // ipv4/ipv6 loopback
    LPCWSTR ip_list[] = {
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

    Createfilter(m_engine, FILTER_NAME_BLOCK_CONNECTION, nullptr, 0, 0x08, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, nullptr, action, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, m_filderIds);
    Createfilter(m_engine, FILTER_NAME_BLOCK_CONNECTION, nullptr, 0, 0x08, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, nullptr, action, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, m_filderIds);

    // win7+
    Createfilter(m_engine, FILTER_NAME_BLOCK_CONNECTION_REDIRECT, nullptr, 0, 0x08, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, nullptr, action, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, m_filderIds);
    Createfilter(m_engine, FILTER_NAME_BLOCK_CONNECTION_REDIRECT, nullptr, 0, 0x08, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, nullptr, action, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, m_filderIds);

    Createfilter(m_engine, FILTER_NAME_BLOCK_RECVACCEPT, nullptr, 0, 0x08, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, nullptr, action, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, m_filderIds);
    Createfilter(m_engine, FILTER_NAME_BLOCK_RECVACCEPT, nullptr, 0, 0x08, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, nullptr, action, FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT, m_filderIds);
}

void WfpProvider::ApplyAppFilters(wstring appPath)
{
    UINT32 count = 0;
    FWPM_FILTER_CONDITION fwfc[8] = { 0 };
    //PCWSTR appPath = _wcsdup(L"C:\\Program Files\\Mozilla Firefox\\firefox.exe");
    FWP_BYTE_BLOB* fwpApplicationByteBlob;
    fwpApplicationByteBlob = (FWP_BYTE_BLOB*)malloc(sizeof(FWP_BYTE_BLOB));
    auto result = FwpmGetAppIdFromFileName0(appPath.c_str(), &fwpApplicationByteBlob);
    if (result == ERROR_SUCCESS)
    {
        fwfc[count].fieldKey = FWPM_CONDITION_ALE_APP_ID;
        fwfc[count].matchType = FWP_MATCH_EQUAL;
        fwfc[count].conditionValue.type = FWP_BYTE_BLOB_TYPE;
        fwfc[count].conditionValue.byteBlob = fwpApplicationByteBlob;

        count += 1;
    }

    auto name = fs::path(appPath).filename().c_str();

    FWP_ACTION_TYPE action = FWP_ACTION_PERMIT;

	// weight for app filter
    const UINT8 weight = 0x09;

	// outbound layer filter
	// permit ipv4 for app
    Createfilter(m_engine, name, fwfc, count, weight, &FWPM_LAYER_ALE_AUTH_CONNECT_V4, nullptr, action, 0, m_AppFilderIds);

    // win7+
    Createfilter(m_engine, name, fwfc, count, weight, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, nullptr, action, 0, m_AppFilderIds);
   
    // permit ipv6 for app
    Createfilter(m_engine, name, fwfc, count, weight, &FWPM_LAYER_ALE_AUTH_CONNECT_V6, nullptr, action, 0, m_AppFilderIds);

    // win7+
    Createfilter(m_engine, name, fwfc, count, weight, &FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, nullptr, action, 0, m_AppFilderIds);

	// inbound layer filter
    Createfilter(m_engine, name, fwfc, count, weight, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, nullptr, action, 0, m_AppFilderIds);
    Createfilter(m_engine, name, fwfc, count, weight, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, nullptr, action, 0, m_AppFilderIds);

    FwpmFreeMemory0(reinterpret_cast<void**>(&fwpApplicationByteBlob));
}

bool DeleteFilter(_In_ HANDLE hengine, _In_ LPCGUID filterId)
{
	const auto code = FwpmFilterDeleteByKey(hengine, filterId);

    return code == ERROR_SUCCESS;
}

void WfpProvider::CreateAllFilters(vector<wstring> appsToPermit)
{
    DWORD result = ERROR_SUCCESS;
	
	result = FwpmTransactionBegin0(m_engine, 0);

	//all code here
    ConfigOutboundTraffic(true);

	for(const auto& path: appsToPermit)
	{
        ApplyAppFilters(path);
	}
	
    result = FwpmTransactionCommit0(m_engine);
}