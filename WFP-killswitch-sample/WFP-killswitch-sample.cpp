// WFP-killswitch-sample.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
//
#include <stdio.h>
#include <stddef.h>
#include <wchar.h>
#include <iostream>
#include <Windows.h>
#include <fwpmu.h>
#include <initguid.h>
#include <rpc.h>
#include "strsafe.h"


// {D5CF2E11-B7F6-41E7-BF5B-BF241471E414}
DEFINE_GUID(GUID_WfpSublayer, 0xd5cf2e11, 0xb7f6, 0x41e7, 0xbf, 0x5b, 0xbf, 0x24, 0x14, 0x71, 0xe4, 0x14);

#pragma comment(lib, "Rpcrt4.lib")

void main()
{
    HANDLE engineHandle = nullptr;
    DWORD  result = ERROR_SUCCESS;

    FWPM_SESSION0 session;
	
    RtlZeroMemory(&session, sizeof(FWPM_SESSION0));

    session.displayData.name = _wcsdup(L"MSN MsnFltr Session");
    session.displayData.description = _wcsdup(L"MsnFltr");

    // Let the Base Firewall Engine cleanup after us.
    //session.flags = FWPM_SESSION_FLAG_DYNAMIC;

    result = FwpmEngineOpen0(
        NULL,
        RPC_C_AUTHN_WINNT,
        NULL,
        &session,
        &engineHandle);

    if (result != ERROR_SUCCESS)
        printf("FwpmEngineOpen0 failed. Return value: %d.\n", result);
    else
        printf("Filter engine opened successfully.\n");

    FWPM_SUBLAYER0   fwpFilterSubLayer;
    RtlZeroMemory(&fwpFilterSubLayer, sizeof(fwpFilterSubLayer));
	
    RPC_STATUS rpcStatus = RPC_S_OK;
    rpcStatus = UuidCreate(&fwpFilterSubLayer.subLayerKey);

    if (RPC_S_OK != rpcStatus)
    {
        printf("UuidCreate failed (%d).\n", rpcStatus);
        return;
    }
	
    fwpFilterSubLayer.displayData.name = _wcsdup(L"MyFilterSublayer");
    fwpFilterSubLayer.displayData.description = _wcsdup(L"My filter sublayer");
    fwpFilterSubLayer.flags = 0;
    fwpFilterSubLayer.weight = 0x100;

    printf("Adding filter sublayer.\n");
    result = FwpmSubLayerAdd0(engineHandle, &fwpFilterSubLayer, NULL);

    if (result != ERROR_SUCCESS)
    {
        printf("FwpmSubLayerAdd0 failed (%d).\n", result);
        return;
    }

    FWPM_FILTER0 fwpFilter;

    RtlZeroMemory(&fwpFilter, sizeof(FWPM_FILTER0));

    fwpFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    fwpFilter.action.type = FWP_ACTION_BLOCK;
    fwpFilter.subLayerKey = fwpFilterSubLayer.subLayerKey;
    fwpFilter.weight.type = FWP_EMPTY; // auto-weight.
    //fwpFilter.weight.uint8 = 1; // auto-weight.

    fwpFilter.numFilterConditions = 0; // this applies to all application traffic
    fwpFilter.displayData.name = _wcsdup(L"Receive/Accept Layer Block");
    fwpFilter.displayData.description = _wcsdup(L"Filter to block all inbound connections.");

    printf("Adding filter to block all inbound connections.\n");
	
    result = FwpmFilterAdd0(engineHandle, &fwpFilter, NULL, NULL);

    if (result != ERROR_SUCCESS) 
        printf("FwpmFilterAdd0 failed. Return value: %d.\n", result);
    else 
        printf("Filter added successfully.\n");


    PCWSTR appPath = _wcsdup(L"C:\\Program Files\\Mozilla Firefox\\firefox.exe");
    FWP_BYTE_BLOB* fwpApplicationByteBlob;
    fwpApplicationByteBlob = (FWP_BYTE_BLOB*)malloc(sizeof(FWP_BYTE_BLOB));
    result = FwpmGetAppIdFromFileName0(appPath, &fwpApplicationByteBlob);
    if (result != ERROR_SUCCESS)
        printf("FwpmGetAppIdFromFileName0 failed. Return value: %d.\n", result);
    else
        printf("FwpmGetAppIdFromFileName0 finished successfully.\n");
	
    FWPM_FILTER_CONDITION0 filterCondition;

    RtlZeroMemory(&filterCondition, sizeof(filterCondition));

    filterCondition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    filterCondition.matchType = FWP_MATCH_EQUAL;
    filterCondition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    filterCondition.conditionValue.byteBlob = fwpApplicationByteBlob;

    RtlZeroMemory(&fwpFilterSubLayer, sizeof(fwpFilterSubLayer));

    rpcStatus = UuidCreate(&fwpFilterSubLayer.subLayerKey);

    if (RPC_S_OK != rpcStatus)
    {
        printf("UuidCreate failed (%d).\n", rpcStatus);
        return;
    }
	
    fwpFilterSubLayer.displayData.name = _wcsdup(L"MyFilterSublayer1");
    fwpFilterSubLayer.displayData.description = _wcsdup(L"My filter sublayer1");
    fwpFilterSubLayer.flags = 0;
    fwpFilterSubLayer.weight = 0x100;

    printf("Adding filter sublayer.\n");
    result = FwpmSubLayerAdd0(engineHandle, &fwpFilterSubLayer, NULL);

    if (result != ERROR_SUCCESS)
    {
        printf("FwpmSubLayerAdd0 failed (%d).\n", result);
        return;
    }
	
 // RtlZeroMemory(&fwpFilter, sizeof(FWPM_FILTER0));

 //   fwpFilter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    fwpFilter.subLayerKey = fwpFilterSubLayer.subLayerKey;
    fwpFilter.action.type = FWP_ACTION_PERMIT;
  /*  fwpFilter.weight.uint8 = 2;
    fwpFilter.flags = FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT;*/
    fwpFilter.weight.type = FWP_EMPTY;
    fwpFilter.filterCondition = &filterCondition;
    fwpFilter.numFilterConditions = 1;
 //   fwpFilter.displayData.name = _wcsdup(L"Allow Firefox");
 //   fwpFilter.displayData.description = _wcsdup(L"Allow Firefox all inbound connections.");
 //   
 //   filterCondition[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
 //   filterCondition[1].matchType = FWP_MATCH_EQUAL;
 //   filterCondition[1].conditionValue.type = FWP_UINT8;
 //   filterCondition[1].conditionValue.uint8 = IPPROTO_TCP;

    result = FwpmFilterAdd0(engineHandle, &fwpFilter, NULL, NULL);

    if (result != ERROR_SUCCESS)
        printf("FwpmFilterAdd0 failed. Return value: %d.\n", result);
    else
        printf("Filter added successfully.\n");

    //RtlZeroMemory(&fwpFilter, sizeof(FWPM_FILTER0));

    //fwpFilter.layerKey = FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
    //fwpFilter.action.type = FWP_ACTION_PERMIT;
    //fwpFilter.subLayerKey = fwpFilterSubLayer.subLayerKey;
    //fwpFilter.weight.type = FWP_EMPTY;
    //fwpFilter.filterCondition = &Condition;
    //fwpFilter.numFilterConditions = 1;
    //fwpFilter.displayData.name = _wcsdup(L"Allow Firefox");
    //fwpFilter.displayData.description = _wcsdup(L"Allow Firefox all inbound connections.");

    //RtlZeroMemory(&Condition, sizeof(Condition));

    //Condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    //Condition.matchType = FWP_MATCH_EQUAL;
    //Condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
    //Condition.conditionValue.byteBlob = fwpApplicationByteBlob;

    //result = FwpmFilterAdd0(engineHandle, &fwpFilter, NULL, NULL);

    //if (result != ERROR_SUCCESS)
    //    printf("FwpmFilterAdd0 failed. Return value: %d.\n", result);
    //else
    //    printf("Filter added successfully.\n");
}