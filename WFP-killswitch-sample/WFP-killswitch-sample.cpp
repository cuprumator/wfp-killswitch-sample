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
#include "WfpProvider.h"


// {D5CF2E11-B7F6-41E7-BF5B-BF241471E414}
DEFINE_GUID(GUID_WfpSublayer, 0xd5cf2e11, 0xb7f6, 0x41e7, 0xbf, 0x5b, 0xbf, 0x24, 0x14, 0x71, 0xe4, 0x14);

#pragma comment(lib, "Rpcrt4.lib")

void main()
{
    WfpProvider wfpProvider;
    wfpProvider.Install();
    wfpProvider.CreateAllFilters(std::vector<std::wstring> {L"C:\\Program Files\\Mozilla Firefox\\firefox.exe"});
    wfpProvider.Uninstall(&ProviderKey, &SublayerKey);
}