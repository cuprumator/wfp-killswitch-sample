// WFP-killswitch-sample.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
//
#include "WfpProvider.h"

void main()
{
    WfpProvider wfpProvider;
    wfpProvider.Install();
    wfpProvider.CreateAllFilters(std::vector<std::wstring> {L"C:\\Program Files\\Mozilla Firefox\\firefox.exe"});
    wfpProvider.Uninstall(&ProviderKey, &SublayerKey);
}