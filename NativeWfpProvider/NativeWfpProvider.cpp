#include "pch.h"
#include "NativeWfpProvider.h"
#include "WfpProvider.h"

void InitProvider()
{
	WfpProvider::Install();
}

void EnableInternet()
{
	WfpProvider::DeleteAllFilters();
}

void DisableInternet(wchar_t** apps, int appCount)
{
	std::vector<std::wstring> appsVector(apps, apps + appCount);
	WfpProvider::CreateAllFilters(appsVector);
}

void UninitProvider()
{
	WfpProvider::Uninstall();
}
