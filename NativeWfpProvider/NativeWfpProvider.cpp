#include "pch.h"
#include "NativeWfpProvider.h"
#include "WfpProvider.h"

void InitProvider()
{
	try
	{
		WfpProvider::Install();
	}
	catch (...)
	{
		//ignore fore now
	}
}

void EnableInternet()
{
	try
	{
		WfpProvider::DeleteAllFilters();
	}
	catch (...)
	{
		//ignore fore now
	}
	
}

void DisableInternet(wchar_t** apps, int appCount)
{
	try
	{
		std::vector<std::wstring> appsVector(apps, apps + appCount);
		WfpProvider::CreateAllFilters(appsVector);
	}
	catch (...)
	{
		//ignore fore now
	}
}

void UninitProvider()
{
	try
	{
		WfpProvider::Uninstall();
	}
	catch (...)
	{
		//ignore fore now
	}
}
