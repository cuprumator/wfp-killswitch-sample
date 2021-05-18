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
		//ignore for now
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
		//ignore for now
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
		//ignore for now
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
		//ignore for now
	}
}
