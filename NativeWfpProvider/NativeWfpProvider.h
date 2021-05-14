#pragma once

extern "C" {
    __declspec(dllexport) void InitProvider();
    __declspec(dllexport) void EnableInternet();
    __declspec(dllexport) void DisableInternet(wchar_t** apps, int appCount);
    __declspec(dllexport) void UninitProvider();
}