#include <string>
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <pathcch.h>

#include "log.h"

namespace {
    const auto VersionOffset = 0x2D0241C;
    const auto BuildOffset = 0x2CF1634;
    const char* wowProcessName = "Wow.exe";
}

DWORD GetProcId(const char* procName)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);

        if (Process32First(hSnap, &procEntry))
        {
            do
            {
                if (!_stricmp(procEntry.szExeFile, procName))
                {
                    procId = procEntry.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &procEntry));
        }
    }
    CloseHandle(hSnap);
    return procId;
}

uintptr_t GetModuleBaseAddress(DWORD procId, const char* modName)
{
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry))
        {
            do
            {
                if (!_stricmp(modEntry.szModule, modName))
                {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }
    CloseHandle(hSnap);
    return modBaseAddr;
}

//7ff6e162c7ca

int main(void)
{
    DWORD wowProcessID = 0;
    char morphPath[MAX_PATH] = {};
    GetCurrentDirectory(MAX_PATH, morphPath);
    std::string morphDllPath = std::string(morphPath) + "\\LiMorph.dll";

    LiMorphLoader::Logging::Print(morphDllPath);
    LiMorphLoader::Logging::Print("Will inject as soon as Wow.exe starts.");

    while (!wowProcessID)
    {
        wowProcessID = GetProcId(wowProcessName);
        Sleep(30);
    }

    uintptr_t wowBaseAddress = GetModuleBaseAddress(wowProcessID, wowProcessName);

    uintptr_t gameVersionAddr = wowBaseAddress + VersionOffset;
    uintptr_t gameBuildAddr = wowBaseAddress + BuildOffset;
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, wowProcessID);
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    if (hProc && hProc != INVALID_HANDLE_VALUE)
    {
        char gameVersion[10] = { 0 };
        char gameBuild[10] = { 0 };
        ReadProcessMemory(hProc, (LPVOID)gameVersionAddr, &gameVersion, 10, 0);
        ReadProcessMemory(hProc, (LPVOID)gameBuildAddr, &gameBuild, 10, 0);
        std::string currentVerion = std::string(gameVersion) + "." + std::string(gameBuild);
        std::string supportedVersion = "9.0.5.37899";

        std::string dbgMsg = "Current WoW version: " + currentVerion;
        LiMorphLoader::Logging::Print(dbgMsg);
        dbgMsg = "LiMorph currently supports WoW version: " + supportedVersion;
        LiMorphLoader::Logging::Print(dbgMsg);

        if (currentVerion == supportedVersion) 
        {
            SetConsoleTextAttribute(hConsole, 10);

            LiMorphLoader::Logging::Print("LiMorph was successfully injected.");

            void* morphDllMemoryAddr = VirtualAllocEx(hProc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            WriteProcessMemory(hProc, morphDllMemoryAddr, morphDllPath.c_str(), morphDllPath.size() + 1, 0);
            HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, morphDllMemoryAddr, 0, 0);

            if (hThread)
            {
                CloseHandle(hThread);
            }
            else 
            {
                LiMorphLoader::Logging::Print("ERROR With Create REMOTE THREAD");
            }
        }
        else 
        {
            SetConsoleTextAttribute(hConsole, 12);

            dbgMsg = "LiMorph failed to inject. Currently supports WoW version: " + supportedVersion;
            LiMorphLoader::Logging::Print(dbgMsg);
        }

        CloseHandle(hProc);
    }
    else 
    {
        LiMorphLoader::Logging::Print("OPEN WOW PROCESS ERROR");
    }

    SetConsoleTextAttribute(hConsole, 15);
    LiMorphLoader::Logging::Print("Press enter to exit window." );
    std::getchar();

    return 0;
}
