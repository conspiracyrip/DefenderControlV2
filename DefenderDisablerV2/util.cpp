#include "util.hpp"

namespace util
{
  // Converts a string to wide
  //
  std::wstring string_to_wide(const std::string& s)
  {
    std::wstring temp(s.length(), L' ');
    std::copy(s.begin(), s.end(), temp.begin());
    return temp;
  }

  // Converts a wide to string
  //
  std::string wide_to_string(const std::wstring& s) {
    std::string temp(s.length(), ' ');
    std::copy(s.begin(), s.end(), temp.begin());
    return temp;
  }

  // Sets the programs debug priviliges
  //
  bool set_privilege(LPCSTR privilege, BOOL enable)
  {
    TOKEN_PRIVILEGES priv = { 0,0,0,0 };
    HANDLE token = nullptr;
    LUID luid = { 0,0 };

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
    {
      if (token)
        CloseHandle(token);

      return false;
    }

    if (!LookupPrivilegeValueA(nullptr, SE_DEBUG_NAME, &luid))
    {
      if (token)
        CloseHandle(token);

      return false;
    }
    priv.PrivilegeCount = 1;
    priv.Privileges[0].Luid = luid;
    priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(token, false, &priv, 0, nullptr, nullptr))
    {
      if (token)
        CloseHandle(token);

      return false;
    }
    if (token)
      CloseHandle(token);

    return true;
  }

  char sub_43604B()
  {
    char v0; // bl
    SC_HANDLE v1; // eax
    SC_HANDLE v2; // esi
    void* v3; // eax

    v0 = 0;
    v1 = OpenSCManagerW(0, 0, 8u);
    v2 = v1;
    if (v1)
    {
      v3 = LockServiceDatabase(v1);
      if (v3)
      {
        UnlockServiceDatabase(v3);
        CloseServiceHandle(v2);
        return 1;
      }
      if (GetLastError() == 1055)
        v0 = 1;
      CloseServiceHandle(v2);
    }
    return v0;
  }

  // Get current username
  //
  std::string get_user()
  {
    char username[UNLEN + 1];
    DWORD username_len = UNLEN + 1;
    GetUserNameA(username, &username_len);
    return std::string(username);
  }

  // Get current path of process
  //
  std::string get_current_path()
  {
    char buf[256];
    DWORD len = sizeof(buf);
    int bytes = GetModuleFileNameA(NULL, buf, len);
    return std::string(buf);
  }
#pragma comment(lib, "ntdll.lib")

  typedef enum _SYSTEM_INFORMATION_CLASS {
      SystemBasicInformation = 0,
      SystemProcessorInformation = 1,
      SystemPerformanceInformation = 2,
      SystemTimeOfDayInformation = 3,
      SystemPathInformation = 4,
      SystemProcessInformation = 5,
      SystemCallCountInformation = 6,
      SystemDeviceInformation = 7,
      SystemProcessorPerformanceInformation = 8,
      SystemFlagsInformation = 9,
      SystemCallTimeInformation = 10,
      SystemModuleInformation = 11,
      SystemLocksInformation = 12,
      SystemStackTraceInformation = 13,
      SystemPagedPoolInformation = 14,
      SystemNonPagedPoolInformation = 15,
      SystemHandleInformation = 16,
      SystemObjectInformation = 17,
      SystemPageFileInformation = 18,
      SystemVdmInstemulInformation = 19,
      SystemVdmBopInformation = 20,
      SystemFileCacheInformation = 21,
      SystemPoolTagInformation = 22,
      SystemInterruptInformation = 23,
      SystemDpcBehaviorInformation = 24,
      SystemFullMemoryInformation = 25,
      SystemLoadGdiDriverInformation = 26,
      SystemUnloadGdiDriverInformation = 27,
      SystemTimeAdjustmentInformation = 28,
      SystemSummaryMemoryInformation = 29,
      SystemMirrorMemoryInformation = 30,
      SystemPerformanceTraceInformation = 31,
      SystemObsolete0 = 32,
      SystemExceptionInformation = 33,
      SystemCrashDumpStateInformation = 34,
      SystemKernelDebuggerInformation = 35,
      SystemContextSwitchInformation = 36,
      SystemRegistryQuotaInformation = 37,
      SystemExtendServiceTableInformation = 38,
      SystemPrioritySeperation = 39,
      SystemVerifierAddDriverInformation = 40,
      SystemVerifierRemoveDriverInformation = 41,
      SystemProcessorIdleInformation = 42,
      SystemLegacyDriverInformation = 43,
      SystemCurrentTimeZoneInformation = 44,
      SystemLookasideInformation = 45,
      SystemTimeSlipNotification = 46,
      SystemSessionCreate = 47,
      SystemSessionDetach = 48,
      SystemSessionInformation = 49,
      SystemRangeStartInformation = 50,
      SystemVerifierInformation = 51,
      SystemVerifierThunkExtend = 52,
      SystemSessionProcessInformation = 53,
      SystemLoadGdiDriverInSystemSpace = 54,
      SystemNumaProcessorMap = 55,
      SystemPrefetcherInformation = 56,
      SystemExtendedProcessInformation = 57,
      SystemRecommendedSharedDataAlignment = 58,
      SystemComPlusPackage = 59,
      SystemNumaAvailableMemory = 60,
      SystemProcessorPowerInformation = 61,
      SystemEmulationBasicInformation = 62,
      SystemEmulationProcessorInformation = 63,
      SystemExtendedHandleInformation = 64,
      SystemLostDelayedWriteInformation = 65,
      SystemBigPoolInformation = 66,
      SystemSessionPoolTagInformation = 67,
      SystemSessionMappedViewInformation = 68,
      SystemHotpatchInformation = 69,
      SystemObjectSecurityMode = 70,
      SystemWatchdogTimerHandler = 71,
      SystemWatchdogTimerInformation = 72,
      SystemLogicalProcessorInformation = 73,
      SystemWow64SharedInformationObsolete = 74,
      SystemRegisterFirmwareTableInformationHandler = 75,
      SystemFirmwareTableInformation = 76,
      SystemModuleInformationEx = 77,
      SystemVerifierTriageInformation = 78,
      SystemSuperfetchInformation = 79,
      SystemMemoryListInformation = 80,
      SystemFileCacheInformationEx = 81,
      SystemThreadPriorityClientIdInformation = 82,
      SystemProcessorIdleCycleTimeInformation = 83,
      SystemVerifierCancellationInformation = 84,
      SystemProcessorPowerInformationEx = 85,
      SystemRefTraceInformation = 86,
      SystemSpecialPoolInformation = 87,
      SystemProcessIdInformation = 88,
      SystemErrorPortInformation = 89,
      SystemBootEnvironmentInformation = 90,
      SystemHypervisorInformation = 91,
      SystemVerifierInformationEx = 92,
      SystemTimeZoneInformation = 93,
      SystemImageFileExecutionOptionsInformation = 94,
      SystemCoverageInformation = 95,
      SystemPrefetchPatchInformation = 96,
      SystemVerifierFaultsInformation = 97,
      SystemSystemPartitionInformation = 98,
      SystemSystemDiskInformation = 99,
      SystemProcessorPerformanceDistribution = 100,
      SystemNumaProximityNodeInformation = 101,
      SystemDynamicTimeZoneInformation = 102,
      SystemCodeIntegrityInformation = 103,
      SystemProcessorMicrocodeUpdateInformation = 104,
      SystemProcessorBrandString = 105,
      SystemVirtualAddressInformation = 106,
      SystemLogicalProcessorAndGroupInformation = 107,
      SystemProcessorCycleTimeInformation = 108,
      SystemStoreInformation = 109,
      SystemRegistryAppendString = 110,
      SystemAitSamplingValue = 111,
      SystemVhdBootInformation = 112,
      SystemCpuQuotaInformation = 113,
      SystemNativeBasicInformation = 114,
      SystemErrorPortTimeouts = 115,
      SystemLowPriorityIoInformation = 116,
      SystemBootEntropyInformation = 117,
      SystemVerifierCountersInformation = 118,
      SystemPagedPoolInformationEx = 119,
      SystemSystemPtesInformationEx = 120,
      SystemNodeDistanceInformation = 121,
      SystemAcpiAuditInformation = 122,
      SystemBasicPerformanceInformation = 123,
      SystemQueryPerformanceCounterInformation = 124,
      SystemSessionBigPoolInformation = 125,
      SystemBootGraphicsInformation = 126,
      SystemScrubPhysicalMemoryInformation = 127,
      SystemBadPageInformation = 128,
      SystemProcessorProfileControlArea = 129,
      SystemCombinePhysicalMemoryInformation = 130,
      SystemEntropyInterruptTimingInformation = 131,
      SystemConsoleInformation = 132,
      SystemPlatformBinaryInformation = 133,
      SystemPolicyInformation = 134,
      SystemHypervisorProcessorCountInformation = 135,
      SystemDeviceDataInformation = 136,
      SystemDeviceDataEnumerationInformation = 137,
      SystemMemoryTopologyInformation = 138,
      SystemMemoryChannelInformation = 139,
      SystemBootLogoInformation = 140,
      SystemProcessorPerformanceInformationEx = 141,
      SystemSpare0 = 142,
      SystemSecureBootPolicyInformation = 143,
      SystemPageFileInformationEx = 144,
      SystemSecureBootInformation = 145,
      SystemEntropyInterruptTimingRawInformation = 146,
      SystemPortableWorkspaceEfiLauncherInformation = 147,
      SystemFullProcessInformation = 148,
      SystemKernelDebuggerInformationEx = 149,
      SystemBootMetadataInformation = 150,
      SystemSoftRebootInformation = 151,
      SystemElamCertificateInformation = 152,
      SystemOfflineDumpConfigInformation = 153,
      SystemProcessorFeaturesInformation = 154,
      SystemRegistryReconciliationInformation = 155,
      SystemEdidInformation = 156,
      SystemManufacturingInformation = 157,
      SystemEnergyEstimationConfigInformation = 158,
      SystemHypervisorDetailInformation = 159,
      SystemProcessorCycleStatsInformation = 160,
      SystemVmGenerationCountInformation = 161,
      SystemTrustedPlatformModuleInformation = 162,
      SystemKernelDebuggerFlags = 163,
      SystemCodeIntegrityPolicyInformation = 164,
      SystemIsolatedUserModeInformation = 165,
      SystemHardwareSecurityTestInterfaceResultsInformation = 166,
      SystemSingleModuleInformation = 167,
      SystemAllowedCpuSetsInformation = 168,
      SystemDmaProtectionInformation = 169,
      SystemInterruptCpuSetsInformation = 170,
      SystemSecureBootPolicyFullInformation = 171,
      SystemCodeIntegrityPolicyFullInformation = 172,
      SystemAffinitizedInterruptProcessorInformation = 173,
      SystemRootSiloInformation = 174,
      SystemCpuSetInformation = 175,
      SystemCpuSetTagInformation = 176,
      SystemWin32WerStartCallout = 177,
      SystemSecureKernelProfileInformation = 178,
      SystemCodeIntegrityPlatformManifestInformation = 179,
      SystemInterruptSteeringInformation = 180,
      SystemSupportedProcessorArchitectures = 181,
      SystemMemoryUsageInformation = 182,
      SystemCodeIntegrityCertificateInformation = 183,
      SystemPhysicalMemoryInformation = 184,
      SystemControlFlowTransition = 185,
      SystemKernelDebuggingAllowed = 186,
      SystemActivityModerationExeState = 187,
      SystemActivityModerationUserSettings = 188,
      SystemCodeIntegrityPoliciesFullInformation = 189,
      SystemCodeIntegrityUnlockInformation = 190,
      SystemIntegrityQuotaInformation = 191,
      SystemFlushInformation = 192,
      SystemProcessorIdleMaskInformation = 193,
      SystemSecureDumpEncryptionInformation = 194,
      SystemWriteConstraintInformation = 195,
      SystemKernelVaShadowInformation = 196,
      SystemHypervisorSharedPageInformation = 197,
      SystemFirmwareBootPerformanceInformation = 198,
      SystemCodeIntegrityVerificationInformation = 199,
      SystemFirmwarePartitionInformation = 200,
      SystemSpeculationControlInformation = 201,
      SystemDmaGuardPolicyInformation = 202,
      SystemEnclaveLaunchControlInformation = 203,
      SystemWorkloadAllowedCpuSetsInformation = 204,
      SystemCodeIntegrityUnlockModeInformation = 205,
      SystemLeapSecondInformation = 206,
      SystemFlags2Information = 207,
      SystemSecurityModelInformation = 208,
      SystemCodeIntegritySyntheticCacheInformation = 209,
      SystemFeatureConfigurationInformation = 210,
      SystemFeatureConfigurationSectionInformation = 211,
      SystemFeatureUsageSubscriptionInformation = 212,
      SystemSecureSpeculationControlInformation = 213,
      MaxSystemInfoClass
  } SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;


  extern "C"
  NTSYSAPI
      NTSTATUS
      WINAPI
      NtQuerySystemInformation(
          _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
          _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
          _In_ ULONG SystemInformationLength,
          _Out_opt_ PULONG ReturnLength);


  typedef struct _RTL_PROCESS_MODULE_INFORMATION
  {
      HANDLE Section;
      PVOID MappedBase;
      PVOID ImageBase;
      ULONG ImageSize;
      ULONG Flags;
      USHORT LoadOrderIndex;
      USHORT InitOrderIndex;
      USHORT LoadCount;
      USHORT OffsetToFileName;
      UCHAR FullPathName[256];
  } RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;


  typedef struct _RTL_PROCESS_MODULES
  {
      ULONG NumberOfModules;
      RTL_PROCESS_MODULE_INFORMATION Modules[1];
  } RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


  // get kernel module base addr
  // stolen off kdmapper since im dirty paster
  uint64_t GetKernelModuleAddress(const std::string& module_name)
  {
      void* buffer = nullptr;
      DWORD buffer_size = 0;

      NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation), buffer, buffer_size, &buffer_size);

      while (status == 0xC0000004) {
          if (buffer != nullptr)
              VirtualFree(buffer, 0, MEM_RELEASE);

          buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
          status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation), buffer, buffer_size, &buffer_size);
      }

      if (status != ERROR_SUCCESS)
      {
          if (buffer != nullptr)
              VirtualFree(buffer, 0, MEM_RELEASE);
          return 0;
      }

      const auto modules = static_cast<PRTL_PROCESS_MODULES>(buffer);
      if (!modules)
          return 0;

      for (auto i = 0u; i < modules->NumberOfModules; ++i) {
          const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[i].FullPathName) + modules->Modules[i].OffsetToFileName);

          if (!_stricmp(current_module_name.c_str(), module_name.c_str()))
          {
              const uint64_t result = reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);

              VirtualFree(buffer, 0, MEM_RELEASE);
              return result;
          }
      }

      VirtualFree(buffer, 0, MEM_RELEASE);
      return 0;
  }




  // Get target process id
  //
  DWORD get_pid(std::string process_name)
  {
    HANDLE hSnapshot;
    if ((hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE)
      return -1;

    DWORD pid = -1;
    PROCESSENTRY32 pe;
    ZeroMemory(&pe, sizeof(PROCESSENTRY32));
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe))
    {
      CloseHandle(hSnapshot);
      return -1;
    }

    while (Process32Next(hSnapshot, &pe))
    {
      if (pe.szExeFile == process_name)
      {
        pid = pe.th32ProcessID;
        break;
      }
    }

    if (pid == -1)
    {
      CloseHandle(hSnapshot);
      return -1;
    }

    CloseHandle(hSnapshot);
    return pid;
  }

}