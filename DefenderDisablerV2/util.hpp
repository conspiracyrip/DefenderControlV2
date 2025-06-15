#pragma once
#include <Windows.h>
#include <string>
#include <lmcons.h>
#include <TlHelp32.h>

namespace util
{
  // Converts a string to wide
  //
  std::wstring string_to_wide(const std::string& s);

  // Converts a wide to string
  //
  std::string wide_to_string(const std::wstring& s);

  // Sets the programs debug priviliges
  //
  bool set_privilege(LPCSTR privilege, BOOL enable);
  char sub_43604B();

  // Get current username
  //
  std::string get_user();

  // Get current path of process
  //
  std::string get_current_path();

  // Get target process id
  //
  DWORD get_pid(std::string process_name);

  // get kernel module base addr
  // stolen off kdmapper since im dirty paster
  uint64_t GetKernelModuleAddress(const std::string& module_name);

}
