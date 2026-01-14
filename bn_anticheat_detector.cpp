#include "bn_anticheat_detector.h"
#include <algorithm>
#include <fstream>
#include <chrono>
#include <thread>
#include <windows.h>
#include <psapi.h>
#include <pdh.h>

//--------------------------------------------------------------------------
// API patterns commonly used by anti-cheat systems
const anticheat_detector_t::api_pattern_t anticheat_detector_t::api_patterns[] = {
  // Debugger detection
  { "IsDebuggerPresent", AC_DEBUGGER_DETECT, "Checks if debugger is attached", 5 },
  { "CheckRemoteDebuggerPresent", AC_DEBUGGER_DETECT, "Checks for remote debugger", 5 },
  { "NtQueryInformationProcess", AC_DEBUGGER_DETECT, "Can detect debugger via ProcessDebugPort", 4 },
  { "NtSetInformationThread", AC_DEBUGGER_DETECT, "Can hide thread from debugger", 4 },
  { "OutputDebugStringA", AC_DEBUGGER_DETECT, "Used in anti-debug tricks", 3 },
  { "OutputDebugStringW", AC_DEBUGGER_DETECT, "Used in anti-debug tricks", 3 },
  { "ZwQueryInformationProcess", AC_DEBUGGER_DETECT, "Native API debugger check", 4 },
  
  // VM detection
  { "NtQuerySystemInformation", AC_VM_DETECT, "Can detect VM artifacts", 3 },
  { "GetSystemFirmwareTable", AC_VM_DETECT, "Checks BIOS/firmware for VM signatures", 4 },
  { "SetupDiGetDeviceRegistryPropertyA", AC_VM_DETECT, "Enumerates hardware for VM detection", 3 },
  
  // Integrity checks
  { "CryptHashData", AC_INTEGRITY_CHECK, "Hashing function for integrity checks", 3 },
  { "CreateToolhelp32Snapshot", AC_INTEGRITY_CHECK, "Memory/process enumeration", 4 },
  { "VirtualProtect", AC_INTEGRITY_CHECK, "Memory protection changes", 3 },
  { "VirtualQuery", AC_INTEGRITY_CHECK, "Query memory regions", 3 },
  { "VirtualQueryEx", AC_INTEGRITY_CHECK, "External memory enumeration for executable unmapped pages", 4 },
  { "ReadProcessMemory", AC_INTEGRITY_CHECK, "Read process memory", 4 },
  { "VirtualAlloc", AC_INTEGRITY_CHECK, "Allocates memory, potentially making it executable", 3 },
  { "VirtualAllocEx", AC_INTEGRITY_CHECK, "External memory allocation, potentially executable", 4 },
  { "VirtualProtectEx", AC_INTEGRITY_CHECK, "External memory protection changes", 4 },
  { "NtProtectVirtualMemory", AC_INTEGRITY_CHECK, "Native memory protection", 4 },
  
  // Exception handler manipulation
  { "SetUnhandledExceptionFilter", AC_INTEGRITY_CHECK, "Sets custom exception handler for monitoring", 4 },
  { "AddVectoredExceptionHandler", AC_INTEGRITY_CHECK, "Adds vectored exception handler", 4 },
  
  // Hook detection via IAT/EAT inspection
  { "GetProcAddress", AC_INTEGRITY_CHECK, "Resolves function addresses for hook checks", 4 },
  { "ImageNtHeader", AC_INTEGRITY_CHECK, "Accesses PE headers for IAT/EAT analysis", 4 },
  
  // Anti-cheat service interaction
  { "DeviceIoControl", AC_PROTECTION_CHECK, "Sends IOCTLs to anti-cheat drivers", 5 },
  { "CreateFileA", AC_PROTECTION_CHECK, "Opens handles to anti-cheat devices", 4 },
  { "CreateFileW", AC_PROTECTION_CHECK, "Opens handles to anti-cheat devices", 4 },
  
  // Network packet inspection
  { "WSAStartup", AC_INTEGRITY_CHECK, "Initializes Winsock for network monitoring", 3 },
  { "recv", AC_INTEGRITY_CHECK, "Receives network data for inspection", 3 },
  { "send", AC_INTEGRITY_CHECK, "Sends network data for inspection", 3 },
  { "WSARecv", AC_INTEGRITY_CHECK, "Advanced network receive for inspection", 3 },
  { "WSASend", AC_INTEGRITY_CHECK, "Advanced network send for inspection", 3 },
  
  // File system integrity checks
  { "FindFirstFileA", AC_INTEGRITY_CHECK, "Enumerates files for integrity checks", 3 },
  { "FindFirstFileW", AC_INTEGRITY_CHECK, "Enumerates files for integrity checks", 3 },
  { "FindNextFileA", AC_INTEGRITY_CHECK, "Continues file enumeration", 3 },
  { "FindNextFileW", AC_INTEGRITY_CHECK, "Continues file enumeration", 3 },
  { "CreateFileMappingA", AC_INTEGRITY_CHECK, "Maps files for hashing/verification", 3 },
  { "CreateFileMappingW", AC_INTEGRITY_CHECK, "Maps files for hashing/verification", 3 },
  
  // Registry key monitoring
  { "RegOpenKeyExA", AC_INTEGRITY_CHECK, "Opens registry keys for monitoring", 3 },
  { "RegOpenKeyExW", AC_INTEGRITY_CHECK, "Opens registry keys for monitoring", 3 },
  { "RegQueryValueExA", AC_INTEGRITY_CHECK, "Queries registry values for anomalies", 3 },
  { "RegQueryValueExW", AC_INTEGRITY_CHECK, "Queries registry values for anomalies", 3 },
  
  // Timing checks
  { "QueryPerformanceCounter", AC_TIMING_CHECK, "High-resolution timing", 3 },
  { "GetTickCount", AC_TIMING_CHECK, "Tick count for timing attacks", 2 },
  { "GetTickCount64", AC_TIMING_CHECK, "64-bit tick count", 2 },
  { "timeGetTime", AC_TIMING_CHECK, "Multimedia timer", 2 },
  { "NtQueryPerformanceCounter", AC_TIMING_CHECK, "Native timing function", 3 },
  
  // Hardware breakpoint detection
  { "GetThreadContext", AC_HARDWARE_BREAKPOINT, "Can read debug registers", 5 },
  { "SetThreadContext", AC_HARDWARE_BREAKPOINT, "Can manipulate debug registers", 5 },
  { "NtGetContextThread", AC_HARDWARE_BREAKPOINT, "Native context function", 5 },
  { "NtSetContextThread", AC_HARDWARE_BREAKPOINT, "Native context function", 5 },
  
  // Process/Module enumeration
  { "EnumProcesses", AC_PROCESS_ENUM, "Enumerate running processes", 3 },
  { "Process32First", AC_PROCESS_ENUM, "Process enumeration", 3 },
  { "Process32Next", AC_PROCESS_ENUM, "Process enumeration", 3 },
  { "EnumProcessModules", AC_MODULE_ENUM, "Module enumeration", 3 },
  { "Module32First", AC_MODULE_ENUM, "Module enumeration", 3 },
  { "Module32Next", AC_MODULE_ENUM, "Module enumeration", 3 },
  { "GetModuleHandleA", AC_MODULE_ENUM, "Get module handle", 2 },
  { "GetModuleHandleW", AC_MODULE_ENUM, "Get module handle", 2 },
  { "LoadLibraryA", AC_MODULE_ENUM, "Load library check", 2 },
  { "LoadLibraryW", AC_MODULE_ENUM, "Load library check", 2 },
  
  // Protection systems
  { "NtProtectVirtualMemory", AC_PROTECTION_CHECK, "Native memory protection", 3 },
};

//--------------------------------------------------------------------------
// String patterns
const anticheat_detector_t::string_pattern_t anticheat_detector_t::string_patterns[] = {
  { "WINE", AC_VM_DETECT, "Wine compatibility layer detection", 4 },
  { "VMware", AC_VM_DETECT, "VMware detection", 4 },
  { "VBox", AC_VM_DETECT, "VirtualBox detection", 4 },
  { "VBOX", AC_VM_DETECT, "VirtualBox detection", 4 },
  { "Xen", AC_VM_DETECT, "Xen hypervisor detection", 4 },
  { "QEMU", AC_VM_DETECT, "QEMU detection", 4 },
  { "Cheat Engine", AC_PROCESS_ENUM, "Cheat Engine detection", 5 },
  { "OllyDbg", AC_DEBUGGER_DETECT, "OllyDbg detection", 5 },
  { "x64dbg", AC_DEBUGGER_DETECT, "x64dbg detection", 5 },
  { "IDA", AC_DEBUGGER_DETECT, "IDA Pro detection", 5 },
  { "Wireshark", AC_PROCESS_ENUM, "Network analysis tool", 3 },
  { "ProcessHacker", AC_PROCESS_ENUM, "Process analysis tool", 4 },
  { "ProcessExplorer", AC_PROCESS_ENUM, "Process analysis tool", 4 },
  { "SeDebugPrivilege", AC_PROTECTION_CHECK, "Debug privilege check", 4 },
  { "\\\\.\\", AC_PROTECTION_CHECK, "Device driver access (anti-cheat services)", 5 },
  { "SOFTWARE\\CheatEngine", AC_INTEGRITY_CHECK, "Registry paths for cheat tools", 4 },
  { "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", AC_INTEGRITY_CHECK, "Auto-start registry monitoring", 3 },
  { "packet", AC_INTEGRITY_CHECK, "Network packet analysis", 3 },
  { "cheat", AC_INTEGRITY_CHECK, "File names containing cheat indicators", 3 },
  { "hack", AC_INTEGRITY_CHECK, "File names containing hack indicators", 3 },
  { "bypass", AC_INTEGRITY_CHECK, "File names containing bypass indicators", 3 },
};

//--------------------------------------------------------------------------
anticheat_detector_t::anticheat_detector_t(BinaryView* _bv) : bv(_bv)
{
  // Initialize energy monitoring
  memset(&energy_usage, 0, sizeof(energy_usage));
}

//--------------------------------------------------------------------------
// Energy monitoring methods
void anticheat_detector_t::start_energy_monitoring()
{
  energy_usage.start_time = std::chrono::steady_clock::now();
}

//--------------------------------------------------------------------------
void anticheat_detector_t::stop_energy_monitoring()
{
  energy_usage.end_time = std::chrono::steady_clock::now();
  calculate_energy_usage();
}

//--------------------------------------------------------------------------
void anticheat_detector_t::calculate_energy_usage()
{
  // Calculate elapsed time
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
    energy_usage.end_time - energy_usage.start_time);
  energy_usage.cpu_time_seconds = duration.count() / 1000.0;
  
  // Get current RAM usage
  energy_usage.ram_usage_mb = get_current_ram_usage();
  
  // Estimate energy consumption (simplified model)
  // Assume average CPU TDP of 65W and RAM power of 5W per 8GB
  double avg_cpu_power_w = 65.0; // Watts
  double ram_power_w = (energy_usage.ram_usage_mb / 8192.0) * 5.0; // 5W per 8GB
  double total_avg_power_w = avg_cpu_power_w + ram_power_w;
  
  // Energy in watt-hours
  energy_usage.energy_consumed_wh = (total_avg_power_w * energy_usage.cpu_time_seconds) / 3600.0;
  
  // Calculate environmental impact
  energy_usage.carbon_emitted_kg = calculate_carbon_emissions(energy_usage.energy_consumed_wh);
  energy_usage.water_consumed_liters = calculate_water_consumption(energy_usage.energy_consumed_wh);
  energy_usage.carbon_credit_cost_usd = calculate_carbon_credit_cost(energy_usage.carbon_emitted_kg);
}

//--------------------------------------------------------------------------
double anticheat_detector_t::get_current_cpu_usage()
{
  // Simplified CPU usage - in a real implementation, you'd use PDH or similar
  // For now, return an estimate based on processing time
  return 50.0; // Assume 50% average CPU usage
}

//--------------------------------------------------------------------------
double anticheat_detector_t::get_current_ram_usage()
{
  PROCESS_MEMORY_COUNTERS pmc;
  if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)))
  {
    return pmc.WorkingSetSize / (1024.0 * 1024.0); // Convert to MB
  }
  return 1024.0; // Default estimate
}

//--------------------------------------------------------------------------
double anticheat_detector_t::calculate_carbon_emissions(double energy_wh)
{
  // Carbon emission factor for US grid electricity (kg CO2 per kWh)
  // Average US grid emission factor is approximately 0.429 kg CO2/kWh
  double emission_factor_kg_per_kwh = 0.429;
  return (energy_wh / 1000.0) * emission_factor_kg_per_kwh;
}

//--------------------------------------------------------------------------
double anticheat_detector_t::calculate_water_consumption(double energy_wh)
{
  // Water consumption for thermoelectric power generation
  // Approximately 1.8 liters per kWh for US average
  double water_per_kwh = 1.8;
  return (energy_wh / 1000.0) * water_per_kwh;
}

//--------------------------------------------------------------------------
double anticheat_detector_t::calculate_carbon_credit_cost(double carbon_kg)
{
  // Average carbon credit price (as of 2024) is approximately $20-30 per metric ton
  // Using $25 per metric ton
  double price_per_ton = 25.0;
  return (carbon_kg / 1000.0) * price_per_ton;
}

//--------------------------------------------------------------------------
const char *anticheat_detector_t::get_category_name(artifact_category_t cat)
{
  switch (cat)
  {
    case AC_DEBUGGER_DETECT: return "Debugger Detection";
    case AC_VM_DETECT: return "VM Detection";
    case AC_INTEGRITY_CHECK: return "Integrity Check";
    case AC_TIMING_CHECK: return "Timing Check";
    case AC_HARDWARE_BREAKPOINT: return "Hardware Breakpoint";
    case AC_PROCESS_ENUM: return "Process Enumeration";
    case AC_MODULE_ENUM: return "Module Enumeration";
    case AC_THREAD_CONTEXT: return "Thread Context";
    case AC_PROTECTION_CHECK: return "Protection Check";
    default: return "Unknown";
  }
}

//--------------------------------------------------------------------------
uint32_t anticheat_detector_t::get_category_color(artifact_category_t cat)
{
  switch (cat)
  {
    case AC_DEBUGGER_DETECT: return 0xFF6B6B; // Red
    case AC_VM_DETECT: return 0xFFA500; // Orange
    case AC_INTEGRITY_CHECK: return 0xFFFF00; // Yellow
    case AC_TIMING_CHECK: return 0x90EE90; // Light Green
    case AC_HARDWARE_BREAKPOINT: return 0xFF1493; // Deep Pink
    case AC_PROCESS_ENUM: return 0x87CEEB; // Sky Blue
    case AC_MODULE_ENUM: return 0xDDA0DD; // Plum
    case AC_THREAD_CONTEXT: return 0xFF69B4; // Hot Pink
    case AC_PROTECTION_CHECK: return 0xFFA07A; // Light Salmon
    default: return 0xCCCCCC; // Gray
  }
}

//--------------------------------------------------------------------------
bool anticheat_detector_t::is_suspicious_constant(uint64_t val)
{
  // Common constants used in anti-debug/anti-vm
  static const uint64_t suspicious_constants[] = {
    0x564D5868, // VMware I/O port
    0x40000000, // VirtualBox CPUID
    0x7FFE0000, // KUSER_SHARED_DATA
    0xC0000000, // Kernel address range
    0x2C,       // ProcessDebugPort
    0x1F,       // ProcessDebugObjectHandle
  };
  
  for (size_t i = 0; i < sizeof(suspicious_constants)/sizeof(suspicious_constants[0]); i++)
  {
    if (val == suspicious_constants[i])
      return true;
  }
  return false;
}

//--------------------------------------------------------------------------
bool anticheat_detector_t::check_api_calls(Function* func)
{
  bool found = false;
  
  // Get all symbols referenced by this function
  auto symbols = bv->GetSymbols();
  
  for (auto& symbol : symbols)
  {
    std::string symbol_name = symbol->GetFullName();
    
    // Check against our API patterns
    for (size_t i = 0; i < sizeof(api_patterns)/sizeof(api_patterns[0]); i++)
    {
      if (symbol_name.find(api_patterns[i].api_name) != std::string::npos)
      {
        // Check if this symbol is referenced by the current function
        auto refs = bv->GetCodeReferences(symbol->GetAddress());
        for (auto& ref : refs)
        {
          if (func->GetStart() <= ref && ref < func->GetEnd())
          {
            detected_artifact_t artifact;
            artifact.address = ref;
            artifact.category = api_patterns[i].category;
            artifact.description = api_patterns[i].description;
            artifact.severity = api_patterns[i].severity;
            artifact.api_used = symbol_name;
            artifact.instruction = symbol_name; // Store the API name as instruction
            artifact.function_name = func->GetSymbol()->GetFullName();
            
            artifacts.push_back(artifact);
            found = true;
            
            // Set comment to mark the artifact
            bv->SetCommentForAddress(artifact.address, "[ACAD] " + artifact.description);
          }
        }
      }
    }
  }
  
  return found;
}

//--------------------------------------------------------------------------
bool anticheat_detector_t::check_string_references(Function* func)
{
  bool found = false;
  
  // Get all strings in the binary
  auto strings = bv->GetStrings();
  
  for (auto& str : strings)
  {
    std::string content(str.str, str.len);
    
    // Convert to lowercase for case-insensitive matching
    std::string lower_content = content;
    std::transform(lower_content.begin(), lower_content.end(), lower_content.begin(), ::tolower);
    
    // Check if this string is referenced by the current function
    auto refs = bv->GetCodeReferences(str.start);
    bool referenced_by_func = false;
    for (auto& ref : refs)
    {
      if (func->GetStart() <= ref && ref < func->GetEnd())
      {
        referenced_by_func = true;
        break;
      }
    }
    
    if (!referenced_by_func) continue;
    
    // Check against string patterns
    for (size_t i = 0; i < sizeof(string_patterns)/sizeof(string_patterns[0]); i++)
    {
      std::string pattern = string_patterns[i].pattern;
      std::transform(pattern.begin(), pattern.end(), pattern.begin(), ::tolower);
      
      if (lower_content.find(pattern) != std::string::npos)
      {
        detected_artifact_t artifact;
        artifact.address = str.start;
        artifact.category = string_patterns[i].category;
        artifact.description = std::string(string_patterns[i].description) + " (string: \"" + content + "\")";
        artifact.severity = string_patterns[i].severity;
        artifact.instruction = "String: \"" + content + "\"";
        artifact.function_name = func->GetSymbol()->GetFullName();
        
        artifacts.push_back(artifact);
        found = true;
        
        // Set comment to mark the artifact
        bv->SetCommentForAddress(artifact.address, "[ACAD] " + artifact.description);
      }
    }
  }
  
  return found;
}

//--------------------------------------------------------------------------
bool anticheat_detector_t::check_inline_detection(Function* func)
{
  bool found = false;
  
  // Get the low-level IL for instruction analysis
  auto llil = func->GetLowLevelIL();
  if (!llil) return false;
  
  for (size_t i = 0; i < llil->GetInstructionCount(); ++i)
  {
    auto instr = llil->GetInstruction(i);
    uint64_t addr = llil->GetInstructionStart(i);
    
    // Check for specific instruction patterns
    if (instr.operation == LLIL_INTRINSIC)
    {
      BNIntrinsic intrinsic = instr.GetIntrinsic();
      
      // CPUID (VM detection) - check by name since intrinsic enum might vary
      std::string intrinsic_name = bv->GetIntrinsicName(intrinsic);
      if (intrinsic_name.find("cpuid") != std::string::npos ||
          intrinsic_name.find("CPUID") != std::string::npos)
      {
        detected_artifact_t artifact;
        artifact.address = addr;
        artifact.category = AC_VM_DETECT;
        artifact.description = "CPUID instruction (VM detection)";
        artifact.severity = 4;
        artifact.instruction = "cpuid";
        artifact.function_name = func->GetSymbol()->GetFullName();
        
        artifacts.push_back(artifact);
        found = true;
        
        // Set comment to mark the artifact
        bv->SetCommentForAddress(addr, "[ACAD] " + artifact.description);
      }
      
      // RDTSC/RDTSCP (timing check)
      else if (intrinsic_name.find("rdtsc") != std::string::npos ||
               intrinsic_name.find("RDTSC") != std::string::npos)
      {
        detected_artifact_t artifact;
        artifact.address = addr;
        artifact.category = AC_TIMING_CHECK;
        artifact.description = "RDTSC instruction (timing check)";
        artifact.severity = 3;
        artifact.instruction = "rdtsc";
        artifact.function_name = func->GetSymbol()->GetFullName();
        
        artifacts.push_back(artifact);
        found = true;
        
        // Set comment to mark the artifact
        bv->SetCommentForAddress(addr, "[ACAD] " + artifact.description);
      }
    }
    
    // Check for interrupt instructions (anti-debug)
    // This is more complex in BN - we'd need to check the disassembly
    // For now, we'll check for specific patterns in the instruction text
    std::string disasm = bv->GetDisassembly(addr);
    std::string lower_disasm = disasm;
    std::transform(lower_disasm.begin(), lower_disasm.end(), lower_disasm.begin(), ::tolower);
    
    if (lower_disasm.find("int 0x2d") != std::string::npos ||
        lower_disasm.find("int 0x3") != std::string::npos ||
        lower_disasm.find("int3") != std::string::npos)
    {
      detected_artifact_t artifact;
      artifact.address = addr;
      artifact.category = AC_DEBUGGER_DETECT;
      artifact.description = "INT instruction (anti-debug)";
      artifact.severity = 5;
      artifact.instruction = disasm;
      artifact.function_name = func->GetSymbol()->GetFullName();
      
      artifacts.push_back(artifact);
      found = true;
      
      // Set comment to mark the artifact
      bv->SetCommentForAddress(addr, "[ACAD] " + artifact.description);
    }
    
    // Check for suspicious constants in operands
    auto operands = instr.GetOperands();
    for (auto& operand : operands)
    {
      if (operand.IsConstant())
      {
        uint64_t val = operand.GetConstant();
        if (is_suspicious_constant(val))
        {
          detected_artifact_t artifact;
          artifact.address = addr;
          artifact.category = AC_UNKNOWN;
          artifact.description = "Suspicious constant: 0x" + std::to_string(val);
          artifact.severity = 3;
          artifact.instruction = "0x" + std::to_string(val);
          artifact.function_name = func->GetSymbol()->GetFullName();
          
          artifacts.push_back(artifact);
          found = true;
        }
      }
    }
  }
  
  return found;
}

//--------------------------------------------------------------------------
// New method to check for memory enumeration patterns (e.g., scanning for executable pages not mapped to files)
bool anticheat_detector_t::check_memory_enumeration(Function* func)
{
  bool found = false;
  
  // Look for VirtualQuery calls in loops or with patterns indicating enumeration
  auto symbols = bv->GetSymbols();
  for (auto& symbol : symbols)
  {
    std::string symbol_name = symbol->GetFullName();
    if (symbol_name.find("VirtualQuery") != std::string::npos ||
        symbol_name.find("VirtualQueryEx") != std::string::npos)
    {
      auto refs = bv->GetCodeReferences(symbol->GetAddress());
      for (auto& ref : refs)
      {
        if (func->GetStart() <= ref && ref < func->GetEnd())
        {
          // Check if this is in a loop (basic heuristic: multiple calls or near loop constructs)
          // For simplicity, flag any VirtualQuery in integrity-checking contexts
          detected_artifact_t artifact;
          artifact.address = ref;
          artifact.category = AC_INTEGRITY_CHECK;
          artifact.description = "Memory enumeration via VirtualQuery (potential scan for executable unmapped pages)";
          artifact.severity = 4;
          artifact.api_used = symbol_name;
          artifact.instruction = symbol_name;
          artifact.function_name = func->GetSymbol()->GetFullName();
          
          artifacts.push_back(artifact);
          found = true;
          
          bv->SetCommentForAddress(artifact.address, "[ACAD] " + artifact.description);
        }
      }
    }
  }
  
  return found;
}

//--------------------------------------------------------------------------
// New method to check for VirtualProtect/VirtualAlloc making memory executable
bool anticheat_detector_t::check_executable_memory_modification(Function* func)
{
  bool found = false;
  
  // Get the low-level IL for deeper analysis
  auto llil = func->GetLowLevelIL();
  if (!llil) return false;
  
  for (size_t i = 0; i < llil->GetInstructionCount(); ++i)
  {
    auto instr = llil->GetInstruction(i);
    uint64_t addr = llil->GetInstructionStart(i);
    
    // Check for calls to VirtualProtect or VirtualAlloc
    if (instr.operation == LLIL_CALL)
    {
      // Get the target of the call
      auto target = instr.GetDest();
      if (target.IsConstant())
      {
        uint64_t target_addr = target.GetConstant();
        auto target_func = bv->GetAnalysisFunctionForAddress(target_addr);
        if (target_func)
        {
          std::string func_name = target_func->GetSymbol()->GetFullName();
          if (func_name.find("VirtualProtect") != std::string::npos ||
              func_name.find("VirtualAlloc") != std::string::npos ||
              func_name.find("VirtualProtectEx") != std::string::npos ||
              func_name.find("VirtualAllocEx") != std::string::npos)
          {
            // Analyze arguments (simplified: check for executable flags like PAGE_EXECUTE)
            // In BN, arguments are in instr.GetOperands()
            auto operands = instr.GetOperands();
            bool has_executable_flag = false;
            for (auto& operand : operands)
            {
              if (operand.IsConstant())
              {
                uint64_t val = operand.GetConstant();
                // Common executable protection flags: PAGE_EXECUTE (0x10), PAGE_EXECUTE_READ (0x20), etc.
                if ((val & 0xF0) != 0)  // Bitmask for execute permissions
                {
                  has_executable_flag = true;
                  break;
                }
              }
            }
            
            if (has_executable_flag)
            {
              detected_artifact_t artifact;
              artifact.address = addr;
              artifact.category = AC_INTEGRITY_CHECK;
              artifact.description = "Memory protection/allocation making regions executable";
              artifact.severity = 5;
              artifact.api_used = func_name;
              artifact.instruction = bv->GetDisassembly(addr);
              artifact.function_name = func->GetSymbol()->GetFullName();
              
              artifacts.push_back(artifact);
              found = true;
              
              bv->SetCommentForAddress(addr, "[ACAD] " + artifact.description);
            }
          }
        }
      }
    }
  }
  
  return found;
}

//--------------------------------------------------------------------------
void anticheat_detector_t::scan_function(Function* func)
{
  if (func == nullptr)
    return;
    
  LogInfo("Scanning function at 0x%llx", func->GetStart());
  
  check_api_calls(func);
  check_string_references(func);
  check_inline_detection(func);
  check_memory_enumeration(func);
  check_executable_memory_modification(func);
}

//--------------------------------------------------------------------------
void anticheat_detector_t::scan_all_functions()
{
  clear_results();
  start_energy_monitoring();
  LogInfo("Starting anti-cheat artifact scan...");
  
  auto functions = bv->GetAnalysisFunctionList();
  for (auto& func : functions)
  {
    scan_function(func);
  }
  
  stop_energy_monitoring();
  LogInfo("Scan complete! Found %zu artifacts", artifacts.size());
  LogInfo("Energy Usage: %.2f Wh, Carbon: %.4f kg, Water: %.2f L, Credits: $%.2f",
           energy_usage.energy_consumed_wh,
           energy_usage.carbon_emitted_kg,
           energy_usage.water_consumed_liters,
           energy_usage.carbon_credit_cost_usd);
  show_results();
}

//--------------------------------------------------------------------------
void anticheat_detector_t::scan_current_function()
{
  clear_results();
  
  // Get the current function (this would need to be passed from UI context)
  // For now, we'll scan all functions
  scan_all_functions();
}

//--------------------------------------------------------------------------
void anticheat_detector_t::clear_results()
{
  artifacts.clear();
}

//--------------------------------------------------------------------------
void anticheat_detector_t::show_results()
{
  if (artifacts.empty())
  {
    LogInfo("No anti-cheat artifacts detected!");
    return;
  }
  
  LogInfo("Anti-Cheat Artifacts Detected:");
  LogInfo("================================");
  
  for (const auto& artifact : artifacts)
  {
    LogInfo("Address: 0x%llx", artifact.address);
    LogInfo("Function: %s", artifact.function_name.c_str());
    LogInfo("Instruction: %s", artifact.instruction.c_str());
    LogInfo("Category: %s", get_category_name(artifact.category));
    LogInfo("Severity: %d/5", artifact.severity);
    LogInfo("Description: %s", artifact.description.c_str());
    if (!artifact.api_used.empty())
      LogInfo("API: %s", artifact.api_used.c_str());
    LogInfo("");
  }
}

//--------------------------------------------------------------------------
void anticheat_detector_t::export_results(const char *filename)
{
  std::ofstream file(filename);
  if (!file.is_open())
  {
    LogError("Failed to open file for export: %s", filename);
    return;
  }
  
  file << "Anti-Cheat Artifacts Detected:\n";
  file << "================================\n";
  file << "\n";
  
  // Energy usage report
  file << "ENERGY & ENVIRONMENTAL IMPACT REPORT\n";
  file << "=====================================\n";
  file << "Analysis Duration: " << energy_usage.cpu_time_seconds << " seconds\n";
  file << "Peak RAM Usage: " << energy_usage.ram_usage_mb << " MB\n";
  file << "Energy Consumed: " << energy_usage.energy_consumed_wh << " Wh\n";
  file << "Carbon Emitted: " << energy_usage.carbon_emitted_kg << " kg CO2\n";
  file << "Water Consumed: " << energy_usage.water_consumed_liters << " liters\n";
  file << "Carbon Credit Cost: $" << energy_usage.carbon_credit_cost_usd << " USD\n";
  file << "\n";
  file << "To offset your carbon footprint from this analysis,\n";
  file << "please purchase carbon credits costing approximately $" << energy_usage.carbon_credit_cost_usd << ".\n";
  file << "This helps combat climate change and supports renewable energy projects.\n";
  file << "\n";
  
  file << "DETECTION RESULTS\n";
  file << "=================\n";
  file << "Total artifacts found: " << artifacts.size() << "\n\n";
  
  for (const auto& artifact : artifacts)
  {
    file << "Address: 0x" << std::hex << artifact.address << std::dec << "\n";
    file << "Function: " << artifact.function_name << "\n";
    file << "Instruction: " << artifact.instruction << "\n";
    file << "Category: " << get_category_name(artifact.category) << "\n";
    file << "Severity: " << artifact.severity << "/5\n";
    file << "Description: " << artifact.description << "\n";
    if (!artifact.api_used.empty())
      file << "API: " << artifact.api_used << "\n";
    file << "\n";
  }
  
  file.close();
  LogInfo("Results exported to %s", filename);
}