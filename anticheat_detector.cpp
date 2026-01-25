#include "anticheat_detector.h"
#include <mergemod.hpp>

int data_id;

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
  { "ReadProcessMemory", AC_INTEGRITY_CHECK, "Read process memory", 4 },
  
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
  { "VirtualProtectEx", AC_PROTECTION_CHECK, "External memory protection", 3 },
  { "NtProtectVirtualMemory", AC_PROTECTION_CHECK, "Native memory protection", 3 },
  
  // Window/UI enumeration
  { "FindWindowA", AC_PROCESS_ENUM, "Find window by name", 2 },
  { "FindWindowW", AC_PROCESS_ENUM, "Find window by name", 2 },
  { "EnumWindows", AC_PROCESS_ENUM, "Enumerate windows", 3 },
  { "GetWindowTextA", AC_PROCESS_ENUM, "Get window title (debugger detection)", 2 },
  { "GetWindowTextW", AC_PROCESS_ENUM, "Get window title (debugger detection)", 2 },
  
  // File/Registry operations
  { "RegOpenKeyExA", AC_INTEGRITY_CHECK, "Registry access for artifact detection", 2 },
  { "RegOpenKeyExW", AC_INTEGRITY_CHECK, "Registry access for artifact detection", 2 },
  { "RegQueryValueExA", AC_INTEGRITY_CHECK, "Registry query for VM/driver detection", 2 },
  { "RegQueryValueExW", AC_INTEGRITY_CHECK, "Registry query for VM/driver detection", 2 },
  { "CreateFileA", AC_INTEGRITY_CHECK, "File access (may check for debugger files)", 2 },
  { "CreateFileW", AC_INTEGRITY_CHECK, "File access (may check for debugger files)", 2 },
  
  // Exception handling anti-debug
  { "SetUnhandledExceptionFilter", AC_DEBUGGER_DETECT, "Exception filter for anti-debug", 4 },
  { "AddVectoredExceptionHandler", AC_DEBUGGER_DETECT, "Vectored exception handler (anti-debug)", 4 },
  { "SetErrorMode", AC_DEBUGGER_DETECT, "Error mode manipulation", 3 },
  
  // Driver/Kernel operations
  { "CreateFileA", AC_PROTECTION_CHECK, "Device handle creation", 3 },
  { "DeviceIoControl", AC_PROTECTION_CHECK, "Direct device I/O", 4 },
  { "NtDeviceIoControlFile", AC_PROTECTION_CHECK, "Native device I/O", 4 },
  
  // Direct kernel calls
  { "NtSetInformationFile", AC_PROTECTION_CHECK, "File information manipulation", 3 },
  { "NtQueryDirectoryFile", AC_PROCESS_ENUM, "Directory enumeration", 2 },
  { "NtOpenProcess", AC_PROCESS_ENUM, "Open process handle", 3 },
  { "NtQueryObject", AC_PROCESS_ENUM, "Query object information", 3 },
  
  // Memory forensics detection
  { "GetProcessMemoryInfo", AC_INTEGRITY_CHECK, "Memory information retrieval", 3 },
  { "GlobalMemoryStatusEx", AC_INTEGRITY_CHECK, "Global memory status check", 2 },
  { "HeapWalk", AC_INTEGRITY_CHECK, "Heap enumeration", 3 },
  { "HeapAlloc", AC_INTEGRITY_CHECK, "Memory allocation (pattern check)", 2 },
  
  // Thread manipulation
  { "CreateRemoteThread", AC_THREAD_CONTEXT, "Remote thread creation", 4 },
  { "NtCreateThreadEx", AC_THREAD_CONTEXT, "Native thread creation", 4 },
  { "SuspendThread", AC_THREAD_CONTEXT, "Thread suspension", 3 },
  { "ResumeThread", AC_THREAD_CONTEXT, "Thread resumption", 3 },
  
  // Network communication (potential C2 or beacon)
  { "WSASocket", AC_INTEGRITY_CHECK, "Winsock initialization", 2 },
  { "WinHttpOpen", AC_INTEGRITY_CHECK, "HTTP connection setup", 2 },
  { "InternetOpenA", AC_INTEGRITY_CHECK, "Internet connection", 2 },
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
  
  // Additional debugger/analysis tool detection
  { "WinDbg", AC_DEBUGGER_DETECT, "WinDbg debugger detection", 5 },
  { "GDB", AC_DEBUGGER_DETECT, "GNU Debugger detection", 5 },
  { "LLDB", AC_DEBUGGER_DETECT, "LLDB debugger detection", 5 },
  { "Radare2", AC_DEBUGGER_DETECT, "Radare2 analysis tool detection", 5 },
  { "Ghidra", AC_DEBUGGER_DETECT, "Ghidra reverse engineering tool", 5 },
  { "BinDiff", AC_DEBUGGER_DETECT, "Hex-Rays BinDiff detection", 4 },
  { "Frida", AC_DEBUGGER_DETECT, "Frida dynamic instrumentation detection", 5 },
  { "DynamoRIO", AC_DEBUGGER_DETECT, "DynamoRIO dynamic instrumentation", 5 },
  { "Pin", AC_DEBUGGER_DETECT, "Intel Pin instrumentation detection", 5 },
  { "Valgrind", AC_DEBUGGER_DETECT, "Valgrind profiler detection", 4 },
  
  // Hypervisor/Virtualization detection
  { "HyperV", AC_VM_DETECT, "Hyper-V detection", 4 },
  { "KVM", AC_VM_DETECT, "KVM hypervisor detection", 4 },
  { "Bochs", AC_VM_DETECT, "Bochs emulator detection", 4 },
  { "Parallels", AC_VM_DETECT, "Parallels Desktop detection", 4 },
  { "VirtualPC", AC_VM_DETECT, "Virtual PC detection", 4 },
  
  // Disassembler detection
  { "Disasm", AC_DEBUGGER_DETECT, "Disassembler detection", 3 },
  { "Hexdump", AC_DEBUGGER_DETECT, "Hex dump analysis detection", 2 },
  { "Strings", AC_DEBUGGER_DETECT, "String analysis tool detection", 2 },
  
  // Security software detection
  { "ESET", AC_INTEGRITY_CHECK, "ESET antivirus detection", 3 },
  { "Norton", AC_INTEGRITY_CHECK, "Norton antivirus detection", 3 },
  { "McAfee", AC_INTEGRITY_CHECK, "McAfee antivirus detection", 3 },
  { "Kaspersky", AC_INTEGRITY_CHECK, "Kaspersky antivirus detection", 3 },
};

//--------------------------------------------------------------------------
plugin_ctx_t::plugin_ctx_t()
  : show_detector_ah(*this),
    main_action(ACTION_DESC_LITERAL_PLUGMOD(
        ACTION_NAME,
        ACTION_LABEL,
        &show_detector_ah,
        this,
        "Ctrl+Shift+A",
        nullptr, -1)),
    detector(*this)
{
}

//--------------------------------------------------------------------------
bool plugin_ctx_t::register_main_action()
{
  return register_action(main_action)
      && attach_action_to_menu("Search/",
                               ACTION_NAME, SETMENU_APP);
}

//--------------------------------------------------------------------------
int idaapi show_detector_ah_t::activate(action_activation_ctx_t *)
{
  ctx.run(0);
  return 0;
}

//--------------------------------------------------------------------------
anticheat_detector_t::anticheat_detector_t(plugin_ctx_t &_ctx) : ctx(_ctx)
{
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
bgcolor_t anticheat_detector_t::get_category_color(artifact_category_t cat)
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
bool anticheat_detector_t::is_suspicious_constant(uint64 val)
{
  // Common constants used in anti-debug/anti-vm
  static const uint64 suspicious_constants[] = {
    0x564D5868, // VMware I/O port
    0x40000000, // VirtualBox CPUID
    0x7FFE0000, // KUSER_SHARED_DATA
    0xC0000000, // Kernel address range
    0x2C,       // ProcessDebugPort
    0x1F,       // ProcessDebugObjectHandle
  };
  
  for (size_t i = 0; i < qnumber(suspicious_constants); i++)
  {
    if (val == suspicious_constants[i])
      return true;
  }
  return false;
}

//--------------------------------------------------------------------------
bool anticheat_detector_t::check_api_calls(ea_t ea, func_t *func)
{
  bool found = false;
  func_item_iterator_t fii;
  
  for (bool fi_ok = fii.set(func); fi_ok; fi_ok = fii.next_code())
  {
    xrefblk_t xb;
    for (bool xb_ok = xb.first_from(fii.current(), XREF_FAR);
         xb_ok && xb.iscode;
         xb_ok = xb.next_from())
    {
      qstring name;
      if (get_name(&name, xb.to) > 0)
      {
        // Check against our API patterns
        for (size_t i = 0; i < qnumber(api_patterns); i++)
        {
          if (strstr(name.c_str(), api_patterns[i].api_name) != nullptr)
          {
            detected_artifact_t artifact;
            artifact.address = fii.current();
            artifact.category = api_patterns[i].category;
            artifact.description = api_patterns[i].description;
            artifact.severity = api_patterns[i].severity;
            artifact.api_used = name;
            artifact.instruction = name; // Store the API name as instruction
            get_func_name(&artifact.function_name, func->start_ea);
            
            artifacts.push_back(artifact);
            found = true;
            
            // Set comment to mark the artifact (only if not already marked)
            qstring cmt;
            get_cmt(&cmt, fii.current(), false);
            if (strstr(cmt.c_str(), "[ACAD]") == nullptr)
            {
              if (!cmt.empty())
                cmt.append(" ");
              cmt.append("[ACAD] ");
              cmt.append(artifact.description);
              set_cmt(fii.current(), cmt.c_str(), false);
            }
          }
        }
      }
    }
  }
  
  return found;
}

//--------------------------------------------------------------------------
bool anticheat_detector_t::check_string_references(ea_t ea, func_t *func)
{
  bool found = false;
  func_item_iterator_t fii;
  
  for (bool fi_ok = fii.set(func); fi_ok; fi_ok = fii.next_code())
  {
    xrefblk_t xb;
    for (bool xb_ok = xb.first_from(fii.current(), XREF_DATA);
         xb_ok;
         xb_ok = xb.next_from())
    {
      qstring str;
      if (get_strlit_contents(&str, xb.to, -1, STRTYPE_C) > 0)
      {
        // Check against string patterns
        for (size_t i = 0; i < qnumber(string_patterns); i++)
        {
          if (stristr(str.c_str(), string_patterns[i].pattern) != nullptr)
          {
            detected_artifact_t artifact;
            artifact.address = fii.current();
            artifact.category = string_patterns[i].category;
            artifact.description.sprnt("%s (string: \"%s\")", 
                                      string_patterns[i].description,
                                      string_patterns[i].pattern);
            artifact.severity = string_patterns[i].severity;
            artifact.instruction.sprnt("String: \"%s\"", string_patterns[i].pattern);
            get_func_name(&artifact.function_name, func->start_ea);
            
            artifacts.push_back(artifact);
            found = true;
            
            // Set comment to mark the artifact (only if not already marked)
            qstring cmt;
            get_cmt(&cmt, fii.current(), false);
            if (strstr(cmt.c_str(), "[ACAD]") == nullptr)
            {
              if (!cmt.empty())
                cmt.append(" ");
              cmt.append("[ACAD] ");
              cmt.append(artifact.description);
              set_cmt(fii.current(), cmt.c_str(), false);
            }
          }
        }
      }
    }
  }
  
  return found;
}

//--------------------------------------------------------------------------
// Helper function for detecting anti-analysis patterns in function prologue
bool anticheat_detector_t::detect_anti_analysis_prologue(ea_t func_ea, func_t *func)
{
  bool found = false;
  func_item_iterator_t fii;
  
  // Check first few instructions of function for anti-analysis patterns
  int check_count = 0;
  for (bool fi_ok = fii.set(func); fi_ok && check_count < 10; fi_ok = fii.next_code(), check_count++)
  {
    ea_t current = fii.current();
    
    if (is_code(get_flags(current)))
    {
      insn_t insn;
      if (decode_insn(&insn, current) > 0)
      {
        // Check for direct stack manipulation that could be anti-debug
        if (insn.itype == NN_push || insn.itype == NN_pop)
        {
          // Look for push/pop of segment registers (common anti-debug)
          if (insn.ops[0].type == o_reg && 
              (insn.ops[0].reg == R_GS || insn.ops[0].reg == R_FS || insn.ops[0].reg == R_SS))
          {
            detected_artifact_t artifact;
            artifact.address = current;
            artifact.category = AC_DEBUGGER_DETECT;
            artifact.description = "Segment register manipulation (potential anti-debug)";
            artifact.severity = 4;
            artifact.instruction = "Segment register push/pop";
            get_func_name(&artifact.function_name, func->start_ea);
            
            artifacts.push_back(artifact);
            found = true;
          }
        }
        
        // Check for CMP with suspicious register patterns
        if (insn.itype == NN_cmp)
        {
          // Comparing with specific debugging-related registers/values
          for (int i = 0; i < UA_MAXOP; i++)
          {
            if (insn.ops[i].type == o_imm)
            {
              // Common constants for anti-debug comparisons
              uint64 val = insn.ops[i].value;
              if (val == 0x00000000 || val == 0xFFFFFFFF || val == 0x40000000 || 
                  val == 0x80000000 || val == 0x7FFFFFFF)
              {
                detected_artifact_t artifact;
                artifact.address = current;
                artifact.category = AC_DEBUGGER_DETECT;
                artifact.description.sprnt("Constant comparison: 0x%llX (potential anti-debug)", val);
                artifact.severity = 3;
                artifact.instruction.sprnt("cmp with 0x%llX", val);
                get_func_name(&artifact.function_name, func->start_ea);
                
                artifacts.push_back(artifact);
                found = true;
              }
            }
          }
        }
      }
    }
  }
  
  return found;
}

//--------------------------------------------------------------------------
bool anticheat_detector_t::check_inline_detection(ea_t ea, func_t *func)
{
  bool found = false;
  func_item_iterator_t fii;
  
  for (bool fi_ok = fii.set(func); fi_ok; fi_ok = fii.next_code())
  {
    ea_t current = fii.current();
    
    // Check for specific instructions
    if (is_code(get_flags(current)))
    {
      insn_t insn;
      if (decode_insn(&insn, current) > 0)
      {
        qstring mnem;
        print_insn_mnem(&mnem, current);
        
        // CPUID (VM detection)
        if (mnem == "cpuid")
        {
          detected_artifact_t artifact;
          artifact.address = current;
          artifact.category = AC_VM_DETECT;
          artifact.description = "CPUID instruction (VM detection)";
          artifact.severity = 4;
          artifact.instruction = "cpuid";
          get_func_name(&artifact.function_name, func->start_ea);
          
          artifacts.push_back(artifact);
          found = true;
          
          // Set comment to mark the artifact (only if not already marked)
          qstring cmt;
          get_cmt(&cmt, current, false);
          if (strstr(cmt.c_str(), "[ACAD]") == nullptr)
          {
            if (!cmt.empty())
              cmt.append(" ");
            cmt.append("[ACAD] ");
            cmt.append(artifact.description);
            set_cmt(current, cmt.c_str(), false);
          }
        }
        
        // RDTSC/RDTSCP (timing check)
        else if (mnem == "rdtsc" || mnem == "rdtscp")
        {
          detected_artifact_t artifact;
          artifact.address = current;
          artifact.category = AC_TIMING_CHECK;
          artifact.description = "RDTSC instruction (timing check)";
          artifact.severity = 3;
          artifact.instruction = mnem;
          get_func_name(&artifact.function_name, func->start_ea);
          
          artifacts.push_back(artifact);
          found = true;
          
          // Set comment to mark the artifact (only if not already marked)
          qstring cmt;
          get_cmt(&cmt, current, false);
          if (strstr(cmt.c_str(), "[ACAD]") == nullptr)
          {
            if (!cmt.empty())
              cmt.append(" ");
            cmt.append("[ACAD] ");
            cmt.append(artifact.description);
            set_cmt(current, cmt.c_str(), false);
          }
        }
        
        // INT 2D (anti-debug) or INT 3
        else if (mnem == "int")
        {
          if (insn.ops[0].type == o_imm && 
              (insn.ops[0].value == 0x2D || insn.ops[0].value == 0x03))
          {
            detected_artifact_t artifact;
            artifact.address = current;
            artifact.category = AC_DEBUGGER_DETECT;
            artifact.description.sprnt("INT %Xh instruction (anti-debug)", insn.ops[0].value);
            artifact.severity = 5;
            artifact.instruction.sprnt("int %Xh", insn.ops[0].value);
            get_func_name(&artifact.function_name, func->start_ea);
            
            artifacts.push_back(artifact);
            found = true;
            
            // Set comment to mark the artifact (only if not already marked)
            qstring cmt;
            get_cmt(&cmt, current, false);
            if (strstr(cmt.c_str(), "[ACAD]") == nullptr)
            {
              if (!cmt.empty())
                cmt.append(" ");
              cmt.append("[ACAD] ");
              cmt.append(artifact.description);
              set_cmt(current, cmt.c_str(), false);
            }
          }
        }
        
        // Check for PEB access (fs:[30h] or gs:[60h] on x64)
        else if (mnem == "mov" && insn.ops[0].type == o_reg)
        {
          // Check if accessing segment registers with specific offsets
          if (insn.ops[1].type == o_mem || insn.ops[1].type == o_displ)
          {
            // Common PEB offsets: 0x30 (x86 fs), 0x60 (x64 gs)
            if (insn.ops[1].addr == 0x30 || insn.ops[1].addr == 0x60)
            {
              detected_artifact_t artifact;
              artifact.address = current;
              artifact.category = AC_DEBUGGER_DETECT;
              artifact.description = "PEB access (potential BeingDebugged check)";
              artifact.severity = 4;
              
              // Get the full instruction text
              qstring insn_text;
              generate_disasm_line(&insn_text, current, GENDSM_FORCE_CODE);
              tag_remove(&insn_text);
              artifact.instruction = insn_text;
              
              get_func_name(&artifact.function_name, func->start_ea);
              
              artifacts.push_back(artifact);
              found = true;
              
              // Set comment to mark the artifact (only if not already marked)
              qstring cmt;
              get_cmt(&cmt, current, false);
              if (strstr(cmt.c_str(), "[ACAD]") == nullptr)
              {
                if (!cmt.empty())
                  cmt.append(" ");
                cmt.append("[ACAD] ");
                cmt.append(artifact.description);
                set_cmt(current, cmt.c_str(), false);
              }
            }
          }
        }
        
        // Check for suspicious constants in operands
        for (int i = 0; i < UA_MAXOP; i++)
        {
          if (insn.ops[i].type == o_imm)
          {
            if (is_suspicious_constant(insn.ops[i].value))
            {
              detected_artifact_t artifact;
              artifact.address = current;
              artifact.category = AC_UNKNOWN;
              artifact.description.sprnt("Suspicious constant: 0x%llX", insn.ops[i].value);
              artifact.severity = 3;
              artifact.instruction.sprnt("0x%llX", insn.ops[i].value);
              get_func_name(&artifact.function_name, func->start_ea);
              
              artifacts.push_back(artifact);
              found = true;
            }
          }
        }
        
        // XLATB instruction (sometimes used in code obfuscation)
        if (mnem == "xlatb")
        {
          detected_artifact_t artifact;
          artifact.address = current;
          artifact.category = AC_INTEGRITY_CHECK;
          artifact.description = "XLATB instruction (potential code obfuscation)";
          artifact.severity = 2;
          artifact.instruction = "xlatb";
          get_func_name(&artifact.function_name, func->start_ea);
          
          artifacts.push_back(artifact);
          found = true;
        }
        
        // LAHF/SAHF pair (can be used for anti-analysis)
        if (mnem == "lahf" || mnem == "sahf")
        {
          detected_artifact_t artifact;
          artifact.address = current;
          artifact.category = AC_DEBUGGER_DETECT;
          artifact.description.sprnt("%s instruction (flag manipulation)", mnem.c_str());
          artifact.severity = 2;
          artifact.instruction = mnem;
          get_func_name(&artifact.function_name, func->start_ea);
          
          artifacts.push_back(artifact);
          found = true;
        }
        
        // SysEnter/SysExit (direct syscall)
        if (mnem == "sysenter" || mnem == "sysexit")
        {
          detected_artifact_t artifact;
          artifact.address = current;
          artifact.category = AC_PROTECTION_CHECK;
          artifact.description.sprnt("%s instruction (direct kernel call)", mnem.c_str());
          artifact.severity = 4;
          artifact.instruction = mnem;
          get_func_name(&artifact.function_name, func->start_ea);
          
          artifacts.push_back(artifact);
          found = true;
        }
        
        // PREFETCH instructions (can indicate timing side-channel attacks)
        if (strstr(mnem.c_str(), "prefetch") != nullptr)
        {
          detected_artifact_t artifact;
          artifact.address = current;
          artifact.category = AC_TIMING_CHECK;
          artifact.description = "PREFETCH instruction (cache timing attack indicator)";
          artifact.severity = 2;
          artifact.instruction = mnem;
          get_func_name(&artifact.function_name, func->start_ea);
          
          artifacts.push_back(artifact);
          found = true;
        }
        
        // CLFLUSH instruction (cache flushing for timing attacks)
        if (mnem == "clflush" || mnem == "clflushopt")
        {
          detected_artifact_t artifact;
          artifact.address = current;
          artifact.category = AC_TIMING_CHECK;
          artifact.description = "CLFLUSH instruction (cache flushing - timing attack)";
          artifact.severity = 3;
          artifact.instruction = mnem;
          get_func_name(&artifact.function_name, func->start_ea);
          
          artifacts.push_back(artifact);
          found = true;
        }
        
        // LFENCE/SFENCE/MFENCE (memory barriers - often used in anti-timing-attack)
        if (mnem == "lfence" || mnem == "sfence" || mnem == "mfence")
        {
          detected_artifact_t artifact;
          artifact.address = current;
          artifact.category = AC_TIMING_CHECK;
          artifact.description.sprnt("%s instruction (memory fence - constant-time execution)", mnem.c_str());
          artifact.severity = 2;
          artifact.instruction = mnem;
          get_func_name(&artifact.function_name, func->start_ea);
          
          artifacts.push_back(artifact);
          found = true;
        }
        
        // PAUSE instruction (timing adjustment)
        if (mnem == "pause")
        {
          detected_artifact_t artifact;
          artifact.address = current;
          artifact.category = AC_TIMING_CHECK;
          artifact.description = "PAUSE instruction (timing adjustment)";
          artifact.severity = 2;
          artifact.instruction = "pause";
          get_func_name(&artifact.function_name, func->start_ea);
          
          artifacts.push_back(artifact);
          found = true;
        }
      }
    }
  }
  
  // Call the new prologue detector
  if (detect_anti_analysis_prologue(ea, func))
    found = true;
  
  return found;
}

//--------------------------------------------------------------------------
void anticheat_detector_t::scan_function(func_t *func)
{
  if (func == nullptr)
    return;
    
  msg("Scanning function at %a\n", func->start_ea);
  
  check_api_calls(func->start_ea, func);
  check_string_references(func->start_ea, func);
  check_inline_detection(func->start_ea, func);
}

//--------------------------------------------------------------------------
void anticheat_detector_t::scan_all_functions()
{
  clear_results();
  msg("Starting anti-cheat artifact scan...\n");
  
  size_t func_qty = get_func_qty();
  for (size_t i = 0; i < func_qty; i++)
  {
    func_t *func = getn_func(i);
    if (func != nullptr)
      scan_function(func);
      
    if ((i % 100) == 0)
      msg("Progress: %d/%d functions\n", i, func_qty);
  }
  
  msg("Scan complete! Found %d artifacts\n", artifacts.size());
  show_results();
}

//--------------------------------------------------------------------------
void anticheat_detector_t::scan_current_function()
{
  clear_results();
  
  func_t *func = get_func(get_screen_ea());
  if (func == nullptr)
  {
    warning("Please position cursor in a function!");
    return;
  }
  
  msg("Scanning current function...\n");
  scan_function(func);
  msg("Found %d artifacts in current function\n", artifacts.size());
  show_results();
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
    info("No anti-cheat artifacts detected!");
    return;
  }
  
  artifact_chooser_t chooser(*this);
  chooser.choose();
}

//--------------------------------------------------------------------------
void anticheat_detector_t::export_results(const char *filename)
{
  FILE *f = qfopen(filename, "w");
  if (f == nullptr)
  {
    warning("Failed to open file for writing!");
    return;
  }
  
  qfprintf(f, "Anti-Cheat Artifact Detection Report\n");
  qfprintf(f, "=====================================\n\n");
  qfprintf(f, "Total artifacts found: %d\n\n", artifacts.size());
  
  for (const auto &artifact : artifacts)
  {
    qfprintf(f, "Address: %a\n", artifact.address);
    qfprintf(f, "Function: %s\n", artifact.function_name.c_str());
    qfprintf(f, "Instruction: %s\n", artifact.instruction.c_str());
    qfprintf(f, "Category: %s\n", get_category_name(artifact.category));
    qfprintf(f, "Severity: %d/5\n", artifact.severity);
    qfprintf(f, "Description: %s\n", artifact.description.c_str());
    if (!artifact.api_used.empty())
      qfprintf(f, "API: %s\n", artifact.api_used.c_str());
    qfprintf(f, "\n");
  }
  
  qfclose(f);
  msg("Report exported to %s\n", filename);
}

//--------------------------------------------------------------------------
// Artifact chooser implementation
const int artifact_chooser_t::widths_[] =
{
  CHCOL_HEX | 10, // Address
  15,             // Function
  25,             // Instruction
  20,             // Category
  5,              // Severity
  40,             // Description
};

const char *const artifact_chooser_t::header_[] =
{
  "Address",
  "Function",
  "Instruction",
  "Category",
  "Severity",
  "Description",
};

artifact_chooser_t::artifact_chooser_t(anticheat_detector_t &det)
  : chooser_t(CH_MODAL | CH_KEEP,
              qnumber(widths_), widths_, header_,
              "Anti-Cheat Artifacts"),
    detector(det)
{
}

size_t idaapi artifact_chooser_t::get_count() const
{
  return detector.artifacts.size();
}

void idaapi artifact_chooser_t::get_row(
      qstrvec_t *cols,
      int *icon_,
      chooser_item_attrs_t *attrs,
      size_t n) const
{
  const detected_artifact_t &artifact = detector.artifacts[n];
  qstrvec_t &cols_ref = *cols;
  
  cols_ref[0].sprnt("%a", artifact.address);
  cols_ref[1] = artifact.function_name;
  cols_ref[2] = artifact.instruction;
  cols_ref[3] = detector.get_category_name(artifact.category);
  cols_ref[4].sprnt("%d/5", artifact.severity);
  cols_ref[5] = artifact.description;
  
  if (attrs != nullptr)
    attrs->color = detector.get_category_color(artifact.category);
}

chooser_t::cbret_t idaapi artifact_chooser_t::enter(size_t n)
{
  if (n < detector.artifacts.size())
    jumpto(detector.artifacts[n].address);
  return cbret_t(0, chooser_base_t::ALL_CHANGED);
}

//--------------------------------------------------------------------------
bool idaapi plugin_ctx_t::run(size_t arg)
{
  static const char form[] =
    "Anti-Cheat Artifact Detector\n"
    "\n"
    "Select scan mode:\n"
    "\n"
    " <~S~can current function:R>\n"
    " <Scan ~a~ll functions:R>>\n"
    "\n";
    
  int scan_mode = 0;
  if (!ask_form(form, &scan_mode))
    return false;
    
  if (scan_mode == 0)
    detector.scan_current_function();
  else
    detector.scan_all_functions();
    
  return true;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  if (!is_idaq())
    return nullptr;
    
  plugin_ctx_t *ctx = new plugin_ctx_t;
  if (!ctx->register_main_action())
  {
    msg("Failed to register menu item for <" ACTION_LABEL "> plugin!\n");
    delete ctx;
    return nullptr;
  }
  
  set_module_data(&data_id, ctx);
  msg("Anti-Cheat Artifact Detector loaded!\n");
  msg("Use " ACTION_LABEL " from Search menu or press Ctrl+Shift+A\n");
  
  return ctx;
}

//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,
  init,
  nullptr,
  nullptr,
  "Anti-Cheat Artifact Detector - Identifies debugger checks, VM detection, and other anti-analysis techniques",
  "Anti-Cheat Artifact Detector plugin for IDA Pro\n"
  "\n"
  "Detects common anti-cheat techniques including:\n"
  "- Debugger detection APIs\n"
  "- VM detection methods\n"
  "- Integrity checks\n"
  "- Timing-based detection\n"
  "- Hardware breakpoint checks\n"
  "- Process/module enumeration\n",
  ACTION_LABEL,
  ""
};