#ifndef __BN_ANTICHEAT_DETECTOR__
#define __BN_ANTICHEAT_DETECTOR__

#include "binaryninjaapi.h"
#include <vector>
#include <string>
#include <map>
#include <chrono>

// Energy monitoring structure
struct energy_usage_t
{
  double cpu_time_seconds;
  double ram_usage_mb;
  double energy_consumed_wh;
  double carbon_emitted_kg;
  double water_consumed_liters;
  double carbon_credit_cost_usd;
  std::chrono::steady_clock::time_point start_time;
  std::chrono::steady_clock::time_point end_time;
};

// Anti-cheat artifact categories
enum artifact_category_t
{
  AC_DEBUGGER_DETECT,
  AC_VM_DETECT,
  AC_INTEGRITY_CHECK,
  AC_TIMING_CHECK,
  AC_HARDWARE_BREAKPOINT,
  AC_PROCESS_ENUM,
  AC_MODULE_ENUM,
  AC_THREAD_CONTEXT,
  AC_PROTECTION_CHECK,
  AC_UNKNOWN
};

// Detected artifact structure
struct detected_artifact_t
{
  uint64_t address;
  artifact_category_t category;
  std::string description;
  std::string function_name;
  int severity; // 1-5, 5 being highest
  std::string api_used;
  std::string instruction; // The actual instruction/API at this location
};

//--------------------------------------------------------------------------
// Anti-cheat artifact detector class
class anticheat_detector_t
{
public:
  BinaryView* bv;
  std::vector<detected_artifact_t> artifacts;

private:
  // API patterns to detect
  struct api_pattern_t
  {
    const char *api_name;
    artifact_category_t category;
    const char *description;
    int severity;
  };

  static const api_pattern_t api_patterns[];
  
  // String patterns that indicate anti-cheat
  struct string_pattern_t
  {
    const char *pattern;
    artifact_category_t category;
    const char *description;
    int severity;
  };
  
  static const string_pattern_t string_patterns[];

  bool check_api_calls(Function* func);
  bool check_string_references(Function* func);
  bool check_inline_detection(Function* func);
  bool check_memory_enumeration(Function* func);
  bool check_executable_memory_modification(Function* func);
  bool is_suspicious_constant(uint64 val);
  
  // Energy monitoring methods
  void start_energy_monitoring();
  void stop_energy_monitoring();
  void calculate_energy_usage();
  double get_current_cpu_usage();
  double get_current_ram_usage();
  double calculate_carbon_emissions(double energy_wh);
  double calculate_water_consumption(double energy_wh);
  double calculate_carbon_credit_cost(double carbon_kg);
  
public:
  anticheat_detector_t(BinaryView* _bv);
  
  void scan_function(Function* func);
  void scan_all_functions();
  void scan_current_function();
  void clear_results();
  
  const char *get_category_name(artifact_category_t cat);
  uint32_t get_category_color(artifact_category_t cat);
  
  void show_results();
  void export_results(const char *filename);
  
  // Energy monitoring data
  energy_usage_t energy_usage;
};

#endif