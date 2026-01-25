#ifndef __ANTICHEAT_DETECTOR__
#define __ANTICHEAT_DETECTOR__

#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <segment.hpp>
#include <funcs.hpp>
#include <xref.hpp>
#include <ua.hpp>
#include <lines.hpp>
#include <allins.hpp>
#include <diskio.hpp>
#include <map>
#include <vector>
#include <string>

#define ACTION_NAME "anticheat:DetectArtifacts"
#define ACTION_LABEL "Anti-Cheat Artifacts Detector"

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
  ea_t address;
  artifact_category_t category;
  qstring description;
  qstring function_name;
  int severity; // 1-5, 5 being highest
  qstring api_used;
  qstring instruction; // The actual instruction/API at this location
};

struct plugin_ctx_t;

//--------------------------------------------------------------------------
// Anti-cheat artifact detector class
class anticheat_detector_t
{
public:
  plugin_ctx_t &ctx;
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

  // Instruction patterns for inline checks
  struct insn_pattern_t
  {
    const char *description;
    artifact_category_t category;
    int severity;
  };

  bool check_api_calls(ea_t ea, func_t *func);
  bool check_string_references(ea_t ea, func_t *func);
  bool check_inline_detection(ea_t ea, func_t *func);
  bool detect_anti_analysis_prologue(ea_t func_ea, func_t *func);
  bool is_suspicious_constant(uint64 val);
  
public:
  anticheat_detector_t(plugin_ctx_t &_ctx);
  
  void scan_function(func_t *func);
  void scan_all_functions();
  void scan_current_function();
  void clear_results();
  
  const char *get_category_name(artifact_category_t cat);
  bgcolor_t get_category_color(artifact_category_t cat);
  
  void show_results();
  void export_results(const char *filename);
};

//--------------------------------------------------------------------------
// Chooser for displaying detected artifacts
class artifact_chooser_t : public chooser_t
{
protected:
  static const int widths_[];
  static const char *const header_[];
  anticheat_detector_t &detector;

public:
  artifact_chooser_t(anticheat_detector_t &det);
  
  virtual size_t idaapi get_count() const override;
  virtual void idaapi get_row(
        qstrvec_t *cols,
        int *icon_,
        chooser_item_attrs_t *attrs,
        size_t n) const override;
  virtual cbret_t idaapi enter(size_t n) override;
};

//--------------------------------------------------------------------------
// Main action handler
struct show_detector_ah_t : public action_handler_t
{
  plugin_ctx_t &ctx;
  show_detector_ah_t(plugin_ctx_t &_ctx) : ctx(_ctx) {}
  virtual int idaapi activate(action_activation_ctx_t *) override;
  virtual action_state_t idaapi update(action_update_ctx_t *) override
  {
    return AST_ENABLE_ALWAYS;
  }
};

//--------------------------------------------------------------------------
// Plugin context
struct plugin_ctx_t : public plugmod_t
{
  show_detector_ah_t show_detector_ah;
  const action_desc_t main_action;
  anticheat_detector_t detector;
  
  plugin_ctx_t();
  bool register_main_action();
  virtual bool idaapi run(size_t arg) override;
};

#endif