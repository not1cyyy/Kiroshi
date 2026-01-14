#include "binaryninjaapi.h"
#include "bn_anticheat_detector.h"

//--------------------------------------------------------------------------
// Main plugin entry point
extern "C" {
    BN_DECLARE_CORE_ABI_VERSION

    BINARYNINJAPLUGIN bool CorePluginInit()
    {
        // Register the anti-cheat detector command
        PluginCommand::Register("Anti-Cheat Detector\\Scan All Functions",
                               "Run anti-cheat artifact detection on all functions",
                               [](BinaryView* bv) {
            anticheat_detector_t detector(bv);
            detector.scan_all_functions();
        });

        PluginCommand::Register("Anti-Cheat Detector\\Scan Current Function",
                               "Run anti-cheat artifact detection on current function",
                               [](BinaryView* bv) {
            anticheat_detector_t detector(bv);
            detector.scan_current_function();
        });

        PluginCommand::Register("Anti-Cheat Detector\\Clear Results",
                               "Clear all detected artifacts",
                               [](BinaryView* bv) {
            anticheat_detector_t detector(bv);
            detector.clear_results();
        });

        PluginCommand::Register("Anti-Cheat Detector\\Export Results",
                               "Export detection results to file",
                               [](BinaryView* bv) {
            // For now, export to a default filename
            anticheat_detector_t detector(bv);
            detector.export_results("anticheat_results.txt");
        });

        LogInfo("Binary Ninja Anti-Cheat Artifact Detector loaded!");
        LogInfo("Use 'Anti-Cheat Detector' commands from the Tools menu");

        return true;
    }
}