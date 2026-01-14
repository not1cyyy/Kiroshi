# Binary Ninja Anti-Cheat Artifacts Detector

This is a port of the IDA Pro Anti-Cheat Artifacts Detector plugin to Binary Ninja. It identifies common anti-cheat techniques used in game protection systems.

## Features

- **API Detection**: Identifies calls to known anti-cheat APIs (IsDebuggerPresent, timing functions, exception handlers, etc.)
- **String Pattern Matching**: Detects suspicious strings indicating anti-cheat presence
- **Instruction Analysis**: Finds anti-debug instructions (CPUID, RDTSC, INT instructions)
- **Memory Analysis**: Detects memory enumeration and executable memory allocation
- **Exception Handler Detection**: Identifies custom exception handlers for monitoring
- **Service Interaction**: Detects communication with anti-cheat drivers/services
- **Network Monitoring**: Identifies network packet inspection code
- **File System Checks**: Detects file integrity verification
- **Registry Monitoring**: Identifies registry key monitoring
- **Constant Analysis**: Identifies suspicious constants used in anti-cheat code
- **Comment Tagging**: Automatically adds comments to detected artifacts
- **Export Functionality**: Export results to text file

## Building

### Prerequisites

1. Binary Ninja installed
2. CMake 3.24 or later
3. C++20 compatible compiler
4. Binary Ninja API headers (cloned to match your BN version)

### Build Steps

1. Clone the binaryninja-api repository and checkout the correct revision:
   ```bash
   git clone https://github.com/Vector35/binaryninja-api.git
   cd binaryninja-api
   # Check api_REVISION.txt in your BN install directory for the correct revision
   git checkout <revision>
   ```

2. Build the plugin:
   ```bash
   mkdir build
   cd build
   cmake ..
   cmake --build .
   cmake --install .
   ```

## Usage

After building and installing:

1. Load a binary in Binary Ninja
2. Go to Tools → Anti-Cheat Detector
3. Choose "Scan All Functions" or "Scan Current Function"
4. View results in the log console
5. Use "Export Results" to save findings to a file
6. Detected artifacts will be marked with comments in the disassembly

## Detected Artifacts

### Categories

- **Debugger Detection**: Checks for attached debuggers
- **VM Detection**: Virtual machine detection techniques
- **Integrity Check**: Memory/process integrity verification
- **Timing Check**: Anti-timing attack measures
- **Hardware Breakpoint**: Debug register manipulation
- **Process Enumeration**: Running process inspection
- **Module Enumeration**: Loaded module checking
- **Thread Context**: Thread context manipulation
- **Protection Check**: Memory protection operations

### Severity Levels

- 1-2: Low suspicion
- 3-4: Medium suspicion
- 5: High suspicion (critical anti-cheat indicators)

## License

MIT License - see LICENSE file for details