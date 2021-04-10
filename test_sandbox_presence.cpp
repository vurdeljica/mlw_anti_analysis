#include "test_sandbox_presence.h"

#include "util.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/sysinfo.h>
#include <stdbool.h>
#include <string>
#include <thread>
#include <unistd.h>

namespace SandboxDetection
{
namespace
{

using namespace std::chrono;    

namespace fs = std::filesystem;
    
std::vector<std::string> commonAnalysisTools = { "x32dbg", "x64dbg", "ghidra", "r2", "radare2", "gdb", "ida", 
                                                 "binwalk", "olly", "wireshark", "windbg", "immunity", "dumpcap"};
                                                 
std::vector<std::string> commonProgramNames = { "sample", "bot", "sandbox", "malware", "test", "klavme", "myapp", "testapp" };

constexpr int MAX_PATH_LEN = 300;
    
bool checkIfProgramIsTracedWithProcFs()
{
    const std::string noTracerText = "TracerPid:\t0";
    return (!Util::doesAnyWordExistInFile("/proc/self/status", { noTracerText }));
}
    
bool checkIfProgramIsTracedWithPtrace()
{
    return (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1);
}

bool isPtraceMonkeyPatched()
{
    return (ptrace(PTRACE_TRACEME, 0, 1, 0) == 0 && ptrace(PTRACE_TRACEME, 0, 1, 0) == 0);
}

bool areAnalysisToolsActive()
{
    const std::string processesPath = "/proc";
    for (const auto& entry : fs::directory_iterator(processesPath))
    {
        const bool isDirectory = fs::is_directory(entry.path().string());
        const bool isProcessDirectory = Util::isNumber(entry.path().filename().string());
        if (isDirectory && isProcessDirectory)
        {
            std::ifstream infile(entry.path().string() + "/comm");
            std::string procName = "";
            std::getline(infile, procName);
            
            if (std::find_if(commonAnalysisTools.begin(), commonAnalysisTools.end(), 
                [&] (const std::string& analysisTool) { return (procName.find(analysisTool) != std::string::npos); }) != commonAnalysisTools.end())
            {
                return true;
            }
        }
    }
    
    return false;
}

bool areAnalysisToolsPresentOnTheSystem()
{
    const std::vector<std::string> installPaths = { "/bin", "/sbin", "/usr/bin", "/usr/sbin" };
    for (const auto& installPath : installPaths)
    {
        if (Util::doesAnyFilenameExistInDirectory(installPath, commonAnalysisTools))
        {
            return true;
        }
    }
    
    return false;
}

std::string getProgramName()
{
    char programNamePathPtr[MAX_PATH_LEN];
    ssize_t len = readlink("/proc/self/exe", programNamePathPtr, MAX_PATH_LEN);
    if (len == -1)
    {
        return "unknown";
    }
    
    programNamePathPtr[len] = '\0';
    const std::string programNamePath = std::string(programNamePathPtr);
    
    return programNamePath.substr(programNamePath.find_last_of("/\\") + 1);
}

bool isProgramNamesKnownFileName()
{
    const std::string programName = getProgramName();
    
    for (const std::string& commonProgramName : commonProgramNames)
    {
        if (programName.find(commonProgramName) != std::string::npos)
        {
            return true;
        }
    }
     
    
    return false;
}

bool isProgramNameMD5Hash()
{
    const std::string programName = getProgramName();
    return (programName.size() == 32 && programName.find_first_not_of("0123456789abcdefABCDEF") == -1);
}

bool checkNumberOfCpuCores()
{
    const auto processorCount = std::thread::hardware_concurrency();
    return (processorCount == 1);
}

bool checkTotalDiskSize()
{
    const size_t diskSize = (size_t)8 * 1024 * 1024 * 1024; // 8 GB 
    const fs::space_info si = fs::space(".");
    return (si.capacity < diskSize);
}

bool checkAvailableDiskSize()
{
    const size_t minAvailSize = (size_t)5 * 1024 * 1024 * 1024; // 5 GB 
    const fs::space_info si = fs::space(".");
    return (si.available < minAvailSize);
}

bool checkAcceleratedSleepViaSysinfo()
{
    const int sleepPeriodMs = 20 * 1000;
    std::chrono::milliseconds startUptime(0u);
    std::chrono::milliseconds endUptime(0u);
    
    struct sysinfo x;
    if (sysinfo(&x) == 0)
    {
        startUptime = std::chrono::milliseconds(static_cast<unsigned long long>(x.uptime) * 1000ULL);
    }
    
    usleep(sleepPeriodMs * 1000);
    
    if (sysinfo(&x) == 0)
    {
        endUptime = std::chrono::milliseconds(static_cast<unsigned long long>(x.uptime) * 1000ULL);
    }
    
    return (endUptime - startUptime < std::chrono::milliseconds(sleepPeriodMs - 1));
}

bool checkAcceleratedSleepViaProcUptime()
{
    const int sleepPeriodMs = 20 * 1000;
    std::chrono::milliseconds startUptime(0u);
    std::chrono::milliseconds endUptime(0u);
    
    double uptime_seconds = 0;
    if (std::ifstream("/proc/uptime", std::ios::in) >> uptime_seconds)
    {
        startUptime = std::chrono::milliseconds(static_cast<unsigned long long>(uptime_seconds * 1000.0));
    }
    
    usleep(sleepPeriodMs * 1000);
    
    if (std::ifstream("/proc/uptime", std::ios::in) >> uptime_seconds)
    {
        endUptime = std::chrono::milliseconds(static_cast<unsigned long long>(uptime_seconds * 1000.0));
    }
    
    return (endUptime - startUptime < std::chrono::milliseconds(sleepPeriodMs - 1));
}

} // anonymous namespace

void isInSandbox()
{
    std::cout << "Testing sandboxed environment:" << std::endl;
    
    Util::prettyPrint("\tChecking if program is traced with proc file system:", checkIfProgramIsTracedWithProcFs);
    Util::prettyPrint("\tChecking if program is traced with ptrace():", checkIfProgramIsTracedWithPtrace);
    Util::prettyPrint("\tChecking if ptrace is monkey patched:", isPtraceMonkeyPatched);
    Util::prettyPrint("\tChecking for active analysis tools:", areAnalysisToolsActive);
    Util::prettyPrint("\tChecking for installed analysis tools:", areAnalysisToolsPresentOnTheSystem);
    Util::prettyPrint("\tChecking program name for common names:", isProgramNamesKnownFileName);
    Util::prettyPrint("\tChecking is program name md5 hash:", isProgramNameMD5Hash);
    Util::prettyPrint("\tChecking number of cpu cores:", checkNumberOfCpuCores);
    Util::prettyPrint("\tChecking total disk size:", checkTotalDiskSize);
    Util::prettyPrint("\tChecking available disk size:", checkAvailableDiskSize);
    Util::prettyPrint("\tChecking for accelerated sleep via sysinfo:", checkAcceleratedSleepViaSysinfo);
    Util::prettyPrint("\tChecking for accelerated sleep via /proc/uptime:", checkAcceleratedSleepViaProcUptime);
    
    std::cout << std::endl;
}

} // SadboxDetection namespace
