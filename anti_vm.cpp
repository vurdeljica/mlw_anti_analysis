#include "test_vm_presence.h"
#include "test_sandbox_presence.h"
#include "test_auto_analysis.h"

int main()
{
    SandboxDetection::isInSandbox();
    AutoAnalysisDetection::isAutoAnalyzed();
    VirtualMachineDetection::isInVirtualMachine();
    
    return 0;
}
