#include "util.h"

#include <fstream>
#include <string>
#include <iostream>
#include <vector>
#include <functional>
#include <filesystem>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>

namespace VirtualMachineDetection
{
namespace
{
    
constexpr auto VMWARE_HYPERVISOR_MAGIC = 0x564D5868;
constexpr auto VMWARE_HYPERVISOR_PORT = 0x5658;
constexpr auto VMWARE_PORT_CMD_GETVERSION = 10;
constexpr auto UINT_MAX = 0xFFFFFFFF;

bool doesBiosVendorBelongToVM()
{
    return Util::doesAnyWordExistInFile("/sys/class/dmi/id/bios_vendor", { "vmware", "vbox", "Phoenix", "innotek" });
}		

bool doesProductVendorBelongToVM()
{
    return Util::doesAnyWordExistInFile("/sys/class/dmi/id/product_name", { "VMware", "VirtualBox", "Phoenix", "innotek" });
}	

bool doesSystemVendorBelongToVM()
{
    return Util::doesAnyWordExistInFile("/sys/class/dmi/id/sys_vendor", { "VMware", "VirtualBox", "Phoenix", "innotek" });
}
	
bool doesBoardVendorBelongToVM()
{
    return Util::doesAnyWordExistInFile("/sys/class/dmi/id/board_vendor", { "VMware", "VirtualBox", "Phoenix", "innotek", "Oracle" });
}
	
bool doesVMKernelModulesExist()
{
    return Util::doesAnyWordExistInFile("/proc/modules", { "vmw_balloon", "vmwfgx", "vboxvideo", "vboxguest" });
}

bool doesSCSIBelongToVM()
{
    return Util::doesAnyWordExistInFile("/proc/scsi/scsi", { "VMware", "VBOX" });
}

bool isHypervisorPresent()
{
    return Util::doesAnyWordExistInFile("/proc/cpuinfo", { "hypervisor" });
}

bool checkVMPresence()
{
    return Util::doesAnyFilenameExistInDirectory("/usr/bin/", {"vmware-", "vbox", "qemu"});
}

bool checkHwBit()
{

	int ecx = 0;
	__asm__ volatile("cpuid" \
			: "=c"(ecx) \
			: "a"(0x01));
   return (ecx >> 31) & 0x1;
   
}

int checkHWVendor()
{
    bool isVM = false;
	int i = 0;
	char vendor[13];
	std::string strings[2]={"VMwareVMware","KVMKVMKVM"};
	int ecx = 0, ebx = 0, edx = 0;
	__asm__ volatile("cpuid" \
			: "=b"(ebx),"=c"(ecx),"=d"(edx) \
			: "a"(0x40000000));
   	sprintf(vendor  , "%c%c%c%c", ebx, (ebx >> 8), (ebx >> 16), (ebx >> 24));
	sprintf(vendor+4, "%c%c%c%c", ecx, (ecx >> 8), (ecx >> 16), (ecx >> 24));
	sprintf(vendor+8, "%c%c%c%c", edx, (edx >> 8), (edx >> 16), (edx >> 24));
	vendor[12] = 0x00;
	for(i = 0; i < 2; i++)
	{
		if(strcmp(strings[i].c_str(),vendor) == 0)
			isVM = true;
			
	}
	
	return isVM;
   
}

int checkRtdscDiff() {
	unsigned long long ret, ret2;
	unsigned eax, edx;
	__asm__ volatile("rdtsc" : "=a" (eax), "=d" (edx));
	ret  = ((unsigned long long)eax) | (((unsigned long long)edx) << 32);
	/* vm exit forced here. it uses: eax = 0; cpuid; */
	__asm__ volatile("cpuid" : /* no output */ : "a"(0x00));
	/**/
	__asm__ volatile("rdtsc" : "=a" (eax), "=d" (edx));
	ret2  = ((unsigned long long)eax) | (((unsigned long long)edx) << 32);
	return ret2 - ret;
}

bool checkVmexitInstruction()
{
    bool isVm = false;
	int avg = 0, sum = 0, sub, i;
	for (i = 0; i < 10; i++) {
		sub = checkRtdscDiff();
		sum=+ sub;
		sleep(1);
	}
	avg=sum/10;
	
	if(avg<0 || avg>750)
	{
		isVm = true;
	}
	
	return isVm;
}

void handler(int signal)
{
    Util::prettyPrint("Checkin IN instruction:", [] { return false; });
    exit(0);    
}

bool checkInInstruction()
{
    bool isVM = false;

    int eax = 0, ebx = 0, ecx = 0, edx = 0;

    signal(SIGSEGV, handler);

    __asm__ volatile("inl (%%dx)" 
            : "=a"(eax),"=c"(ecx),"=d"(edx),"=b"(ebx)\
            : "a"(VMWARE_HYPERVISOR_MAGIC),	"c" ( VMWARE_PORT_CMD_GETVERSION),"d"(VMWARE_HYPERVISOR_PORT), "b"(UINT_MAX)
            );

    if(ebx==0x564D5868)
    {
        //VMWare
        isVM = true;
    }
	
	return isVM;
} 

bool checkMacAddresses(const std::vector<std::string>& macAddressSuffixes, const std::string& macAddressFilepath)
{
    bool anyMacAddressPrefixExists = false;
    
    try
    {
        std::ifstream fileStream(macAddressFilepath);
        std::string interfaceMacAddress = "";
        fileStream >> interfaceMacAddress;
        
        for (const auto& macAddressSuffix : macAddressSuffixes)
        {
            if (interfaceMacAddress.find(macAddressSuffix) == 0)
            {
                anyMacAddressPrefixExists = true;
                break;
            }
        }
    }
    catch (std::ifstream::failure e)
    {
        
    }
    
    return anyMacAddressPrefixExists;
}

bool doesMacBelongToVMWare()
{
	return checkMacAddresses({ "00:05:69","00:0c:29", "00:0C:29", "00:1C:14", "00:1c:14", "00:50:56" }, "/sys/class/net/ens33/address");
}
			
bool doesMacBelongToVirtualBox()
{
	return checkMacAddresses({ "08:00:27" }, "/sys/class/net/enp0s3/address");
}

bool checkMacAddress()
{
    return doesMacBelongToVirtualBox() || doesMacBelongToVMWare();
}

} // anonymmous namespace

void isInVirtualMachine()
{
    std::cout << "Testing virtualized environment:" << std::endl;
    
    Util::prettyPrint("\tChecking bios vendor:", doesBiosVendorBelongToVM);
    Util::prettyPrint("\tChecking product vendor:", doesProductVendorBelongToVM);
    Util::prettyPrint("\tChecking system vendor:", doesSystemVendorBelongToVM);
    Util::prettyPrint("\tChecking board vendor:", doesBoardVendorBelongToVM);
    Util::prettyPrint("\tChecking Kernel modules:", doesVMKernelModulesExist);
    Util::prettyPrint("\tChecking SCSI:", doesSCSIBelongToVM);
    Util::prettyPrint("\tChecking Hypervisor flag:", isHypervisorPresent);
    Util::prettyPrint("\tChecking VM presence:", checkVMPresence);
    Util::prettyPrint("\tChecking MAC address:", checkMacAddress);
    Util::prettyPrint("\tChecking Hypervisor bit:", checkHwBit);
    Util::prettyPrint("\tChecking time of VMEXIT:", checkVmexitInstruction);
    Util::prettyPrint("\tChecking virtualization vendor:", checkHWVendor);
    
    // Has to be last Util::prettyPrint. If executed in VirtualBox VM or host OS it will exit program execution.
    Util::prettyPrint("\tChecking IN instruction:", checkInInstruction);
    
    std::cout << std::endl;
}

} // VirtualMachineDetection
