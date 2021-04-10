#include "test_auto_analysis.h"

#include "util.h"

#include <sys/epoll.h>
#include <unistd.h>
#include <string>
#include <filesystem>
#include <iostream>
#include <fcntl.h>
#include <array>
#include <chrono>

namespace AutoAnalysisDetection
{
namespace
{

using namespace std::chrono;
    
namespace fs = std::filesystem;
constexpr auto MAX_NUM_OF_EVENTS = 32;
constexpr auto MAX_TIME_TO_WAIT_MS = 10000;
constexpr auto MAX_NUM_OF_EVENTS_FOR_DETECTING_AUTO_ANALYSIS = 10;
constexpr auto EPOLL_WAIT_TIME = 1000;

constexpr auto SLEEP_PERIOD_S = 300;
    
// Requires root privileges
bool checkInputEvents()
{
    int epollfd = epoll_create1(0);
    if (epollfd == -1)
    {
        std::cout << "epoll_create1 failed" << std::endl;
        return false;
    }
            
    const std::string directoryPath = "/dev/input";
    for (const auto& entry : fs::directory_iterator(directoryPath))
    {
        const bool isFile = (!fs::is_directory(entry.path().string()));
        
        const int fd = open(entry.path().string().c_str(), O_RDONLY);
        if (fd == -1)
        {
            //std::cout << "ERRROR!!!!!" << std::endl;
            continue;
        }
        
        if (isFile)
        {
            struct epoll_event event;
            event.data.fd = fd;
            event.events = EPOLLIN | EPOLLET;
            
            if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event) == -1)
            {
                std::cout << "Epoll ctl failed" << std::endl;
            }
            
        }
    }
    
    std::array<struct epoll_event, MAX_NUM_OF_EVENTS> events;
    int totalNumberOfEvents = 0;
        
    const milliseconds startEventListeningTimestamp = duration_cast<milliseconds>(system_clock::now().time_since_epoch());
    const milliseconds endEventListeningTimestamp = startEventListeningTimestamp + std::chrono::milliseconds(MAX_TIME_TO_WAIT_MS);
    
    while (duration_cast<milliseconds>(system_clock::now().time_since_epoch()) < endEventListeningTimestamp)
    {
        auto n = epoll_wait(epollfd, events.data(), MAX_NUM_OF_EVENTS, EPOLL_WAIT_TIME);
        totalNumberOfEvents += n;
    }
    
    const bool isAutoAnalysis = (totalNumberOfEvents < MAX_NUM_OF_EVENTS_FOR_DETECTING_AUTO_ANALYSIS);
    return isAutoAnalysis;

}

bool stallExecutionBySleeping()
{
    sleep(SLEEP_PERIOD_S);
    return false;
}

} // anonymous namespace

void isAutoAnalyzed()
{
    std::cout << "Testing automated analysis:" << std::endl;
    
    Util::prettyPrint("\tChecking for input events:", checkInputEvents);
    //Util::prettyPrint("\tStalling execution by sleeping:", stallExecutionBySleeping);
    
    std::cout << std::endl;
}

} // AutoAnalysisDetection
