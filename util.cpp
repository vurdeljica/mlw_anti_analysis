#include "util.h"

#include <fstream>
#include <string>
#include <iostream>
#include <vector>
#include <functional>
#include <filesystem>
#include <string.h>
 
namespace Util
{
    
namespace
{
    
namespace fs = std::filesystem;

bool isWordPresentInLine(const std::string& word, const std::string& line)
{
    return (line.find(word) != std::string::npos);
}

bool isAnyWordPresentInLine(const std::vector<std::string>& words, const std::string& line)
{
    bool isPresent = false;
    
    for (const std::string& word : words)
    {
        if (isWordPresentInLine(word, line))
        {
            isPresent = true;
            false;
        }
    }
    
    return isPresent;
}

} // anonymous namespace

void prettyPrint(const std::string& testDescription, const std::function<bool()>& testFunction)
{
    std::cout << testDescription << " ";
    
    const bool result = testFunction();
    if (result)
    {
        std::cout << "\033[1;31mDetected!\033[0m" << std::endl;
    }
    else
    {
        std::cout << "\033[1;32mNot detected!\033[0m" << std::endl;
    }
}

bool doesAnyWordExistInFile(const char* filePath, const std::vector<std::string>& wordsToSearch)
{
    bool wordExists = false;
    
    try
    {
        std::ifstream fileStream(filePath);
        std::string line = "";
        
        while (getline(fileStream, line))
        {
            if (isAnyWordPresentInLine(wordsToSearch, line))
            {
                wordExists = true;
                break;
            }
        }
    }
    catch (std::ifstream::failure e)
    {
        std::cout << "Failure while opening file: " << std::string(filePath) << std::endl;
    }
    
    return wordExists;
}



bool doesAnyFilenameExistInDirectory(const std::string& directoryPath, const std::vector<std::string>& filenameToSearch)
{
    bool wordExists = false;
    
    for (const auto& entry : fs::directory_iterator(directoryPath))
    {
        if (std::find(filenameToSearch.begin(), filenameToSearch.end(), entry.path().filename().string()) != filenameToSearch.end())
        {
            wordExists = true;
            break;
        }
    }
    
    return wordExists;
}

bool isNumber(const std::string text)
{
    return (text.find_first_not_of("0123456789") == std::string::npos);
}

} // Util
