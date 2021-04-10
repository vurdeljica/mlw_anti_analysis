#ifndef UTIL_H
#define UTIL_H

#include <fstream>
#include <string>
#include <iostream>
#include <vector>
#include <functional>
#include <string.h>

namespace Util
{

void prettyPrint(const std::string& testDescription, const std::function<bool()>& testFunction);

bool doesAnyWordExistInFile(const char* filePath, const std::vector<std::string>& wordsToSearch);

bool doesAnyFilenameExistInDirectory(const std::string& directoryPath, const std::vector<std::string>& filenameToSearch);

bool isNumber(const std::string text);

}

#endif
