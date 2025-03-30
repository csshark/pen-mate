#ifndef FIRMWARE_VERIFIER_H
#define FIRMWARE_VERIFIER_H

#include <string>


std::string calculateSHA256(const std::string& filePath);
std::string calculateSHA512(const std::string& filePath);
std::string recognizeFirmwareType(const std::string& filePath);
void addFirmwareSignature(const std::string& signature, const std::string& type);
void listFirmwareSignatures();
void restoreComponent(const std::string& filePath, const std::string& componentPath, size_t offset);
void analyzeBinFile(const std::string& filePath); // Add this line

#endif