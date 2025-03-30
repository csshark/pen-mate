#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <vector>
#include <cstring>
#include <map>
#include <algorithm>
#include "firmwareVerifier.h"

std::map<std::string, std::string> firmwareSignatures = {
    {"\x7F""ELF", "Linux"},
    {"RTOS", "RTOS"},
    {"AD\x01", "Analog Devices"},
    {"AVNT\x02", "Avnet Silica"},
    {"STM32\x03", "STMicroelectronics"},
    {"ESP\x04", "Espressif Systems"},
    {"NRF\x05", "Nordic Semiconductor"},
    {"TIVA\x06", "Texas Instruments"},
    {"RPI\x07", "Raspberry Pi"},
    {"NXP\x08", "NXP Semiconductors"}
};

std::vector<char> readBinFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + filePath);
    }
    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return buffer;
}

std::string interpretBinFile(const std::vector<char>& buffer) {
    for (const auto& [signature, type] : firmwareSignatures) {
        if (std::search(buffer.begin(), buffer.end(), signature.begin(), signature.end()) != buffer.end()) {
            return type;
        }
    }
    return "Unknown";
}

std::string recognizeFirmwareType(const std::string& filePath) {
    std::vector<char> buffer = readBinFile(filePath);
    return interpretBinFile(buffer);
}

void addFirmwareSignature(const std::string& signature, const std::string& type) {
    firmwareSignatures[signature] = type;
    std::cout << "Added signature: " << signature << " -> " << type << std::endl;
}

void listFirmwareSignatures() {
    std::cout << "Known Firmware Signatures:" << std::endl;
    for (const auto& [signature, type] : firmwareSignatures) {
        std::cout << "Signature: " << signature << " -> Type: " << type << std::endl;
    }
}

std::string calculateSHA256(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + filePath);
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize SHA-256 digest");
    }
    char buffer[1024];
    while (file.read(buffer, sizeof(buffer))) {
        if (EVP_DigestUpdate(ctx, buffer, file.gcount()) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to update SHA-256 digest");
        }
    }
    if (EVP_DigestUpdate(ctx, buffer, file.gcount()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to update SHA-256 digest");
    }
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;
    if (EVP_DigestFinal_ex(ctx, hash, &hashLen) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize SHA-256 digest");
    }
    EVP_MD_CTX_free(ctx);
    std::stringstream ss;
    for (unsigned int i = 0; i < hashLen; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::string calculateSHA512(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file: " + filePath);
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize SHA-512 digest");
    }
    char buffer[1024];
    while (file.read(buffer, sizeof(buffer))) {
        if (EVP_DigestUpdate(ctx, buffer, file.gcount()) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to update SHA-512 digest");
        }
    }
    if (EVP_DigestUpdate(ctx, buffer, file.gcount()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to update SHA-512 digest");
    }
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;
    if (EVP_DigestFinal_ex(ctx, hash, &hashLen) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize SHA-512 digest");
    }
    EVP_MD_CTX_free(ctx);
    std::stringstream ss;
    for (unsigned int i = 0; i < hashLen; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

void restoreComponent(const std::string& filePath, const std::string& componentPath, size_t offset) {
    std::ifstream componentFile(componentPath, std::ios::binary);
    if (!componentFile) {
        throw std::runtime_error("Failed to open component file: " + componentPath);
    }
    std::fstream binFile(filePath, std::ios::in | std::ios::out | std::ios::binary);
    if (!binFile) {
        throw std::runtime_error("Failed to open .bin file: " + filePath);
    }
    binFile.seekp(offset, std::ios::beg);
    char buffer[1024];
    while (componentFile.read(buffer, sizeof(buffer))) {
        binFile.write(buffer, componentFile.gcount());
    }
    binFile.write(buffer, componentFile.gcount());
    std::cout << "Component restored successfully at offset " << offset << std::endl;
}

void analyzeBinFile(const std::string& filePath) {
    try {
        std::vector<char> buffer = readBinFile(filePath);
        std::cout << "File size: " << buffer.size() << " bytes" << std::endl;
        std::string firmwareType = recognizeFirmwareType(filePath);
        std::cout << "Firmware Type: " << firmwareType << std::endl;
        std::string sha256Hash = calculateSHA256(filePath);
        std::cout << "SHA-256 Hash: " << sha256Hash << std::endl;
        std::string sha512Hash = calculateSHA512(filePath);
        std::cout << "SHA-512 Hash: " << sha512Hash << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

