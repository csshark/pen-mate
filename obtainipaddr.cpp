#include <iostream>
#include <string>
#include <ifaddrs.h>      
#include <arpa/inet.h>    
#include <netinet/in.h>   
#include <cstring>

std::string getIPv4Address() {
    struct ifaddrs *interfaces = nullptr;
    struct ifaddrs *temp_addr = nullptr;
    std::string ipv4Address = "";

    // Get the list of network interfaces
    if (getifaddrs(&interfaces) == -1) {
        perror("getifaddrs");
        return ipv4Address; // Return empty string on error
    }

    // Iterate through the interfaces
    for (temp_addr = interfaces; temp_addr != nullptr; temp_addr = temp_addr->ifa_next) {
        // Check for IPv4 and avoid loopback addresses
        if (temp_addr->ifa_addr->sa_family == AF_INET) {
            char addressBuffer[INET_ADDRSTRLEN]; 
            // Convert the address to a string
            inet_ntop(AF_INET, &((struct sockaddr_in*)temp_addr->ifa_addr)->sin_addr, addressBuffer, sizeof(addressBuffer));

            // Ignore the loopback address
            if (std::string(addressBuffer) != "127.0.0.1") {
                ipv4Address = addressBuffer; // Store the found IPv4 address
                break; // Exit after the first valid IP found
            }
        }
    }

    // Clean up
    freeifaddrs(interfaces);
    
    return ipv4Address; // Return the found address or empty string if not found
}