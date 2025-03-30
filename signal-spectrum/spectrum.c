#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <signal.h>

#define SPECTRUM_SIZE 64 // Number of frequency bins for spectrum display
double spectrum[SPECTRUM_SIZE] = {0};

// Handler for SIGINT to clean up
void handle_sigint(int signal) {
    printf("\nExiting program...\n");
    exit(0);
}

// Packet handler function
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // Here you would extract the signal strength from the captured packet
    // For demonstration, we'll use a placeholder for the RSSI value
    int rssi = rand() % -100; // Simulating RSSI value

    // Update the spectrum: increment spectrum bin for the corresponding signal
    int bin = (rssi + 100) * (SPECTRUM_SIZE - 1) / 100; // Normalize RSSI to bins
    if (bin >= 0 && bin < SPECTRUM_SIZE) {
        spectrum[bin]++;
    }
}

// Function to display the spectrum in real-time
void display_spectrum() {
    system("clear"); // Clear the console
    for (int i = 0; i < SPECTRUM_SIZE; i++) {
        int bar_length = spectrum[i] / 10; // Scale for better visualization
        printf("%3d: ", i);
        for (int j = 0; j < bar_length; j++) {
            printf("#");
        }
        printf("\n");
    }
}

int main(int argc, char *argv[]) {
    // Handle cleanup on interrupt
    signal(SIGINT, handle_sigint);

    char *dev; // The device to be used
    char errbuf[PCAP_ERRBUF_SIZE];

    // Find a device
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find device: %s\n", errbuf);
        return 1;
    }

    // Open the device in monitor mode
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }

    printf("Monitoring device: %s\n", dev);
    
    // Start capturing packets
    while (1) {
        struct pcap_pkthdr header;
        const u_char *packet = pcap_next(handle, &header);
        if (packet != NULL) {
            packet_handler(NULL, &header, packet);
            display_spectrum();
        }
    }

    // Cleanup doesn't reach here because of the infinite loop
    pcap_close(handle);
    return 0;
}