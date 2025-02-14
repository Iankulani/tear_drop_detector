#include <pcap.h>
#include <iostream>
#include <cstring>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>

class TeardropDetector {
public:
    TeardropDetector(const std::string& target_ip) : target_ip_(target_ip) {}

    // Function to detect potential tear drop attack
    void detect_teardrop(const struct pcap_pkthdr *header, const u_char *packet) {
        struct ip *ip_header = (struct ip *)(packet + 14); // Skip Ethernet header (14 bytes)

        if (ip_header->ip_p == IPPROTO_IP) { // IP Protocol
            // Check if the IP packet is fragmented
            if (ip_header->ip_off & htons(IP_MF)) { // More fragments flag (MF) is set
                std::cout << "Fragmented packet detected from " << inet_ntoa(ip_header->ip_src) << std::endl;

                // Check if fragment offset is not a multiple of 8
                uint16_t fragment_offset = ntohs(ip_header->ip_off) & 0x1FFF;
                if (fragment_offset % 8 != 0) {
                    std::cout << "Suspicious fragment with invalid offset detected from "
                              << inet_ntoa(ip_header->ip_src) << "!" << std::endl;
                    std::cout << "Fragment offset: " << fragment_offset << std::endl;
                }
            }
        }
    }

    // Packet handler that calls the detection function
    static void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
        TeardropDetector* detector = reinterpret_cast<TeardropDetector*>(user_data);
        detector->detect_teardrop(header, packet);
    }

    // Function to start capturing packets
    void start_sniffing() {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle;
        char *dev = nullptr;

        // Open a device for packet capture (use pcap_lookupdev to find a device)
        dev = pcap_lookupdev(errbuf);
        if (dev == nullptr) {
            std::cerr << "Error finding device: " << errbuf << std::endl;
            return;
        }

        std::cout << "Device found: " << dev << std::endl;

        // Open the device for capturing packets in promiscuous mode
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
            std::cerr << "Error opening device: " << errbuf << std::endl;
            return;
        }

        // Filter to capture packets only for the specified IP address
        struct bpf_program fp;
        char filter_exp[50];
        snprintf(filter_exp, sizeof(filter_exp), "host %s", target_ip_.c_str());
        if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
            return;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
            return;
        }

        // Start capturing packets
        std::cout << "Starting packet capture for IP address: " << target_ip_ << std::endl;
        pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char*>(this));

        // Close the capture handle
        pcap_close(handle);
    }

private:
    std::string target_ip_;
};

int main() {
    std::string target_ip;

    // Prompt user for target IP
    std::cout << "Enter the target IP address to monitor:";
    std::cin >> target_ip;

    // Create an instance of TeardropDetector and start sniffing
    TeardropDetector detector(target_ip);
    detector.start_sniffing();

    return 0;
}
