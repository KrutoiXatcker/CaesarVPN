// vpn_client.cpp
#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdio.h>
#include <chrono>
#include <signal.h>

bool running = true;

void signalHandler(int sig) {
    running = false;
}

class CaesarCipher {
private:
    int shift;

public:
    CaesarCipher(int shift_val = 3) : shift(shift_val % 256) {}

    std::string encrypt(const std::string& data) {
        std::string result = data;
        for (size_t i = 0; i < data.length(); i++) {
            result[i] = (static_cast<unsigned char>(data[i]) + shift) % 256;
        }
        return result;
    }

    std::string decrypt(const std::string& data) {
        std::string result = data;
        for (size_t i = 0; i < data.length(); i++) {
            result[i] = (static_cast<unsigned char>(data[i]) - shift + 256) % 256;
        }
        return result;
    }
};

class TUNInterface {
private:
    int tun_fd;
    std::string name;

public:
    TUNInterface(const std::string& dev_name = "tun0") : name(dev_name) {
        struct ifreq ifr;
        tun_fd = open("/dev/net/tun", O_RDWR);
        if (tun_fd < 0) {
            perror("Failed to open TUN device");
            throw std::runtime_error("Failed to open TUN device");
        }

        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        strncpy(ifr.ifr_name, dev_name.c_str(), IFNAMSIZ);

        if (ioctl(tun_fd, TUNSETIFF, (void *)&ifr) < 0) {
            perror("Failed to create TUN interface");
            close(tun_fd);
            throw std::runtime_error("Failed to create TUN interface");
        }

        int flags = fcntl(tun_fd, F_GETFL, 0);
        fcntl(tun_fd, F_SETFL, flags | O_NONBLOCK);

        name = ifr.ifr_name;
        std::cout << "TUN interface " << name << " created" << std::endl;
    }

    int getFD() const { return tun_fd; }
    const std::string& getName() const { return name; }

    int readPacket(std::string& packet) {
        char buffer[65536];
        int n = read(tun_fd, buffer, sizeof(buffer));
        if (n > 0) {
            packet.assign(buffer, n);
        }
        return n;
    }

    int writePacket(const std::string& packet) {
        return write(tun_fd, packet.c_str(), packet.length());
    }

    void setupInterface(const std::string& ip) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            perror("Socket for setup failed");
            return;
        }

        struct ifreq ifr;
        struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ);
        addr->sin_family = AF_INET;
        inet_pton(AF_INET, ip.c_str(), &addr->sin_addr);

        if (ioctl(sock, SIOCSIFADDR, &ifr) == 0) {
            std::cout << "Assigned IP " << ip << " to " << name << std::endl;
        }

        addr->sin_addr.s_addr = inet_addr("255.255.255.0");
        ioctl(sock, SIOCSIFNETMASK, &ifr);

        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
            ioctl(sock, SIOCSIFFLAGS, &ifr);
        }

        close(sock);

        std::string cmd = "ip link set " + name + " mtu 1500";
        system(cmd.c_str());
    }

    ~TUNInterface() {
        if (tun_fd >= 0) {
            close(tun_fd);
        }
    }
};

class UDPClient {
private:
    int udp_socket;
    CaesarCipher cipher;
    TUNInterface tun;
    std::string server_ip;
    int server_port;
    struct sockaddr_in server_addr;
    std::string client_tun_ip;
    std::chrono::steady_clock::time_point last_activity;

    void setupRoutes() {
        std::string cmd;
        cmd = "ip route add " + server_ip + " via $(ip route | grep default | awk '{print $3}' | head -1) 2>/dev/null";
        system(cmd.c_str());
        cmd = "ip route add default via 10.0.0.1 dev " + tun.getName() + " 2>/dev/null";
        system(cmd.c_str());
        std::cout << "Routes configured" << std::endl;
    }

    void cleanupRoutes() {
        std::string cmd;
        cmd = "ip route del default via 10.0.0.1 dev " + tun.getName() + " 2>/dev/null";
        system(cmd.c_str());
        cmd = "ip route del " + server_ip + " 2>/dev/null";
        system(cmd.c_str());
    }

    void updateActivity() {
        last_activity = std::chrono::steady_clock::now();
    }

    void mainLoop() {
        char udp_buffer[65536];
        socklen_t server_addr_len = sizeof(server_addr);
        while (running) {
            // TUN -> UDP
            std::string tun_packet;
            int n = tun.readPacket(tun_packet);
            if (n > 0) {
                updateActivity();
                std::string encrypted = cipher.encrypt(tun_packet);
                sendto(udp_socket, encrypted.c_str(), encrypted.length(), 0,
                       (struct sockaddr*)&server_addr, sizeof(server_addr));
            } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("TUN read error");
            }

            // UDP -> TUN
            memset(udp_buffer, 0, sizeof(udp_buffer));
            int bytes = recvfrom(udp_socket, udp_buffer, sizeof(udp_buffer), 0,
                                 (struct sockaddr*)&server_addr, &server_addr_len);
            if (bytes > 0) {
                updateActivity();
                std::string encrypted(udp_buffer, bytes);
                std::string decrypted = cipher.decrypt(encrypted);
                if (decrypted.substr(0, 11) == "DHCP_OFFER:") {
                    // Игнорируем повторные DHCP-ответы
                    continue;
                }
                int written = tun.writePacket(decrypted);
                if (written <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    perror("TUN write error");
                }
            } else if (bytes < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("UDP recv error");
            }

            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    }

public:
    UDPClient(const std::string& server_ip, int port = 8080, int cipher_shift = 3) 
        : cipher(cipher_shift), tun("tun0"), server_ip(server_ip), server_port(port) {
        udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_socket < 0) {
            throw std::runtime_error("UDP socket creation failed");
        }

        int buf_size = 65536;
        setsockopt(udp_socket, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
        setsockopt(udp_socket, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));

        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(port);
        if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
            throw std::runtime_error("Invalid server address");
        }

        int flags = fcntl(udp_socket, F_GETFL, 0);
        fcntl(udp_socket, F_SETFL, flags | O_NONBLOCK);

        last_activity = std::chrono::steady_clock::now();
    }

    bool requestIP() {
        std::string request = "DHCP_REQUEST";
        std::string encrypted = cipher.encrypt(request);
        for (int i = 0; i < 5; ++i) {
            sendto(udp_socket, encrypted.c_str(), encrypted.length(), 0,
                   (struct sockaddr*)&server_addr, sizeof(server_addr));

            char buffer[65536];
            struct sockaddr_in recv_addr;
            socklen_t addr_len = sizeof(recv_addr);
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(udp_socket, &readfds);
            struct timeval tv;
            tv.tv_sec = 2;
            tv.tv_usec = 0;

            if (select(udp_socket + 1, &readfds, nullptr, nullptr, &tv) > 0) {
                int n = recvfrom(udp_socket, buffer, sizeof(buffer), 0,
                                 (struct sockaddr*)&recv_addr, &addr_len);
                if (n > 0) {
                    std::string resp_enc(buffer, n);
                    std::string resp = cipher.decrypt(resp_enc);
                    if (resp.substr(0, 11) == "DHCP_OFFER:") {
                        client_tun_ip = resp.substr(11);
                        std::cout << "Received IP from server: " << client_tun_ip << std::endl;
                        tun.setupInterface(client_tun_ip);
                        setupRoutes();
                        return true;
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        return false;
    }

    void start() {
        if (!requestIP()) {
            throw std::runtime_error("Failed to obtain IP from server");
        }

        std::cout << "\n=== UDP VPN Client Started ===" << std::endl;
        std::cout << "Local TUN IP: " << client_tun_ip << std::endl;
        std::cout << "Server TUN IP: 10.0.0.1" << std::endl;
        std::cout << "Press Ctrl+C to stop\n" << std::endl;

        std::thread main_thread([this]() { this->mainLoop(); });
        main_thread.detach();

        while (running) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        cleanupRoutes();
        // Дожидаемся завершения потока (опционально)
        // Но так как он detach, просто даём время на отправку последних пакетов
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    ~UDPClient() {
        if (udp_socket > 0) {
            close(udp_socket);
        }
    }
};

int main() {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    std::string server_ip = "94.241.175.171";
    //std::cout << "Enter VPN server IP: ";
    //std::cin >> server_ip;

    std::cout << "Starting UDP VPN Client..." << std::endl;
    std::cout << "Note: Run as root for TUN and routing access" << std::endl;

    try {
        UDPClient client(server_ip, 8080, 5);
        client.start();
    } catch (const std::exception& e) {
        std::cerr << "Client error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "Client stopped." << std::endl;
    return 0;
}
