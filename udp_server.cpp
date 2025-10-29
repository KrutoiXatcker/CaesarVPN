#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <thread>
#include <vector>
#include <algorithm>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <sys/select.h>
#include <chrono>
#include <unordered_map>
#include <mutex>

class CaesarCipher {
private:
    int shift;
public:
    CaesarCipher(int shift_val = 3) : shift(shift_val % 256) {}
    std::string encrypt(const std::string& data) {
        std::string result = data;
        for (size_t i = 0; i < data.length(); i++) {
            result[i] = (data[i] + shift) % 256;
        }
        return result;
    }
    std::string decrypt(const std::string& data) {
        std::string result = data;
        for (size_t i = 0; i < data.length(); i++) {
            result[i] = (data[i] - shift + 256) % 256;
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
            throw std::runtime_error("Failed to open TUN device");
        }
        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        strncpy(ifr.ifr_name, dev_name.c_str(), IFNAMSIZ);
        if (ioctl(tun_fd, TUNSETIFF, (void *)&ifr) < 0) {
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
        std::string cmd;
        cmd = "ip addr add " + ip + "/24 dev " + name + " 2>/dev/null";
        system(cmd.c_str());
        cmd = "ip link set " + name + " up 2>/dev/null";
        system(cmd.c_str());
        system("sysctl -w net.ipv4.ip_forward=1 2>/dev/null");
        cmd = "iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -j MASQUERADE 2>/dev/null";
        system(cmd.c_str());
        cmd = "iptables -A FORWARD -i " + name + " -j ACCEPT 2>/dev/null";
        system(cmd.c_str());
        cmd = "iptables -A FORWARD -o " + name + " -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null";
        system(cmd.c_str());
        cmd = "ip link set " + name + " mtu 1500";
        system(cmd.c_str());
        std::cout << "TUN interface " << name << " configured with IP " << ip << std::endl;
    }
    ~TUNInterface() {
        if (tun_fd >= 0) close(tun_fd);
    }
};

struct ClientInfo {
    struct sockaddr_in addr;
    socklen_t addr_len;
    std::string tun_ip;
    std::chrono::steady_clock::time_point last_activity;
};

class UDPServer {
private:
    int udp_socket;
    CaesarCipher cipher;
    bool running;
    TUNInterface tun;
    std::unordered_map<std::string, ClientInfo> clients; // key: "ip:port"
    std::mutex clients_mutex;
    std::vector<std::string> ip_pool;
    size_t next_ip_index;

    std::string getClientKey(const struct sockaddr_in& addr) {
        return std::string(inet_ntoa(addr.sin_addr)) + ":" + std::to_string(ntohs(addr.sin_port));
    }

    std::string allocateIP() {
        if (next_ip_index >= ip_pool.size()) {
            std::cerr << "No more IP addresses available!" << std::endl;
            return "";
        }
        return ip_pool[next_ip_index++];
    }

    void setupIPPool() {
        // Выделяем 10.0.0.2 - 10.0.0.254
        for (int i = 2; i <= 254; ++i) {
            ip_pool.push_back("10.0.0." + std::to_string(i));
        }
        next_ip_index = 0;
    }

public:
    UDPServer(int port = 8080, int cipher_shift = 3) 
        : cipher(cipher_shift), running(false), tun("tun0") {
        setupIPPool();
        udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_socket < 0) {
            throw std::runtime_error("UDP socket creation failed");
        }
        int buf_size = 65536;
        setsockopt(udp_socket, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
        setsockopt(udp_socket, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
        int opt = 1;
        setsockopt(udp_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port);

        if (bind(udp_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            close(udp_socket);
            throw std::runtime_error("UDP bind failed");
        }

        int flags = fcntl(udp_socket, F_GETFL, 0);
        fcntl(udp_socket, F_SETFL, flags | O_NONBLOCK);

        std::cout << "UDP VPN Server started on port " << port << std::endl;
        tun.setupInterface("10.0.0.1");
    }

    void start() {
        running = true;
        std::cout << "Waiting for UDP clients..." << std::endl;
        std::thread main_thread([this]() { this->mainLoop(); });
        main_thread.detach();

        while (running) {
            cleanupInactiveClients();
            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
    }

private:
    void cleanupInactiveClients() {
        auto now = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> lock(clients_mutex);
        for (auto it = clients.begin(); it != clients.end();) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last_activity);
            if (elapsed.count() > 60) {
                std::cout << "Client " << it->first << " timed out" << std::endl;
                it = clients.erase(it);
            } else {
                ++it;
            }
        }
    }

    void handleDHCPRequest(const struct sockaddr_in& client_addr, socklen_t addr_len) {
        std::string key = getClientKey(client_addr);
        std::lock_guard<std::mutex> lock(clients_mutex);

        if (clients.find(key) != clients.end()) {
            // Уже есть IP — отправим его снова
            std::string response = "DHCP_OFFER:" + clients[key].tun_ip;
            std::string encrypted = cipher.encrypt(response);
            sendto(udp_socket, encrypted.c_str(), encrypted.length(), 0,
                   (struct sockaddr*)&client_addr, addr_len);
            return;
        }

        std::string ip = allocateIP();
        if (ip.empty()) return;

        ClientInfo info;
        info.addr = client_addr;
        info.addr_len = addr_len;
        info.tun_ip = ip;
        info.last_activity = std::chrono::steady_clock::now();
        clients[key] = info;

        std::string response = "DHCP_OFFER:" + ip;
        std::string encrypted = cipher.encrypt(response);
        sendto(udp_socket, encrypted.c_str(), encrypted.length(), 0,
               (struct sockaddr*)&client_addr, addr_len);

        std::cout << "Assigned IP " << ip << " to client " << key << std::endl;
    }

    void mainLoop() {
        char udp_buffer[65536];
        while (running) {
            struct sockaddr_in incoming_addr;
            socklen_t addr_len = sizeof(incoming_addr);
            memset(udp_buffer, 0, sizeof(udp_buffer));
            int bytes_received = recvfrom(udp_socket, udp_buffer, sizeof(udp_buffer), 0,
                                         (struct sockaddr*)&incoming_addr, &addr_len);
            if (bytes_received > 0) {
                std::string encrypted_data(udp_buffer, bytes_received);
                std::string decrypted = cipher.decrypt(encrypted_data);

                std::string key = getClientKey(incoming_addr);
                {
                    std::lock_guard<std::mutex> lock(clients_mutex);
                    if (clients.find(key) != clients.end()) {
                        clients[key].last_activity = std::chrono::steady_clock::now();
                    }
                }

                if (decrypted == "DHCP_REQUEST") {
                    handleDHCPRequest(incoming_addr, addr_len);
                    continue;
                }

                // Обычный трафик
                {
                    std::lock_guard<std::mutex> lock(clients_mutex);
                    if (clients.find(key) == clients.end()) {
                        // Неавторизованный клиент — игнорируем
                        continue;
                    }
                }

                int written = tun.writePacket(decrypted);
                if (written <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    perror("TUN write failed");
                }
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("UDP recv error");
            }

            // Отправка трафика из TUN клиентам
            std::string tun_packet;
            int bytes_from_tun = tun.readPacket(tun_packet);
            if (bytes_from_tun > 0) {
                std::lock_guard<std::mutex> lock(clients_mutex);
                for (auto& kv : clients) {
                    std::string encrypted = cipher.encrypt(tun_packet);
                    sendto(udp_socket, encrypted.c_str(), encrypted.length(), 0,
                           (struct sockaddr*)&kv.second.addr, kv.second.addr_len);
                }
            } else if (bytes_from_tun < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("TUN read error");
            }

            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    }

public:
    ~UDPServer() {
        running = false;
        if (udp_socket > 0) close(udp_socket);
        std::cout << "UDP VPN Server stopped" << std::endl;
    }
};

int main() {
    std::cout << "Starting UDP VPN Server..." << std::endl;
    std::cout << "Note: Run as root for TUN and iptables access" << std::endl;
    try {
        UDPServer server(8080, 5);
        server.start();
    } catch (const std::exception& e) {
        std::cerr << "Server error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
