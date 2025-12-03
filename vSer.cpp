#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <thread>
#include <vector>
#include <mutex>
#include <atomic>
#include <map>
#include <queue>
#include <deque>
#include <chrono>
#include <algorithm>
#include <fstream>
#include <signal.h>
#include <sys/wait.h>
#include <sstream>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <zlib.h>

#define PORT            8888          // TCP/TLS VPN port
#define UDP_PORT        8889          // UDP VPN port (ChaCha20-Poly1305)
#define BUFFER_SIZE     8192
#define MAX_EVENTS      256
#define MAX_CLIENTS     100
#define AUTH_TOKEN      "MODERNVPN2024"
#define HEARTBEAT_INTERVAL 15   // seconds since lastActivity
#define CLIENT_TIMEOUT     45   // seconds since lastActivity
#define TUN_NAME        "tun0"

// ---- VPN addressing (server + pool) ----------------------------------------

#define VPN_IPV4_NET      "10.8.0.0/24"
#define VPN_IPV4_SERVER   "10.8.0.1"

// Simple ULA IPv6 prefix (lab-grade IPv6, NAT66-style)
#define VPN_IPV6_PREFIX   "fd10:8:0::/64"
#define VPN_IPV6_SERVER   "fd10:8:0::1"

// DNS servers to push
static const char* DNS4_PRIMARY   = "1.1.1.1";
static const char* DNS4_SECONDARY = "8.8.8.8";
static const char* DNS6_PRIMARY   = "2606:4700:4700::1111";
static const char* DNS6_SECONDARY = "2001:4860:4860::8888";

// Underlay MTU tuning
#define MIN_UNDERLAY_MTU     1300
#define DEFAULT_UNDERLAY_MTU 1500

// Outbound interface selection
static const char* OUTBOUND_IFACE_CONFIG = "auto";

// Transport mode: how to use TCP/UDP
enum class TransportMode {
    UDP_PREFERRED,  // try UDP, fallback TCP
    TCP_ONLY,       // pure TCP tunnel
    UDP_ONLY        // pure UDP (WireGuard-ish)
};

static const TransportMode TRANSPORT_MODE = TransportMode::UDP_PREFERRED;

std::atomic<bool> g_running{true};

void signalHandler(int signum) {
    std::cout << "\n[!] Received signal " << signum << ", shutting down...\n";
    g_running = false;
}

int executeCommand(const std::string& cmd) {
    std::cout << "[CMD] " << cmd << std::endl;
    int ret = system(cmd.c_str());
    if (ret != 0) {
        std::cerr << "[ERROR] Command failed with code: " << ret << std::endl;
    }
    return ret;
}

struct ClientInfo {
    int socket;
    SSL* ssl; // TLS handle

    std::string ip;             // real client IP
    uint16_t port{};
    std::chrono::steady_clock::time_point lastActivity;
    std::chrono::steady_clock::time_point lastHeartbeat;
    bool authenticated;
    std::string assignedIP;     // VPN IPv4 (10.8.0.x)
    std::string assignedIPv6;   // VPN IPv6 (fd10:8:0::x)
    uint64_t bytesSent;
    uint64_t bytesReceived;
    int reconnectAttempts;

    std::vector<uint8_t> tcpRecvBuffer;
    size_t tcpNeeded = 4;
    bool tcpReadingHeader = true;


    // Per-client send queue for TCP/TLS (used by epoll EPOLLOUT and heartbeat)
    std::deque<std::vector<uint8_t>> sendQueue;

    ClientInfo()
        : socket(-1),
          ssl(nullptr),
          authenticated(false),
          bytesSent(0),
          bytesReceived(0),
          reconnectAttempts(0) {}
};

// For UDP peers
struct UdpPeer {
    sockaddr_in addr{};
    std::chrono::steady_clock::time_point lastActivity;
};

class VPNServer {
private:
    int tunFd;
    int tcpSocket;
    int udpSocket;
    int epollFd;
    std::string interfaceName;  // outbound interface (eth0/eth1/.../wlan0)
    int tunMtu;

    std::mutex clientsMutex;
    std::map<int, ClientInfo> clients;            // socket -> client
    std::queue<std::string> availableIPs;
    std::map<std::string, std::chrono::steady_clock::time_point> ipReservations;

    // Routing tables (keys can be IPv4 or IPv6 string)
    std::map<std::string, int>     ipToTcpSocket;  // VPN IP -> TCP socket
    std::map<std::string, UdpPeer> ipToUdpPeer;   // VPN IP -> UDP peer

    std::atomic<uint64_t> totalBytesSent{0};
    std::atomic<uint64_t> totalBytesReceived{0};
    std::atomic<int> totalConnections{0};

    // TLS
    SSL_CTX* sslCtx;

    // UDP symmetric key (ChaCha20-Poly1305)
    unsigned char udpKey[32]; // 256-bit key
    bool udpKeyInitialized;

public:
    VPNServer() :
        tunFd(-1),
        tcpSocket(-1),
        udpSocket(-1),
        epollFd(-1),
        interfaceName("eth0"),
        tunMtu(-1),
        sslCtx(nullptr),
        udpKeyInitialized(false) {

        setupSignalHandlers();
        detectNetworkInterface();
        initializeIPPool();
        initOpenSSL();
        initTLS();
        initUdpCrypto();
    }

    ~VPNServer() {
        cleanup();
    }

    // ------------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------------

    void setupSignalHandlers() {
        signal(SIGINT,  signalHandler);
        signal(SIGTERM, signalHandler);
        signal(SIGPIPE, SIG_IGN);
    }

    void detectNetworkInterface() {
        if (std::string(OUTBOUND_IFACE_CONFIG) != "auto") {
            interfaceName = OUTBOUND_IFACE_CONFIG;
            std::cout << "[+] Using configured outbound interface: " << interfaceName << std::endl;
            return;
        }

        std::ifstream routes("/proc/net/route");
        std::string line, iface;

        while (std::getline(routes, line)) {
            std::istringstream iss(line);
            std::string dest, gateway;
            iss >> iface >> dest >> gateway;

            if (dest == "00000000" && gateway != "00000000") {
                interfaceName = iface;
                std::cout << "[+] Detected default outbound interface: " << interfaceName << std::endl;
                return;
            }
        }

        std::vector<std::string> common = {"eth0", "eth1", "enp0s3", "ens33", "wlan0"};
        for (const auto& f : common) {
            std::string cmd = "ip link show " + f + " 2>/dev/null";
            if (system(cmd.c_str()) == 0) {
                interfaceName = f;
                std::cout << "[+] Fallback to interface: " << interfaceName << std::endl;
                return;
            }
        }

        std::cout << "[!] WARNING: Could not detect interface, using eth0 by default\n";
        interfaceName = "eth0";
    }

    void initializeIPPool() {
        for (int i = 2; i < 255; i++) {
            availableIPs.push("10.8.0." + std::to_string(i));
        }
    }

    // Build per-client IPv6 from IPv4 (e.g. 10.8.0.10 -> fd10:8:0::a)
    std::string makeClientIPv6(const std::string& ipv4) {
        size_t lastDot = ipv4.rfind('.');
        if (lastDot == std::string::npos) {
            return VPN_IPV6_SERVER;
        }
        int lastOctet = std::stoi(ipv4.substr(lastDot + 1));
        std::ostringstream oss;
        oss << "fd10:8:0::" << std::hex << lastOctet;
        return oss.str();
    }

    int getInterfaceMTU(const std::string& ifname) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) return DEFAULT_UNDERLAY_MTU;

        struct ifreq ifr;
        std::memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);

        if (ioctl(sock, SIOCGIFMTU, &ifr) < 0) {
            close(sock);
            return DEFAULT_UNDERLAY_MTU;
        }
        close(sock);
        return ifr.ifr_mtu;
    }

    int computeTunMTU() {
        int underlay = getInterfaceMTU(interfaceName);
        if (underlay < MIN_UNDERLAY_MTU) {
            underlay = MIN_UNDERLAY_MTU;
        }

        int m = underlay - 80;   // leave headroom for IP+UDP/TCP+TLS/etc
        if (m < 1200) m = 1200;

        std::cout << "[+] Underlay MTU on " << interfaceName
                  << " = " << underlay
                  << ", setting TUN MTU to " << m << std::endl;
        return m;
    }

    // ------------------------------------------------------------------------
    // OpenSSL / TLS
    // ------------------------------------------------------------------------

    void initOpenSSL() {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
    }

    X509* generateSelfSignedCert(EVP_PKEY* pkey) {
        X509* x509 = X509_new();
        if (!x509) return nullptr;

        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // 1 year
        X509_set_pubkey(x509, pkey);

        X509_NAME* name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
                                   (unsigned char*)"IN", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
                                   (unsigned char*)"ModernVPN", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   (unsigned char*)"ModernVPN Server", -1, -1, 0);

        X509_set_issuer_name(x509, name);

        if (!X509_sign(x509, pkey, EVP_sha256())) {
            X509_free(x509);
            return nullptr;
        }

        return x509;
    }

    void initTLS() {
        sslCtx = SSL_CTX_new(TLS_server_method());
        if (!sslCtx) {
            std::cerr << "[ERROR] Failed to create SSL_CTX\n";
            std::exit(1);
        }

        const char* CERT_FILE = "/etc/vpn_server/server.crt";
        const char* KEY_FILE  = "/etc/vpn_server/server.key";

        if (access(CERT_FILE, R_OK) == 0 && access(KEY_FILE, R_OK) == 0) {
            std::cout << "[+] Loading existing TLS certificate...\n";

            if (SSL_CTX_use_certificate_file(sslCtx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
                std::cerr << "[ERROR] Failed to load certificate file\n";
                ERR_print_errors_fp(stderr);
                std::exit(1);
            }

            if (SSL_CTX_use_PrivateKey_file(sslCtx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
                std::cerr << "[ERROR] Failed to load private key file\n";
                ERR_print_errors_fp(stderr);
                std::exit(1);
            }

            if (!SSL_CTX_check_private_key(sslCtx)) {
                std::cerr << "[ERROR] Certificate and key mismatch\n";
                std::exit(1);
            }

            std::cout << "[+] TLS loaded: using permanent certificate.\n";
        } else {
            std::cout << "[!] No certificate found → generating temporary self-signed cert\n";

            EVP_PKEY_CTX* keygenCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
            EVP_PKEY* pkey = nullptr;

            if (!keygenCtx ||
                EVP_PKEY_keygen_init(keygenCtx) <= 0 ||
                EVP_PKEY_CTX_set_rsa_keygen_bits(keygenCtx, 2048) <= 0 ||
                EVP_PKEY_keygen(keygenCtx, &pkey) <= 0) {

                std::cerr << "[ERROR] RSA key generation failed\n";
                if (keygenCtx) EVP_PKEY_CTX_free(keygenCtx);
                std::exit(1);
            }
            EVP_PKEY_CTX_free(keygenCtx);

            X509* cert = generateSelfSignedCert(pkey);
            if (!cert) {
                std::cerr << "[ERROR] Failed to generate X509 certificate\n";
                EVP_PKEY_free(pkey);
                std::exit(1);
            }

            if (SSL_CTX_use_certificate(sslCtx, cert) <= 0 ||
                SSL_CTX_use_PrivateKey(sslCtx, pkey) <= 0 ||
                !SSL_CTX_check_private_key(sslCtx)) {
                std::cerr << "[ERROR] Failed to use generated certificate or key\n";
                ERR_print_errors_fp(stderr);
                X509_free(cert);
                EVP_PKEY_free(pkey);
                std::exit(1);
            }

            X509_free(cert);
            EVP_PKEY_free(pkey);
        }

        SSL_CTX_set_min_proto_version(sslCtx, TLS1_2_VERSION);
    #if OPENSSL_VERSION_NUMBER >= 0x10101000L
        SSL_CTX_set_ciphersuites(sslCtx,
            "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256");
    #endif
        SSL_CTX_set_cipher_list(sslCtx,
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384");

        std::cout << "[+] TLS initialized\n";
    }

    void initUdpCrypto() {
        if (RAND_bytes(udpKey, sizeof(udpKey)) != 1) {
            std::cerr << "[ERROR] Failed to generate UDP key\n";
            std::exit(1);
        }
        udpKeyInitialized = true;
        std::cout << "[+] UDP AES-256-GCM key generated\n";
    }

    // ------------------------------------------------------------------------
    // UDP AEAD helper
    // ------------------------------------------------------------------------

    // =======================================================
// AES-256-GCM UDP Encryption (matches Android client)
// =======================================================
bool udpEncrypt(const uint8_t* in, size_t inLen, std::vector<uint8_t>& out) {
    if (!udpKeyInitialized) return false;

    unsigned char iv[12];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        return false;
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0;
    int ciphertext_len = 0;
    std::vector<uint8_t> ciphertext(inLen + 16); // extra space for tag

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, udpKey, iv) != 1) {
        
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, in, inLen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    ciphertext_len += len;

    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);

    // Build final UDP packet: [IV(12)][cipher+tag]
    out.resize(12 + ciphertext_len + 16);
    memcpy(out.data(), iv, 12);
    memcpy(out.data() + 12, ciphertext.data(), ciphertext_len);
    memcpy(out.data() + 12 + ciphertext_len, tag, 16);

    return true;
}


// =======================================================
// AES-256-GCM UDP Decryption (matches Android client)
// =======================================================
bool udpDecrypt(const uint8_t* in, size_t inLen, std::vector<uint8_t>& out) {
    if (!udpKeyInitialized) return false;
    if (inLen < 12 + 16) return false;

    const unsigned char* iv = in;
    const unsigned char* ciphertext = in + 12;
    size_t ciphertext_len = inLen - 12 - 16;
    const unsigned char* tag = in + 12 + ciphertext_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    out.resize(ciphertext_len);

    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, udpKey, iv) != 1) {

        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptUpdate(ctx, out.data(), &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (EVP_DecryptFinal_ex(ctx, out.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return false; // authentication failed
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    out.resize(plaintext_len);
    return true;
}


    // ------------------------------------------------------------------------
    // Compression helpers (zlib)
    // ------------------------------------------------------------------------

    bool compressBuffer(const uint8_t* in, size_t inLen, std::vector<uint8_t>& out) {
        uLongf destLen = compressBound(inLen);
        out.resize(destLen);
        int res = compress2(out.data(), &destLen, in, inLen, Z_BEST_SPEED);
        if (res != Z_OK) return false;
        out.resize(destLen);
        return true;
    }

    bool decompressBuffer(const uint8_t* in, size_t inLen, std::vector<uint8_t>& out,
                          size_t expectedMax = BUFFER_SIZE * 4) {
        if (inLen == 0) return false;
        out.resize(expectedMax);
        uLongf destLen = expectedMax;
        int res = uncompress(out.data(), &destLen, in, inLen);
        if (res != Z_OK) return false;
        out.resize(destLen);
        return true;
    }

    // ------------------------------------------------------------------------
    // TUN device & network configuration
    // ------------------------------------------------------------------------

    int createTunDevice(const char* dev) {
        struct ifreq ifr{};
        int fd, err;

        if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
            perror("Opening /dev/net/tun");
            return fd;
        }

        memset(&ifr, 0, sizeof(ifr));
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

        if (*dev) {
            strncpy(ifr.ifr_name, dev, IFNAMSIZ);
        }

        if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) < 0) {
            perror("ioctl(TUNSETIFF)");
            close(fd);
            return err;
        }

        std::cout << "[+] TUN device " << ifr.ifr_name << " created\n";
        return fd;
    }

    bool configureTunDevice() {
        std::cout << "\n[*] Configuring network (IPv4 + IPv6, NAT, MTU)...\n";

        if (executeCommand("ip addr add " + std::string(VPN_IPV4_SERVER) + "/24 dev " + TUN_NAME + " 2>/dev/null") != 0) {
            std::cout << "[!] IPv4 address may already be assigned, continuing...\n";
        }

        if (executeCommand("ip -6 addr add " + std::string(VPN_IPV6_SERVER) + "/64 dev " + TUN_NAME + " 2>/dev/null") != 0) {
            std::cout << "[!] IPv6 address may already be assigned, continuing...\n";
        }

        if (executeCommand("ip link set " + std::string(TUN_NAME) + " up") != 0) {
            return false;
        }

        tunMtu = computeTunMTU();
        executeCommand("ip link set " + std::string(TUN_NAME) + " mtu " + std::to_string(tunMtu));

        executeCommand("sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1");
        executeCommand("sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null 2>&1");
        executeCommand("sysctl -w net.ipv6.conf.default.forwarding=1 > /dev/null 2>&1");

        executeCommand("sysctl -w net.ipv6.conf." + interfaceName + ".accept_ra=0 > /dev/null 2>&1");

        // Clean old rules
        executeCommand("iptables -t nat -D POSTROUTING -s " + std::string(VPN_IPV4_NET) +
                       " -o " + interfaceName + " -j MASQUERADE 2>/dev/null");
        executeCommand("iptables -D FORWARD -i " + std::string(TUN_NAME) + " -o " + interfaceName +
                       " -j ACCEPT 2>/dev/null");
        executeCommand("iptables -D FORWARD -i " + interfaceName + " -o " + std::string(TUN_NAME) +
                       " -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null");

        executeCommand("ip6tables -t nat -D POSTROUTING -s " + std::string(VPN_IPV6_PREFIX) +
                       " -o " + interfaceName + " -j MASQUERADE 2>/dev/null");
        executeCommand("ip6tables -D FORWARD -i " + std::string(TUN_NAME) + " -o " + interfaceName +
                       " -j ACCEPT 2>/dev/null");
        executeCommand("ip6tables -D FORWARD -i " + interfaceName + " -o " + std::string(TUN_NAME) +
                       " -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null");

        // New NAT rules
        if (executeCommand("iptables -t nat -A POSTROUTING -s " + std::string(VPN_IPV4_NET) +
                           " -o " + interfaceName + " -j MASQUERADE") != 0) {
            std::cerr << "[!] IPv4 MASQUERADE rule failed - VPN may not have internet\n";
        }

        executeCommand("iptables -A FORWARD -i " + std::string(TUN_NAME) + " -o " + interfaceName +
                       " -j ACCEPT");
        executeCommand("iptables -A FORWARD -i " + interfaceName + " -o " + std::string(TUN_NAME) +
                       " -m state --state RELATED,ESTABLISHED -j ACCEPT");

        executeCommand("ip6tables -t nat -A POSTROUTING -s " + std::string(VPN_IPV6_PREFIX) +
                       " -o " + interfaceName + " -j MASQUERADE");
        executeCommand("ip6tables -A FORWARD -i " + std::string(TUN_NAME) + " -o " + interfaceName +
                       " -j ACCEPT");
        executeCommand("ip6tables -A FORWARD -i " + interfaceName + " -o " + std::string(TUN_NAME) +
                       " -m state --state RELATED,ESTABLISHED -j ACCEPT");

        std::cout << "[+] Network configured successfully (MTU=" << tunMtu << ")\n";
        return true;
    }

    bool setNonBlocking(int fd) {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) return false;
        return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
    }

    bool setSocketOptions(int socket) {
        int flag = 1;

        if (setsockopt(socket, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
            perror("TCP_NODELAY");
            return false;
        }

        if (setsockopt(socket, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag)) < 0) {
            perror("SO_KEEPALIVE");
            return false;
        }

        int bufsize = 262144;
        setsockopt(socket, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        setsockopt(socket, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

        struct timeval tv{};
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        return true;
    }

    // ------------------------------------------------------------------------
    // IP allocation and routing maps
    // ------------------------------------------------------------------------

    std::string assignIPToClient(const std::string& clientIP) {
        std::lock_guard<std::mutex> lock(clientsMutex);

        auto now = std::chrono::steady_clock::now();
        for (auto it = ipReservations.begin(); it != ipReservations.end();) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
            if (elapsed > 300) {
                availableIPs.push(it->first);
                it = ipReservations.erase(it);
            } else {
                ++it;
            }
        }

        if (availableIPs.empty()) {
            return "";
        }

        std::string ip = availableIPs.front();
        availableIPs.pop();
        ipReservations[ip] = now;
        return ip;
    }

    void releaseIP(const std::string& ip) {
    if (ip.empty()) return;

    std::lock_guard<std::mutex> lock(clientsMutex);

    // Completely remove reservation
    ipReservations.erase(ip);

    // Return to pool immediately
    availableIPs.push(ip);

    // Remove routing entries
    ipToTcpSocket.erase(ip);
    ipToUdpPeer.erase(ip);

    std::cout << "[+] IP released immediately: " << ip << std::endl;}


    // ------------------------------------------------------------------------
    // Authentication
    // ------------------------------------------------------------------------

    bool authenticateClient(ClientInfo& client, const std::string& clientIP) {
        char authBuffer[256];
        memset(authBuffer, 0, sizeof(authBuffer));

        const char* authReq = "AUTH_REQ";
        int sent = SSL_write(client.ssl, authReq, strlen(authReq));
        if (sent <= 0) {
            std::cout << "[-] Failed to send AUTH_REQ to " << clientIP << std::endl;
            return false;
        }

        std::cout << "[*] Sent AUTH_REQ to " << clientIP << std::endl;

        int attempts = 0;
        int maxAttempts = 3;

        while (attempts < maxAttempts) {
            fd_set readfds;
            struct timeval tv{};
            FD_ZERO(&readfds);
            FD_SET(client.socket, &readfds);
            tv.tv_sec = 5;
            tv.tv_usec = 0;

            int activity = select(client.socket + 1, &readfds, NULL, NULL, &tv);

            if (activity > 0) {
                int n = SSL_read(client.ssl, authBuffer, sizeof(authBuffer) - 1);
                if (n > 0) {
                    authBuffer[n] = '\0';
                    std::string token(authBuffer);
                    token = token.substr(0, token.find('\n'));

                    if (token == AUTH_TOKEN) {
                        const char* authOk = "AUTH_OK";
                        SSL_write(client.ssl, authOk, strlen(authOk));
                        std::cout << "[+] Client authenticated: " << clientIP << std::endl;
                        return true;
                    }
                }
            }

            attempts++;
            std::cout << "[*] Auth attempt " << attempts << " failed for " << clientIP << std::endl;
        }

        const char* authFail = "AUTH_FAIL";
        SSL_write(client.ssl, authFail, strlen(authFail));
        std::cout << "[-] Authentication failed for: " << clientIP << std::endl;
        return false;
    }

    // Clean close for pre-registered clients (handshake failures etc)
    void closeClientSocket(int sock, SSL* ssl) {
        if (ssl) {
            int r = SSL_shutdown(ssl);
            if (r == 0) {
                SSL_shutdown(ssl);
            }
            SSL_free(ssl);
        }
        if (sock >= 0) {
            shutdown(sock, SHUT_RDWR);
            close(sock);
        }
    }

    // ------------------------------------------------------------------------
    // TCP/TLS client management
    // ------------------------------------------------------------------------

    void handleNewTcpConnection() {
        while (true) {
            struct sockaddr_in clientAddr{};
            socklen_t clientLen = sizeof(clientAddr);

            int clientSocket = accept(tcpSocket, (struct sockaddr*)&clientAddr, &clientLen);
            if (clientSocket < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                perror("Accept failed");
                break;
            }

            std::string clientIP  = inet_ntoa(clientAddr.sin_addr);
            uint16_t    clientPort = ntohs(clientAddr.sin_port);

            std::cout << "[*] New TCP connection from: " << clientIP << ":" << clientPort << std::endl;

            {
                std::lock_guard<std::mutex> lock(clientsMutex);
                if ((int)clients.size() >= MAX_CLIENTS) {
                    std::cout << "[-] Max clients reached\n";
                    const char* msg = "SERVER_FULL";
                    send(clientSocket, msg, strlen(msg), 0);
                    close(clientSocket);
                    continue;
                }
            }

            std::thread(&VPNServer::handleClientHandshake, this, clientSocket, clientIP, clientPort).detach();
        }
    }

    void handleClientHandshake(int clientSocket, std::string clientIP, uint16_t clientPort) {
        SSL* ssl = nullptr;

        if (!setSocketOptions(clientSocket)) {
            std::cout << "[-] Failed to set socket options for " << clientIP << "\n";
            closeClientSocket(clientSocket, ssl);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            if ((int)clients.size() >= MAX_CLIENTS) {
                std::cout << "[-] Max clients reached (race)\n";
                const char* msg = "SERVER_FULL";
                send(clientSocket, msg, strlen(msg), 0);
                closeClientSocket(clientSocket, ssl);
                return;
            }
        }

        ssl = SSL_new(sslCtx);
        if (!ssl) {
            std::cerr << "[-] SSL_new failed for " << clientIP << "\n";
            closeClientSocket(clientSocket, nullptr);
            return;
        }
        SSL_set_fd(ssl, clientSocket);

        std::cout << "[*] Starting TLS handshake with " << clientIP << "...\n";
        if (SSL_accept(ssl) <= 0) {
            std::cerr << "[-] TLS handshake failed for " << clientIP << "\n";
            ERR_print_errors_fp(stderr);
            closeClientSocket(clientSocket, ssl);
            return;
        }
        std::cout << "[+] TLS handshake OK for " << clientIP << "\n";

        ClientInfo temp;
        temp.socket = clientSocket;
        temp.ssl    = ssl;

        if (!authenticateClient(temp, clientIP)) {
            std::cout << "[-] Authentication failed for " << clientIP << "\n";
            closeClientSocket(clientSocket, ssl);
            return;
        }

        std::string assignedIP = assignIPToClient(clientIP);
        if (assignedIP.empty()) {
            std::cout << "[-] No available IPs\n";
            const char* msg = "NO_IP_AVAILABLE";
            SSL_write(ssl, msg, strlen(msg));
            closeClientSocket(clientSocket, ssl);
            return;
        }

        std::string assignedIPv6 = makeClientIPv6(assignedIP);
        int mtuToSend = tunMtu > 0 ? tunMtu : computeTunMTU();

        std::ostringstream cfg;
        cfg << "CFG "
            << assignedIP
            << " " << VPN_IPV4_SERVER
            << " " << assignedIPv6
            << " " << VPN_IPV6_SERVER
            << " " << DNS4_PRIMARY << "," << DNS4_SECONDARY
            << " " << DNS6_PRIMARY << "," << DNS6_SECONDARY
            << " " << mtuToSend << " ";

        switch (TRANSPORT_MODE) {
            case TransportMode::UDP_PREFERRED: cfg << "HYBRID"; break;
            case TransportMode::TCP_ONLY:      cfg << "TCP";    break;
            case TransportMode::UDP_ONLY:      cfg << "UDP";    break;
        }
        cfg << "\n";

        std::string cfgStr = cfg.str();
        std::cout << "[*] Sending CFG to " << clientIP << ": " << cfgStr;
        if (SSL_write(ssl, cfgStr.c_str(), cfgStr.size()) <= 0) {
            std::cout << "[-] Failed to send CFG to client\n";
            releaseIP(assignedIP);
            closeClientSocket(clientSocket, ssl);
            return;
        }

        if (udpKeyInitialized && TRANSPORT_MODE != TransportMode::TCP_ONLY) {
            int sentKey = SSL_write(ssl, udpKey, sizeof(udpKey));
            if (sentKey != (int)sizeof(udpKey)) {
                std::cerr << "[-] Failed to send UDP key to client\n";
                releaseIP(assignedIP);
                closeClientSocket(clientSocket, ssl);
                return;
            }
            std::cout << "[+] Sent UDP key to client (" << sentKey << " bytes)\n";
        }

        if (!setNonBlocking(clientSocket)) {
            std::cerr << "[-] Failed to set non-blocking for " << clientIP << "\n";
            releaseIP(assignedIP);
            closeClientSocket(clientSocket, ssl);
            return;
        }

        struct epoll_event ev{};
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = clientSocket;

        if (epoll_ctl(epollFd, EPOLL_CTL_ADD, clientSocket, &ev) < 0) {
            perror("epoll_ctl add");
            releaseIP(assignedIP);
            closeClientSocket(clientSocket, ssl);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(clientsMutex);

            ClientInfo info;
            info.socket       = clientSocket;
            info.ssl          = ssl;
            info.ip           = clientIP;
            info.port         = clientPort;
            info.lastActivity = std::chrono::steady_clock::now();
            info.lastHeartbeat= std::chrono::steady_clock::now();
            info.authenticated= true;
            info.assignedIP   = assignedIP;
            info.assignedIPv6 = assignedIPv6;
            info.bytesSent    = 0;
            info.bytesReceived= 0;
            info.reconnectAttempts = 0;

            clients[clientSocket]       = info;
            ipToTcpSocket[assignedIP]   = clientSocket;
            ipToTcpSocket[assignedIPv6] = clientSocket;
        }

        totalConnections++;
        std::cout << "[+] Client connected: " << clientIP << ":" << clientPort
                  << " -> " << assignedIP << " / " << assignedIPv6 << std::endl;
        std::cout << "[*] Active clients: " << clients.size() << "/" << MAX_CLIENTS << std::endl;
    }

    // EPOLLET-safe non-blocking TLS read loop
    void handleClientData(int clientSocket) {
    ClientInfo* c = nullptr;

    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        auto it = clients.find(clientSocket);
        if (it == clients.end()) return;
        c = &it->second;
    }

    uint8_t temp[4096];

    while (true) {
        int n = SSL_read(c->ssl, temp, sizeof(temp));
        if (n <= 0) {
            int err = SSL_get_error(c->ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return;
            removeClient(clientSocket);
            return;
        }

        c->tcpRecvBuffer.insert(c->tcpRecvBuffer.end(), temp, temp + n);

        while (c->tcpRecvBuffer.size() >= c->tcpNeeded) {
            if (c->tcpReadingHeader) {
                uint32_t frameLen;
                memcpy(&frameLen, c->tcpRecvBuffer.data(), 4);
                frameLen = ntohl(frameLen);

                c->tcpRecvBuffer.erase(c->tcpRecvBuffer.begin(),
                                       c->tcpRecvBuffer.begin() + 4);

                c->tcpNeeded = frameLen;
                c->tcpReadingHeader = false;
            }

            if (!c->tcpReadingHeader && c->tcpRecvBuffer.size() >= c->tcpNeeded) {
                std::vector<uint8_t> payload(
                    c->tcpRecvBuffer.begin(),
                    c->tcpRecvBuffer.begin() + c->tcpNeeded
                );

                c->tcpRecvBuffer.erase(
                    c->tcpRecvBuffer.begin(),
                    c->tcpRecvBuffer.begin() + c->tcpNeeded
                );

                c->tcpNeeded = 4;
                c->tcpReadingHeader = true;

                std::vector<uint8_t> decompressed;
                if (!decompressBuffer(payload.data(), payload.size(), decompressed))
                    decompressed = payload;

                write(tunFd, decompressed.data(), decompressed.size());
            }
        }
    }}



    void flushClientSendQueue(int clientSocket) {
        bool needRemove = false;
        auto now = std::chrono::steady_clock::now();

        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            auto it = clients.find(clientSocket);
            if (it == clients.end()) return;
            ClientInfo& c = it->second;

            while (!c.sendQueue.empty()) {
                std::vector<uint8_t>& buf = c.sendQueue.front();
                
                // prepare framed buffer: 4 byte length + payload
                uint32_t len = htonl((uint32_t)buf.size());
                std::vector<uint8_t> framed(4 + buf.size());
                memcpy(framed.data(), &len, 4);
                memcpy(framed.data() + 4, buf.data(), buf.size());
                int sent = SSL_write(c.ssl, framed.data(), framed.size());
                if (sent <= 0) {
                    int err = SSL_get_error(c.ssl, sent);
                    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                        // can't send more now
                        break;
                    } else {
                        needRemove = true;
                        break;
                    }
                } else if ((size_t)sent < buf.size()) {
                    buf.erase(buf.begin(), buf.begin() + sent);
                    c.bytesSent += sent;
                    totalBytesSent += sent;
                    c.lastActivity = now;
                    break;
                } else {
                    c.bytesSent += sent;
                    totalBytesSent += sent;
                    c.lastActivity = now;
                    c.sendQueue.pop_front();
                }
            }

            if (!needRemove && c.sendQueue.empty()) {
                struct epoll_event ev{};
                ev.events = EPOLLIN | EPOLLET;
                ev.data.fd = clientSocket;
                epoll_ctl(epollFd, EPOLL_CTL_MOD, clientSocket, &ev);
            }
        }

        if (needRemove) {
            removeClient(clientSocket);
        }
    }

    void sendDisconnectSignal(int clientSocket) {
    if (clients.find(clientSocket) == clients.end()) return;

    const char* msg = "DC";    // 2-byte disconnect command
    uint32_t len = htonl(2);

    uint8_t frame[6];
    memcpy(frame, &len, 4);
    memcpy(frame + 4, msg, 2);

    SSL_write(clients[clientSocket].ssl, frame, sizeof(frame));}


    void removeClient(int clientSocket) {
    std::lock_guard<std::mutex> lock(clientsMutex);

    auto it = clients.find(clientSocket);
    if (it == clients.end()) return;
    sendDisconnectSignal(clientSocket);

    std::string ip4  = it->second.assignedIP;
    std::string ip6  = it->second.assignedIPv6;

    // Release IP immediately
    releaseIP(ip4);
    ipToTcpSocket.erase(ip6);
    ipToUdpPeer.erase(ip6);

    epoll_ctl(epollFd, EPOLL_CTL_DEL, clientSocket, nullptr);

    SSL_shutdown(it->second.ssl);
    SSL_free(it->second.ssl);

    shutdown(clientSocket, SHUT_RDWR);
    close(clientSocket);

    clients.erase(it);

    std::cout << "[CLIENT] Removed socket " << clientSocket << std::endl;}



    // ------------------------------------------------------------------------
    // UDP handling (hybrid + NAT rebinding)
    // ------------------------------------------------------------------------

    void handleUdpPacket() {
        if (TRANSPORT_MODE == TransportMode::TCP_ONLY) {
            char tmp[BUFFER_SIZE];
            recvfrom(udpSocket, tmp, sizeof(tmp), 0, nullptr, nullptr);
            return;
        }

        char buffer[BUFFER_SIZE * 2];
        sockaddr_in clientAddr{};
        socklen_t len = sizeof(clientAddr);

        int n = recvfrom(udpSocket, buffer, sizeof(buffer), 0,
                         (struct sockaddr*)&clientAddr, &len);
        if (n <= 0) return;

        std::vector<uint8_t> decrypted;
        if (!udpDecrypt((uint8_t*)buffer, (size_t)n, decrypted)) {
            return;
        }

        std::vector<uint8_t> decompressed;
        if (!decompressBuffer(decrypted.data(), decrypted.size(), decompressed)) {
            decompressed = std::move(decrypted);
        }

        if (decompressed.empty()) return;

        unsigned char* pkt = decompressed.data();
        uint8_t version = pkt[0] >> 4;

        std::string srcIpStr;

        if (version == 4) {
            if (decompressed.size() < 20) return;
            uint32_t src;
            std::memcpy(&src, pkt + 12, 4);
            struct in_addr srcAddr{};
            srcAddr.s_addr = src;
            srcIpStr = inet_ntoa(srcAddr);
        }
        else if (version == 6) {
            if (decompressed.size() < 40) return;
            char addr6[INET6_ADDRSTRLEN] = {0};
            if (inet_ntop(AF_INET6, pkt + 8, addr6, sizeof(addr6)) == nullptr) {
                return;
            }
            srcIpStr = addr6;
        }
        else {
            return;
        }

        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            auto& peer = ipToUdpPeer[srcIpStr];
            peer.addr = clientAddr;
            peer.lastActivity = std::chrono::steady_clock::now();
        }

        int written = write(tunFd, decompressed.data(), (int)decompressed.size());
        if (written > 0) {
            totalBytesReceived += (uint64_t)written;
        }
    }

    // ------------------------------------------------------------------------
    // TUN reading (routing to TCP/UDP) – robust loop
    // ------------------------------------------------------------------------

    void handleTunDataOnce() {
        while (true) {
            char buffer[BUFFER_SIZE];

            int n = read(tunFd, buffer, BUFFER_SIZE);
            if (n <= 0) {
                if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    break;
                }
                if (n < 0) {
                    perror("TUN read error");
                }
                return;
            }

            if (n < 20) continue;

            unsigned char* pkt = (unsigned char*)buffer;
            uint8_t version = pkt[0] >> 4;
            if (version != 4 && version != 6) {
                continue;
            }

            std::string dstIpStr;
            if (version == 4) {
                if (n < 20) continue;
                uint32_t dst;
                std::memcpy(&dst, pkt + 16, 4);
                struct in_addr dstAddr{};
                dstAddr.s_addr = dst;
                dstIpStr = inet_ntoa(dstAddr);
            } else {
                if (n < 40) continue;
                char addr6[INET6_ADDRSTRLEN];
                if (inet_ntop(AF_INET6, pkt + 24, addr6, sizeof(addr6)) == nullptr) {
                    continue;
                }
                dstIpStr = addr6;
            }

            int      targetTcpSocket = -1;
            bool     hasUdpPeer = false;
            UdpPeer  udpPeerCopy{};

            {
                std::lock_guard<std::mutex> lock(clientsMutex);
                auto itTcp = ipToTcpSocket.find(dstIpStr);
                if (itTcp != ipToTcpSocket.end()) {
                    targetTcpSocket = itTcp->second;
                }

                auto itUdp = ipToUdpPeer.find(dstIpStr);
                if (itUdp != ipToUdpPeer.end()) {
                    hasUdpPeer = true;
                    udpPeerCopy = itUdp->second;
                }
            }

            if (TRANSPORT_MODE == TransportMode::TCP_ONLY) {
                hasUdpPeer = false;
            } else if (TRANSPORT_MODE == TransportMode::UDP_ONLY) {
                targetTcpSocket = -1;
            }

            if (targetTcpSocket == -1 && !hasUdpPeer) {
                continue;
            }

            // TCP path
            if (targetTcpSocket != -1) {
                std::vector<uint8_t> compressed;
                if (!compressBuffer((uint8_t*)buffer, (size_t)n, compressed)) {
                    compressed.assign(reinterpret_cast<uint8_t*>(buffer),
                                      reinterpret_cast<uint8_t*>(buffer) + n);
                }

                {
                    std::lock_guard<std::mutex> lock(clientsMutex);
                    auto it = clients.find(targetTcpSocket);
                    if (it != clients.end() && it->second.authenticated) {
                        it->second.sendQueue.emplace_back(std::move(compressed));
                        it->second.lastActivity = std::chrono::steady_clock::now();
                        struct epoll_event ev{};
                        ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
                        ev.data.fd = targetTcpSocket;
                        epoll_ctl(epollFd, EPOLL_CTL_MOD, targetTcpSocket, &ev);
                    }
                }
            }

            // UDP path
            if (hasUdpPeer) {
                std::vector<uint8_t> compressed;
                if (!compressBuffer((uint8_t*)buffer, (size_t)n, compressed)) {
                    compressed.assign((uint8_t*)buffer, (uint8_t*)buffer + n);
                }

                std::vector<uint8_t> encrypted;
                if (!udpEncrypt(compressed.data(), compressed.size(), encrypted)) {
                    continue;
                }

                sendto(udpSocket, encrypted.data(), (int)encrypted.size(), 0,
                       (struct sockaddr*)&udpPeerCopy.addr, sizeof(udpPeerCopy.addr));
                totalBytesSent += (uint64_t)n;
            }
        }
    }

    // ------------------------------------------------------------------------
    // Monitoring & Stats (server-side heartbeat + timeout)
    // ------------------------------------------------------------------------

    void monitorClients() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(10));

            auto now = std::chrono::steady_clock::now();
            std::vector<int> disconnected;

            {
                std::lock_guard<std::mutex> lock(clientsMutex);
                for (auto& pair : clients) {
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                        now - pair.second.lastActivity).count();

                    if (elapsed > CLIENT_TIMEOUT) {
                        std::cout << "[!] Client timeout: " << pair.second.ip << std::endl;
                        disconnected.push_back(pair.first);
                        continue;
                    }

                    if (elapsed > HEARTBEAT_INTERVAL) {
                        // Enqueue a tiny heartbeat frame, don't write SSL from this thread
                        std::vector<uint8_t> hb(1, 0x00);
                        pair.second.sendQueue.emplace_back(std::move(hb));
                        pair.second.lastHeartbeat = now;
                        struct epoll_event ev{};
                        ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
                        ev.data.fd = pair.first;
                        epoll_ctl(epollFd, EPOLL_CTL_MOD, pair.first, &ev);
                    }
                }

                for (auto it = ipToUdpPeer.begin(); it != ipToUdpPeer.end();) {
                    auto age = std::chrono::duration_cast<std::chrono::seconds>(
                        now - it->second.lastActivity).count();
                    if (age > 60) {
                        it = ipToUdpPeer.erase(it);
                    } else {
                        ++it;
                    }
                }
            }

            for (int sock : disconnected) {
                removeClient(sock);
            }
        }
    }

    void printStats() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::seconds(30));

            std::lock_guard<std::mutex> lock(clientsMutex);
            std::cout << "\n========== VPN STATISTICS ==========\n";
            std::cout << "Active Clients: " << clients.size() << "/" << MAX_CLIENTS << std::endl;
            std::cout << "Total Connections: " << totalConnections << std::endl;
            std::cout << "Total Sent: " << totalBytesSent / 1024 / 1024 << " MB\n";
            std::cout << "Total Received: " << totalBytesReceived / 1024 / 1024 << " MB\n";
            std::cout << "Transport mode: ";
            switch (TRANSPORT_MODE) {
                case TransportMode::UDP_PREFERRED: std::cout << "HYBRID (UDP+TCP)"; break;
                case TransportMode::TCP_ONLY:      std::cout << "TCP_ONLY"; break;
                case TransportMode::UDP_ONLY:      std::cout << "UDP_ONLY"; break;
            }
            std::cout << "\n====================================\n\n";
        }
    }

    void clearIptables() {
        std::cout << "[*] Clearing ALL iptables rules (IPv4 + IPv6)...\n";

        executeCommand("iptables -F");
        executeCommand("iptables -X");
        executeCommand("iptables -t nat -F");
        executeCommand("iptables -t nat -X");
        executeCommand("iptables -t mangle -F");
        executeCommand("iptables -t mangle -X");
        executeCommand("iptables -t raw -F");
        executeCommand("iptables -t raw -X");
        executeCommand("iptables -t security -F");
        executeCommand("iptables -t security -X");

        executeCommand("iptables -P INPUT ACCEPT");
        executeCommand("iptables -P FORWARD ACCEPT");
        executeCommand("iptables -P OUTPUT ACCEPT");

        executeCommand("ip6tables -F");
        executeCommand("ip6tables -X");
        executeCommand("ip6tables -t nat -F 2>/dev/null");
        executeCommand("ip6tables -t nat -X 2>/dev/null");
        executeCommand("ip6tables -t mangle -F");
        executeCommand("ip6tables -t mangle -X");
        executeCommand("ip6tables -t raw -F");
        executeCommand("ip6tables -t raw -X");
        executeCommand("ip6tables -t security -F");
        executeCommand("ip6tables -t security -X");

        executeCommand("ip6tables -P INPUT ACCEPT");
        executeCommand("ip6tables -P FORWARD ACCEPT");
        executeCommand("ip6tables -P OUTPUT ACCEPT");

        std::cout << "[+] iptables fully reset.\n";
    }

    // ------------------------------------------------------------------------
    // Startup & main loop
    // ------------------------------------------------------------------------

    bool start() {
        std::cout << "\n========================================\n";
        std::cout << "  Modern VPN Server - Hybrid TCP/UDP\n";
        std::cout << "  TLS + ChaCha20 + Compression + IPv6\n";
        std::cout << "========================================\n\n";

        clearIptables();

        tunFd = createTunDevice(TUN_NAME);
        if (tunFd < 0) {
            return false;
        }

        if (!configureTunDevice()) {
            std::cerr << "[ERROR] Network configuration failed\n";
            return false;
        }

        tcpSocket = socket(AF_INET6, SOCK_STREAM, 0);
        if (tcpSocket < 0) {
            perror("TCP socket creation failed");
            return false;
        }
        // Allow IPv4+IPv6 on same socket
        int off = 0;
        setsockopt(tcpSocket, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
        int opt = 1;
        setsockopt(tcpSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(tcpSocket, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

        sockaddr_in6 serverAddr6{};
        serverAddr6.sin6_family = AF_INET6;
        serverAddr6.sin6_addr   = in6addr_any;
        serverAddr6.sin6_port   = htons(PORT);

        if (bind(tcpSocket, (sockaddr*)&serverAddr6, sizeof(serverAddr6)) < 0) {

            perror("TCP bind failed");

            return false;
        }

        if (listen(tcpSocket, 128) < 0) {
            perror("Listen failed");
            return false;
        }

        setNonBlocking(tcpSocket);

        udpSocket = socket(AF_INET6, SOCK_DGRAM, 0);
    

        setsockopt(udpSocket, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));


        sockaddr_in6 udpAddr6{};

        udpAddr6.sin6_family = AF_INET6;

        udpAddr6.sin6_addr   = in6addr_any;

        udpAddr6.sin6_port   = htons(UDP_PORT);


        bind(udpSocket, (sockaddr*)&udpAddr6, sizeof(udpAddr6));
        

        setNonBlocking(udpSocket);

        setNonBlocking(tunFd);

        epollFd = epoll_create1(0);
        if (epollFd < 0) {
            perror("Epoll creation failed");
            return false;
        }

        struct epoll_event ev{};
        ev.events = EPOLLIN;
        ev.data.fd = tcpSocket;
        epoll_ctl(epollFd, EPOLL_CTL_ADD, tcpSocket, &ev);

        struct epoll_event tev{};
        tev.events = EPOLLIN;
        tev.data.fd = tunFd;
        epoll_ctl(epollFd, EPOLL_CTL_ADD, tunFd, &tev);

        struct epoll_event uev{};
        uev.events = EPOLLIN;
        uev.data.fd = udpSocket;
        epoll_ctl(epollFd, EPOLL_CTL_ADD, udpSocket, &uev);

        std::cout << "[+] TCP Server listening on 0.0.0.0:" << PORT << std::endl;
        std::cout << "[+] UDP Server listening on 0.0.0.0:" << UDP_PORT << std::endl;
        std::cout << "[+] TUN interface: " << TUN_NAME << " (" << VPN_IPV4_SERVER << "/24, " << VPN_IPV6_SERVER << "/64)\n";
        std::cout << "[+] Outbound interface: " << interfaceName << std::endl;
        std::cout << "[+] Max clients: " << MAX_CLIENTS << std::endl;
        std::cout << "[+] Authentication: Enabled (token)\n";
        std::cout << "[+] TLS: Enabled\n";
        std::cout << "[+] UDP AEAD: AES-256-GCM\n\n";

        std::thread monitorThread(&VPNServer::monitorClients, this);
        std::thread statsThread(&VPNServer::printStats, this);
        monitorThread.detach();
        statsThread.detach();

        struct epoll_event events[MAX_EVENTS];

        while (g_running) {
            int nfds = epoll_wait(epollFd, events, MAX_EVENTS, 1000);

            if (nfds < 0) {
                if (errno == EINTR) continue;
                perror("epoll_wait");
                break;
            }

            for (int i = 0; i < nfds; i++) {
                int fd = events[i].data.fd;

                if (fd == tcpSocket) {
                    handleNewTcpConnection();
                } else if (fd == tunFd) {
                    handleTunDataOnce();
                } else if (fd == udpSocket) {
                    handleUdpPacket();
                } else {
                    if (events[i].events & EPOLLIN) {
                        handleClientData(fd);
                    }
                    if (events[i].events & EPOLLOUT) {
                        flushClientSendQueue(fd);
                    }
                }
            }
        }

        return true;
    }

    // ------------------------------------------------------------------------
    // Cleanup
    // ------------------------------------------------------------------------

    void cleanup() {
        std::cout << "\n[*] Cleaning up...\n";

        g_running = false;

        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            for (auto& pair : clients) {
                if (pair.second.ssl) {
                    int r = SSL_shutdown(pair.second.ssl);
                    if (r == 0) SSL_shutdown(pair.second.ssl);
                    SSL_free(pair.second.ssl);
                }
                shutdown(pair.first, SHUT_RDWR);
                close(pair.first);
            }
            clients.clear();
        }

        if (udpSocket >= 0) {
            shutdown(udpSocket, SHUT_RDWR);
            close(udpSocket);
            udpSocket = -1;
        }

        if (tcpSocket >= 0) {
            shutdown(tcpSocket, SHUT_RDWR);
            close(tcpSocket);
            tcpSocket = -1;
        }

        if (tunFd >= 0) {
            close(tunFd);
            tunFd = -1;
        }

        if (epollFd >= 0) {
            close(epollFd);
            epollFd = -1;
        }

        std::cout << "[*] Removing TUN + iptables rules...\n";

        executeCommand("iptables -t nat -D POSTROUTING -s " + std::string(VPN_IPV4_NET) +
                       " -o " + interfaceName + " -j MASQUERADE 2>/dev/null");
        executeCommand("iptables -D FORWARD -i " + std::string(TUN_NAME) + " -o " + interfaceName +
                       " -j ACCEPT 2>/dev/null");
        executeCommand("iptables -D FORWARD -i " + interfaceName + " -o " + std::string(TUN_NAME) +
                       " -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null");

        executeCommand("ip6tables -t nat -D POSTROUTING -s " + std::string(VPN_IPV6_PREFIX) +
                       " -o " + interfaceName + " -j MASQUERADE 2>/dev/null");
        executeCommand("ip6tables -D FORWARD -i " + std::string(TUN_NAME) + " -o " + interfaceName +
                       " -j ACCEPT 2>/dev/null");
        executeCommand("ip6tables -D FORWARD -i " + interfaceName + " -o " + std::string(TUN_NAME) +
                       " -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null");

        executeCommand("ip link set " + std::string(TUN_NAME) + " down 2>/dev/null");
        executeCommand("ip link delete " + std::string(TUN_NAME) + " 2>/dev/null");

        if (sslCtx) {
            SSL_CTX_free(sslCtx);
            sslCtx = nullptr;
        }

        std::cout << "[+] Cleanup complete\n";
    }
};

int main() {
    if (geteuid() != 0) {
        std::cerr << "[ERROR] This program must be run as root (use sudo)\n";
        return 1;
    }

    VPNServer server;

    if (!server.start()) {
        std::cerr << "[ERROR] Failed to start VPN server\n";
        return 1;
    }

    std::cout << "[*] Server stopped\n";
    return 0;
}
