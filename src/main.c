#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <limits.h>
#include <unistd.h>
#include "toml_parser.h"
#include "dns_parser.h"

#define BUFFER_SIZE     1024
#define PORT            9898

static int get_executable_dir(char* out_path, size_t size);

int main(int argc, char* argv[]) {
    uint16_t port = PORT;

    int opt;

    while ((opt = getopt(argc, argv, "p:")) != -1) {
        switch (opt) {
            case 'p': {
                long p = strtol(optarg, NULL, 10);
                if (p <= 0 || p > 65535) {
                    fprintf(stderr, "Invalid port number: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
                port = (uint16_t)p;
                break;
            }
            default:
                fprintf(stderr, "Usage: %s [-p port]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }
    
    char exe_dir[PATH_MAX];
    char config_path[PATH_MAX];

    if (get_executable_dir(exe_dir, sizeof(exe_dir)) < 0) {
        exit(EXIT_FAILURE);
    }

    snprintf(config_path, sizeof(config_path), "%s/config.toml", exe_dir);

    config_data config = tp_parse(config_path);
    tp_print_config(&config);

    uint8_t buffer[BUFFER_SIZE];
    
    // main
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Socket creation failed");
        tp_free_config(&config);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr = {0};

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sockfd);
        tp_free_config(&config);
        exit(EXIT_FAILURE);
    }

    // proxy
    int proxyfd = socket(AF_INET, SOCK_DGRAM, 0);
    
    if (proxyfd < 0) {
        perror("Proxy socket creation failed");
        close(sockfd);
        tp_free_config(&config);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in upstream_addr = {0};
    upstream_addr.sin_family = AF_INET;
    upstream_addr.sin_port = htons(53);

    if (inet_pton(AF_INET, config.dns_server, &upstream_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid DNS server IP in config: %s\n", config.dns_server);
        close(sockfd);
        close(proxyfd);
        tp_free_config(&config);
        exit(EXIT_FAILURE);
    }

    struct timeval timeout = {2, 0};
    if (setsockopt(proxyfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt failed");
        close(sockfd);
        close(proxyfd);
        tp_free_config(&config);
        exit(EXIT_FAILURE);
    }

    printf("\n");
    printf("\n");
    printf("UDP DNS proxy server listening on port %d...\n", port);
    printf("\n");

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        ssize_t len = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                               (struct sockaddr *)&client_addr, &client_len);

        if (len < 0) {
            perror("Receive from client failed");
            continue;
        }
        
        if (len < 12) {
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        printf("Received from %s:%d, %zd bytes\n", client_ip, ntohs(client_addr.sin_port), len);

        dns_packet_t packet = {0};
        if (dns_parse_request_packet(buffer, len, &packet) < 0) {
            fprintf(stderr, "Invalid DNS request from %s\n", client_ip);
            dns_free_packet(&packet);
            continue;
        }

        bool is_blacklisted = false;
        for (int i = 0; i < packet.header.question_count; i++) {
            printf("Query: %s : ", packet.questions[i].domain_name);
            if (dns_is_blacklisted_ip(packet.questions[i].domain_name, &config)) {
                printf("blacklisted\n\n");
                is_blacklisted = true;
                break;
            } else {
                printf("redirected to upstream dns\n\n");
                dns_free_packet(&packet);
                break;
            }
        }

        if (is_blacklisted) {
            uint8_t response[BUFFER_SIZE];
            ssize_t resp_len = dns_create_response_with_error(buffer, len, response, config.blacklist_response_code);
            ssize_t sent = sendto(sockfd, response, resp_len, 0,
                                  (struct sockaddr *)&client_addr, client_len);
            if (sent < 0) {
                perror("sendto client failed");
            }

            dns_free_packet(&packet);
            continue;
        }

        printf("\n");

        ssize_t sent = sendto(proxyfd, buffer, len, 0,
                              (struct sockaddr *)&upstream_addr, sizeof(upstream_addr));
        if (sent < 0) {
            perror("sendto upstream failed");
            continue;
        }

        uint8_t response[BUFFER_SIZE];
        ssize_t resp_len = recvfrom(proxyfd, response, BUFFER_SIZE, 0, NULL, NULL);
        if (resp_len < 0) {
            perror("recvfrom upstream failed or timed out");
            continue;
        }

        sent = sendto(sockfd, response, resp_len, 0,
                      (struct sockaddr *)&client_addr, client_len);
        if (sent < 0) {
            perror("sendto client failed");
        }
    }

    tp_free_config(&config);
    close(proxyfd);
    close(sockfd);

    return 0;
}


static int get_executable_dir(char* out_path, size_t size) {
    ssize_t len = readlink("/proc/self/exe", out_path, size - 1);

    if (len == -1) {
        perror("read link");
        return -1;
    }

    out_path[len] = '\0';

    char* last_slash = strrchr(out_path, '/');

    if (!last_slash) {
        fprintf(stderr, "Invalid path to executable file\n");
        return -1;
    }

    *last_slash = '\0';

    return 0;
}