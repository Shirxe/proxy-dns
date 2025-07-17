#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include <stdio.h>
#include <stdint.h>
#include <toml_parser.h>

typedef struct {
    uint16_t id;
    uint16_t flags;
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t nameserver_count;
    uint16_t additional_count;  
} dns_header_t;

typedef struct {
    char* domain_name;
    uint16_t type;
    uint16_t qclass;
} dns_question_t;

typedef struct {
    dns_header_t header;
    dns_question_t *questions;
} dns_packet_t;

int dns_parse_request_packet(const uint8_t* buffer, int buffer_len, dns_packet_t* packet);

void dns_free_packet(dns_packet_t* packet);

bool dns_is_blacklisted_ip(const char* addr, const config_data* confg);

ssize_t dns_create_response_with_error(uint8_t* request, ssize_t req_len, uint8_t* response, int FLAGS);

#endif // DNS_PARSER_H