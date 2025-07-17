#include "dns_parser.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static char* decode_domain_name(const uint8_t* buffer, int* offset, int buffer_len) {
    char* name = malloc(256);
    if (!name) return NULL;
    
    int name_pos = 0;
    int jumped = 0;
    int orig_offset = *offset;

    while (*offset < buffer_len && buffer[*offset] != 0x00) {
        uint8_t len = buffer[*offset];
        *offset += 1;

        if (len >= 0xC0) {
            if (*offset >= buffer_len) {
                free(name);
                return NULL;
            }
            uint16_t pointer = ((len & 0x3F) << 8) | buffer[*offset];
            *offset += 1;
            if (!jumped) {
                orig_offset = *offset;
                jumped = 1;
            }
            *offset = pointer;
            continue;
        }

        if (name_pos > 0 && name_pos < 255) {
            name[name_pos++] = '.';
        }

        if (*offset + len > buffer_len || name_pos + len > 255) {
            free(name);
            return NULL;
        }

        for (int i = 0; i < len; i++) {
            name[name_pos++] = buffer[*offset];
            *offset += 1;
        }
    }
    
    if (*offset >= buffer_len) {
        free(name);
        return NULL;
    }
    name[name_pos] = '\0';

    *offset += 1; 

    if (jumped) {
        *offset = orig_offset;
    }
    return name;
}

int dns_parse_request_packet(const uint8_t* buffer, int buffer_len, dns_packet_t* packet) {
    dns_header_t tmp_header;
    memcpy(&tmp_header, buffer, sizeof(dns_header_t));

    packet->header.id               = ntohs(tmp_header.id);
    packet->header.flags            = ntohs(tmp_header.flags);
    packet->header.question_count   = ntohs(tmp_header.question_count);
    packet->header.answer_count     = ntohs(tmp_header.answer_count);
    packet->header.nameserver_count = ntohs(tmp_header.nameserver_count);
    packet->header.additional_count = ntohs(tmp_header.additional_count);

    if (packet->header.question_count == 0) {
        packet->questions = NULL;
        return 0;
    }

    packet->questions = malloc(packet->header.question_count * sizeof(dns_question_t));
    if (!packet->questions) return -1;

    int offset = 12;
    for (int i = 0; i < packet->header.question_count; i++) {
        packet->questions[i].domain_name = decode_domain_name(buffer, &offset, buffer_len);

        if (!packet->questions[i].domain_name) {
            for (int j = 0; j < i; j++) {
                free(packet->questions[j].domain_name);
            }
            free(packet->questions);
            return -1;
        }

        if (offset + 4 > buffer_len) {
            free(packet->questions[i].domain_name);
            for (int j = 0; j < i; j++) {
                free(packet->questions[j].domain_name);
            }
            free(packet->questions);
            return -1;
        }

        uint16_t type_net, class_net;
        memcpy(&type_net,  buffer + offset, 2);
        memcpy(&class_net, buffer + offset + 2, 2);
        packet->questions[i].type   = ntohs(type_net);
        packet->questions[i].qclass = ntohs(class_net);
        offset += 4;
    }

    return 0;
}

bool dns_is_blacklisted_ip(const char* addr, const config_data* confg) {
    if (!addr || !confg)
        return false;

    for (size_t i = 0; i < confg->blacklist_ips_size; i++) {
        const char* entry = confg->blacklist_ips[i];
        if (!entry)
            continue;

        size_t entry_len = strlen(entry);

        if (entry_len > 8 && entry[0] == '*' && entry[1] == '.' &&
            entry[entry_len - 2] == '.' && entry[entry_len - 1] == '*') {

            size_t middle_len = entry_len - 4;
            char middle[256];
            if (middle_len >= sizeof(middle))
                continue;

            strncpy(middle, entry + 2, middle_len);
            middle[middle_len] = '\0';

            size_t addr_len = strlen(addr);

            if (addr_len < middle_len)
                continue;

            const char* pos = strstr(addr, middle);

            if (pos) {
                bool valid_before = (*(pos - 1) == '.');
                const char* after = pos + middle_len;
                bool valid_after = (*after == '.') && (*(after + 1) != '\0');

                if (valid_before && valid_after) {
                    return true;
                }
            }
        }
        else {
            if (strcmp(addr, entry) == 0) {
                return true;
            }
        }
    }
    return false;
}

ssize_t dns_create_response_with_error(uint8_t* request, ssize_t req_len, uint8_t* response, int FLAGS) {
    memcpy(response, request, req_len);
    
    dns_header_t header;
    memcpy(&header, response, sizeof(dns_header_t));

    header.flags = htons(ntohs(header.flags) | (0x8000 | FLAGS));
    header.answer_count = 0;
    header.additional_count = 0;

    memcpy(response, &header, sizeof(dns_header_t));

    return req_len;
}

void dns_free_packet(dns_packet_t* packet) {
    if (!packet) {
        return;
    }
    
    if (packet->questions) {
        for (int i = 0; i < packet->header.question_count; i++) {
            free(packet->questions[i].domain_name);
        }
        free(packet->questions);
    }

    packet->questions = NULL;
        
    packet->header.question_count = 0;
    packet->header.flags = 0;
    packet->header.id = 0;
    packet->header.additional_count = 0;
    packet->header.nameserver_count = 0;
    packet->header.answer_count = 0;
}