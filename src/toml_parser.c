#include "toml_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static void error(const char* msg) {
    fprintf(stderr, "ERROR: %s\n", msg);
    exit(EXIT_FAILURE);
}

static void free_config_data(config_data* config) {
    if (config->dns_server) {
        free(config->dns_server);
    }

    for (size_t i = 0; i < config->blacklist_ips_size; i++) {
        if (config->blacklist_ips[i]) {
            free(config->blacklist_ips[i]);
        }
    }

    if (config->blacklist_ips) {
        free(config->blacklist_ips);
    }
}

static char* strdup_safe(const char* src) {
    if (!src) return NULL;

    char* dest = strdup(src);

    if (!dest) {
        error("Memory allocation failed");
    }

    return dest;
}

static int is_valid_ipv4(const char* ip) {
    if (!ip) return 0;

    int dot_counter = 0;
    int digit_counter = 0;
    int segment_value = 0;

    while (*ip) {
        if (!isdigit((unsigned char)*ip) && *ip != '.') return 0;

        if (*ip == '.') {
            if (digit_counter == 0) return 0;
            if (++dot_counter == 4) return 0;

            digit_counter = 0;
            segment_value = 0;
            ip++;
            continue;
        }

        segment_value = segment_value * 10 + (*ip - '0');
        if (++digit_counter > 3 || segment_value > 255) return 0;

        ip++;
    }

    return dot_counter == 3 && digit_counter > 0;
}

config_data tp_parse(const char* config_file) {
    config_data config = {0};

    if (!config_file) {
        error("Config file path is NULL");
    }

    toml_result_t result = toml_parse_file_ex(config_file);
    if (!result.ok) {
        error(result.errmsg);
    }

    toml_datum_t dns_server = toml_seek(result.toptab, "dns_server");
    toml_datum_t blacklist_ips = toml_seek(result.toptab, "blacklist");
    toml_datum_t blacklist_response_code = toml_seek(result.toptab, "blacklist_response_code");

    if (dns_server.type != TOML_STRING || !dns_server.u.str.ptr || !is_valid_ipv4(dns_server.u.str.ptr)) {
        toml_free(result);
        error("Missing or invalid 'dns_server' property in config\nExample: 'dns_server = \"8.8.8.8\"'");
    }

    if (blacklist_ips.type != TOML_ARRAY) {
        toml_free(result);
        error("Missing or invalid 'blacklist' property in config\nExample: 'blacklist = [\"example.com\", \"test.com\"]'");
    }

    if (blacklist_response_code.type != TOML_INT64) {
        toml_free(result);
        error("Missing or invalid 'blacklist_response_code' property in config\nExample: 'blacklist_response_code = \"3\"'");
    }

    config.dns_server = strdup_safe(dns_server.u.str.ptr);
    config.blacklist_response_code = blacklist_response_code.u.int64;

    config.blacklist_ips_size = blacklist_ips.u.arr.size;

    if (config.blacklist_ips_size > 0) {
        config.blacklist_ips = malloc(config.blacklist_ips_size * sizeof(char*));

        if (!config.blacklist_ips) {
            toml_free(result);
            free_config_data(&config);
            error("Memory allocation failed for blacklist_ips");
        }

        for (size_t i = 0; i < config.blacklist_ips_size; i++) {
            toml_datum_t elem = blacklist_ips.u.arr.elem[i];
            
            if (elem.type != TOML_STRING || !elem.u.str.ptr) {
                toml_free(result);
                free_config_data(&config);
                error("'blacklist_ips' element not a string");
            }

            config.blacklist_ips[i] = strdup_safe(elem.u.str.ptr);
        }
    }

    toml_free(result);
    return config;
}

void tp_print_config(const config_data* config) {
    if (!config) return;

    printf("UPSTREAM DNS IP: %s\n", config->dns_server);
    printf("Blacklist response: %d\n", config->blacklist_response_code);
    
    printf("Blacklist IPs = [");
    for (size_t i = 0; i < config->blacklist_ips_size; i++) {
        printf("%s%s", i ? ", " : "", config->blacklist_ips[i]);
    }
    printf("]\n");
}

void tp_free_config(config_data* config) {
    if (config) {
        free_config_data(config);
        config->dns_server = NULL;
        config->blacklist_ips = NULL;
    }
}