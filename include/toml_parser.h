#ifndef TOML_PARSER_H
#define TOML_PARSER_H

#include "tomlc17.h"

typedef struct {
    char* dns_server;
    char** blacklist_ips;
    size_t blacklist_ips_size;
    int blacklist_response_code;
} config_data;

config_data tp_parse(const char* config_file);
void tp_print_config(const config_data* config);
void tp_free_config(config_data* config);

#endif // TOML_PARSER_H