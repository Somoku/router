#include <iostream>
#include <string>
#include <cstring>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "router.h"

RouterBase* create_router_object() {
    return new Router;
}

int Router::data_handler(int in_port, Header header, char* payload, char* packet){
    return -1;
}

int Router::dv_handler(int in_port, Header header, char* payload, char* packet){
    return -1;
}

int Router::control_handler(int in_port, Header header, char* payload, char* packet){
    return -1;
}

void Router::router_init(int port_num, int external_port, char* external_addr, char* available_addr) {
    this->port_num = port_num;
    this->external_port = external_port;
    if(external_port == 0){
        this->external_addr = nullptr;
        this->available_addr = nullptr;
        this->available_mask = 0;
        this->external_mask = 0;
        return;
    }
    // Split CIDR external_addr into ip + mask
    this->external_addr = strtok(external_addr, "/");
    this->external_mask = atoi(strtok(NULL, "/"));

    // Split CIDR available_addr into ip + mask
    this->available_addr = strtok(available_addr, "/");
    this->available_mask = atoi(strtok(NULL, "/"));
    return;
}

int Router::router(int in_port, char* packet) {
    // Analyze received packet.
    Header header;
    memcpy(&header, packet, HEADER_SIZE);
    char* payload{new char[header.length]};
    memcpy(payload, packet + HEADER_SIZE, header.length);

    // Handle different types.
    switch(header.type){
        case TYPE_DV:
            return dv_handler(in_port, header, payload, packet);
        case TYPE_DATA:
            return data_handler(in_port, header, payload, packet);
        case TYPE_CONTROL:
            return control_handler(in_port, header, payload, packet);
        default:
            fprintf(stderr, "Error: Invalid type.\n");
    }
    return -1;
}