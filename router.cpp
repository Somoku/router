#include <iostream>
#include <string>
#include <cstring>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include "router.h"

//TODO: check delete
//TODO: external port

RouterBase* create_router_object() {
    return new Router;
}

Dis_Next* Router::dv_search(uint32_t dst){
    if(this->DV_table.find(dst) != this->DV_table.end()){
        if(this->DV_table[dst].distance == -1)
            return nullptr;
        else
            return &(this->DV_table[dst]);
    }
    return nullptr;
}

void Router::create_packet(Header header, char* payload, char* packet){
    assert(HEADER_SIZE + header.length <= MAX_PACKET);

    memcpy(packet, &header, HEADER_SIZE);
    memcpy(packet + HEADER_SIZE, payload, header.length);
}

bool Router::is_external(uint32_t dst){
    if(dst & (this->external_mask) == this->external_addr)
        return true;
    return false;
}

uint32_t* Router::nat_in2pub(uint32_t in){
    if(this->NAT_table.find(in) != this->NAT_table.end())
        return &(this->NAT_table[in]);
    else{
        size_t pub_size = pub_use.size();
        for(int i = 0; i < pub_size; i++){
            int idx = (pub_pos + i) % pub_size;
            if(!pub_use[idx]){
                pub_use[idx] = true;
                uint32_t pub_ip = available_addr & idx;
                this->NAT_table.insert({in, pub_ip});
                pub_pos = (idx + 1) % pub_size;
                return &(this->NAT_table[in]);
            }
        }
    }
    return nullptr;
}

uint32_t* Router::nat_pub2in(uint32_t pub){
    if(!pub_use[pub & ~(this->available_mask)])
        return nullptr;
    for(auto& entry : this->NAT_table){
        if(entry.second == pub){
            uint32_t* ret = new uint32_t;
            *ret = entry.first;
            return ret;
        }
    }
    return nullptr;
}

int Router::data_handler(int in_port, Header header, char* payload, char* packet){
    uint32_t dst = ntohl(header.dst);
    uint32_t src = ntohl(header.src);
    // 如果src为外网ip，则要对dst进行地址转换
    if(is_external(src)){
        uint32_t* dst_in = nat_pub2in(dst);
        if(!dst_in){
            fprintf(stderr, "Error: Invalid public address.\n");
            return -1;
        }
        Header new_header{htonl(*dst_in), header.dst, header.type, header.length};
        create_packet(new_header, payload, packet);
        dst = *dst_in;
        free(dst_in);
    }
    
    // 如果dst为外网ip，并且存在连接该外网的端口（distance = 0），则要对src进行地址转换
    Dis_Next* dn = dv_search(dst);
    if(!dn)
        return 1;
    if(dn->distance == 0 && is_external(dst)){
        uint32_t* src_pub = nat_in2pub(src);
        // If no public address available, abort the packet.
        if(!src_pub)
            return -1;
        Header new_header{htonl(*src_pub), header.dst, header.type, header.length};
        create_packet(new_header, payload, packet);
        return dn->next;
    }
    else
        return dn->next;
}

int Router::dv_handler(int in_port, Header header, char* payload, char* packet){
    if(this->w[in_port] == -1)
        return -1;
    assert(header.length % sizeof(dv_entry) == 0);

    uint32_t entry_num = header.length / sizeof(dv_entry);
    dv_entry* dv_payload{new dv_entry[entry_num]};
    memcpy(dv_payload, payload, header.length);

    // Update DV_table.
    int broadcast = -1;
    for(int i = 0; i < entry_num; i++){
        uint32_t ip = dv_payload[i].ip;
        int32_t distance = dv_payload[i].distance;
        if(this->DV_table.find(ip) == this->DV_table.end()){
            if(distance != -1){
                this->DV_table[ip] = Dis_Next{distance + this->w[in_port], in_port};
                broadcast = 0;
            }
        }
        else{
            if(distance != -1){
                if(this->DV_table[ip].distance > distance + this->w[in_port]){
                    this->DV_table[ip] = Dis_Next{distance + this->w[in_port], in_port};
                    broadcast = 0;
                }
                else if(this->DV_table[ip].distance + this->w[in_port] < distance)
                    broadcast = 0;
            }
            else{
                if(this->DV_table[ip].next == in_port){
                    this->DV_table[ip].distance = -1;
                    broadcast = 0;
                }
                else if(this->DV_table[ip].distance != -1)
                    broadcast = 0;
            }
        }
    }
    delete[] dv_payload;
    return broadcast;
}

void Router::dv_packet(char* packet){
    size_t dv_num{DV_table.size()};
    int i{0};
    dv_entry* dv_payload{new dv_entry[dv_num]};
    
    for(auto& entry : this->DV_table){
        dv_payload[i].ip = entry.first;
        dv_payload[i].distance = entry.second.distance;
        i++;
    }
    assert(i == dv_num);
    Header header{0, 0, TYPE_DV, (uint16_t)(dv_num * sizeof(dv_entry))};
    create_packet(header, (char*)dv_payload, packet);
    delete[] dv_payload;
    return;
}

void Router::nat_release(uint32_t in_ip){
    if(this->NAT_table.find(in_ip) != this->NAT_table.end()){
        this->pub_use[this->NAT_table[in_ip] & ~(this->available_mask)] = false;
        this->NAT_table.erase(in_ip);
    }
    return;
}

int Router::port_change(int port, int value, char* packet){
    assert(value > 0 || value == -1);

    if(port > this->port_num || port <= 1){
        fprintf(stderr, "Error: Invalid port number.\n");
        return -1;
    }

    if(this->w[port] != value){
        int old_value = this->w[port];
        this->w[port] = value;
        // Update DV_table.
        for(auto& entry : DV_table){
            if(entry.second.next == port){
                // Delete an edge.
                if(value == -1)
                    entry.second.distance = -1;
                // Change edge weight.
                else if(old_value != -1)
                    entry.second.distance -= (old_value - value);
            }
        }
        dv_packet(packet);
        return 0;
    }
    return -1;
}

int Router::add_host(int port, uint32_t ip, char* packet){
    if(port > this->port_num){
        fprintf(stderr, "Error: Invalid port number.\n");
        return -1;
    }
    this->w[port] = 0;
    DV_table[ip] = Dis_Next{0, port};
    dv_packet(packet);
    return 0;
}

int Router::control_handler(int in_port, Header header, char* payload, char* packet){
    int ctrl_type = atoi(strtok(payload, " "));
    char* internal_ip, *token;
    uint32_t in_ip, ip;
    int port, value;

    switch(ctrl_type){
        case TRIGGER_DV_SEND: {
            dv_packet(packet);
            return 0;
        }
        break;
        case RELEASE_NAT_ITEM: {
            in_ip = 0;
            internal_ip = strtok(NULL, " ");
            if(!internal_ip){
                fprintf(stderr, "Error: Invalid internal_ip.\n");
                return -1;
            }
            if(inet_pton(AF_INET, internal_ip, &in_ip) != 1){
                fprintf(stderr, "Error: inet_pton().\n");
                return -1;
            }
            nat_release(ntohl(in_ip));
            return -1;
        }
        break;
        case PORT_VALUE_CHANGE: {
            // Get port.
            token = strtok(NULL, " ");
            if(!token){
                fprintf(stderr, "Error: Invalid command.\n");
                return -1;
            }
            port = atoi(token);
            assert(port > 1);
            
            // Get value.
            token = strtok(NULL, " ");
            if(!token){
                fprintf(stderr, "Error: Invalid command.\n");
                return -1;
            }
            value = atoi(token);
            assert(value == -1 || value > 0);

            // Execute command.
            return port_change(port, value, packet);
        }
        break;
        case ADD_HOST: {
            // Get port.
            token = strtok(NULL, " ");
            if(!token){
                fprintf(stderr, "Error: Invalid command.\n");
                return -1;
            }
            port = atoi(token);
            assert(port > 0);

            // Get ip.
            token = strtok(NULL, " ");
            if(!token){
                fprintf(stderr, "Error: Invalid command.\n");
                return -1;
            }
            if(inet_pton(AF_INET, internal_ip, &ip) != 1){
                fprintf(stderr, "Error: inet_pton().\n");
                return -1;
            }
            
            // Execute command.
            return add_host(port, ntohl(ip), packet);
        }
        break;
        default:
            fprintf(stderr, "Error: Invalid controller command.\n");
    }
    return -1;
}

void Router::router_init(int port_num, int external_port, char* external_addr, char* available_addr) {
    assert(port_num > 0);

    this->port_num = port_num;
    this->w.resize(port_num + 1, -1);
    this->w[1] = 0;
    this->external_port = external_port;
    this->pub_pos = 0;
    if(external_port == 0){
        this->external_addr = 0;
        this->available_addr = 0;
        this->available_mask_bit = 0;
        this->external_mask_bit = 0;
        this->external_mask = 0;
        this->available_mask = 0;
        return;
    }

    // Split CIDR external_addr into ip + mask
    char* token;
    uint32_t external_ip, available_ip;
    token = strtok(external_addr, "/");
    if(!token){
        fprintf(stderr, "Error: Invalid external_addr.\n");
        return;
    }
    if(inet_pton(AF_INET, token, &external_ip) != 1){
        fprintf(stderr, "Error: inet_pton().\n");
        return;
    }
    this->external_addr = ntohl(external_ip);
    token = strtok(NULL, "/");
    if(!token){
        fprintf(stderr, "Error: Invalid mask bit.\n");
        return;
    }
    this->external_mask_bit = atoi(token);
    this->external_mask = ((1 << (this->external_mask_bit)) - 1) << (32 - (this->external_mask_bit));
    this->external_addr &= this->external_mask;

    // Split CIDR available_addr into ip + mask
    token = strtok(available_addr, "/");
    if(!token){
        fprintf(stderr, "Error: Invalid available_addr.\n");
        return;
    }
    if(inet_pton(AF_INET, token, &available_ip) != 1){
        fprintf(stderr, "Error: inet_pton().\n");
        return;
    }
    this->available_addr = ntohl(available_ip);
    this->available_mask_bit = atoi(strtok(NULL, "/"));
    this->available_mask = ((1 << (this->available_mask_bit)) - 1) << (32 - (this->available_mask_bit));
    this->available_addr &= this->available_mask;
    this->pub_use.resize(1 << (32 - (this->available_mask_bit)), false);
    return;
}

int Router::router(int in_port, char* packet) {
    // Analyze received packet.
    Header header;
    int ret = -1;
    memcpy(&header, packet, HEADER_SIZE);
    char* payload{new char[header.length]};
    memcpy(payload, packet + HEADER_SIZE, header.length);

    // Handle different types.
    switch(header.type){
        case TYPE_DV:
            ret = dv_handler(in_port, header, payload, packet);
            break;
        case TYPE_DATA:
            ret = data_handler(in_port, header, payload, packet);
            break;
        case TYPE_CONTROL:
            ret = control_handler(in_port, header, payload, packet);
            break;
        default:
            fprintf(stderr, "Error: Invalid type.\n");
    }
    free(payload);
    return ret;
}