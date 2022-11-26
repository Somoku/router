#include <iostream>
#include <string>
#include <cstring>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <assert.h>
#include "router.h"

//#define _DEBUG

//TODO: external port
//TODO: Clear all invalid entries in DV_table.

RouterBase* create_router_object() {
    return new Router;
}

Dis_Next* Router::dv_search(uint32_t dst){
#ifdef _DEBUG
    printf("dv_search(): dst = %x\n", dst);
#endif
    if(this->DV_table.find(dst) != this->DV_table.end()){
        if(this->DV_table[dst].distance == -1)
            return nullptr;
        else{
#ifdef _DEBUG
            printf("dv_search(): Distance = %d, Next = %d\n", this->DV_table[dst].distance, this->DV_table[dst].next);
#endif
            return &(this->DV_table[dst]);
        }
    }
    return nullptr;
}

void Router::create_packet(Header header, char* payload, char* packet){
    assert(HEADER_SIZE + header.length <= MAX_PACKET);

    memcpy(packet, &header, HEADER_SIZE);
    memcpy(packet + HEADER_SIZE, payload, header.length);
}

bool Router::is_external(uint32_t dst){
#ifdef _DEBUG
    printf("is_external(): dst = %x\n", dst);
    printf("is_external(): external_addr = %x\n", this->external_addr);
#endif
    if(this->external_port != 0 && ((dst & (this->external_mask)) == this->external_addr))
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
#ifdef _DEBUG
    printf("data_handler(): dst = %x\n", dst);
    printf("data_handler(): src = %x\n", src);
#endif
    // 如果src为外网ip，则要对dst进行地址转换
    if(is_external(src)){
#ifdef _DEBUG
        printf("data_handler(): external packet.\n");
#endif
        /*
        if(in_port != this->external_port)
            return -1;
        */

        uint32_t* dst_in = nat_pub2in(dst);
        if(!dst_in){
            fprintf(stderr, "Error: Invalid public address.\n");
            return -1;
        }
        Header new_header{htonl(*dst_in), header.dst, header.type, header.length};
        
        memset(packet, 0, HEADER_SIZE + header.length);
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

        Header new_header{htonl(*src_pub), htonl(dst), header.type, header.length};
        
        memset(packet, 0, HEADER_SIZE + header.length);
        create_packet(new_header, payload, packet);
        
        return dn->next;
    }
    else
        return dn->next;
}

int Router::dv_handler(int in_port, Header header, char* payload, char* packet){
    // Ignore packet from invalid edge.
    if(this->w[in_port] == -1)
        return -1;
    assert(header.length % sizeof(dv_entry) == 0);

    uint32_t entry_num = header.length / sizeof(dv_entry);
    // No update for empty packet.
    if(entry_num == 0)
       return -1;

    dv_entry* dv_payload{new dv_entry[entry_num]};
    memcpy(dv_payload, payload, header.length);
#ifdef _DEBUG
    printf("dv_handler(): entry_num = %u\n", entry_num);
    printf("dv_handler(): --- dv_payload begin ---\n");
    for(int i = 0; i < entry_num; i++){
        std::cout<<"IP = "<<std::hex<<dv_payload[i].ip<<std::dec<<", Distance = "<<dv_payload[i].distance<<std::endl;
    }
    printf("dv_handler(): --- dv_payload end ---\n");

    printf("dv_handler(): --- DV_table begin ---\n");
    for(auto& entry : this->DV_table){
        std::cout<<"IP = "<<std::hex<<entry.first<<std::dec<<", Distance = "<<entry.second.distance<<", Next = "<<entry.second.next<<std::endl;
    }
    printf("dv_handler(): --- DV_table end ---\n");
#endif
    // Update DV_table.
    int broadcast = -1; // 0 = propagate, -1 = abort, others = specific one
    std::map<uint32_t, Dis_Next> sub_dv_table; // Entries to be propagated.

    for(int i = 0; i < entry_num; i++){
        uint32_t ip = dv_payload[i].ip;
        int32_t distance = dv_payload[i].distance;

        // Add a new entry.
        if(this->DV_table.find(ip) == this->DV_table.end()){
            if(distance != -1){
                this->DV_table[ip] = Dis_Next{distance + this->w[in_port], in_port};
                if(sub_dv_table.find(ip) == sub_dv_table.end())
                    sub_dv_table.insert({ip, this->DV_table[ip]});
                else
                    sub_dv_table[ip] = this->DV_table[ip];
#ifdef _DEBUG
                printf("dv_handler(): Add a new entry.\n");
                std::cout<<"IP = "<<std::hex<<ip<<std::dec<<", Distance = "<<this->DV_table[ip].distance<<", Next = "<<this->DV_table[ip].next<<std::endl;
#endif
                broadcast = 0;
            }
        }
        // Update an entry.
        else{
            if(distance != -1){
                if(this->DV_table[ip].distance == -1 || this->DV_table[ip].distance > distance + this->w[in_port]){
#ifdef _DEBUG
                    std::cout<<"Old entry: IP = "<<std::hex<<ip<<std::dec<<", Distance = "<<this->DV_table[ip].distance<<", Next = "<<this->DV_table[ip].next<<std::endl;
#endif                    
                    this->DV_table[ip] = Dis_Next{distance + this->w[in_port], in_port};
                    if(sub_dv_table.find(ip) == sub_dv_table.end())
                        sub_dv_table.insert({ip, this->DV_table[ip]});
                    else
                        sub_dv_table[ip] = this->DV_table[ip];
#ifdef _DEBUG
                    printf("dv_handler(): Update an entry.\n");
                    std::cout<<"New entry: IP = "<<std::hex<<ip<<std::dec<<", Distance = "<<this->DV_table[ip].distance<<", Next = "<<this->DV_table[ip].next<<std::endl;
#endif                    
                    broadcast = 0;
                }
                else if(this->DV_table[ip].distance != -1 && this->DV_table[ip].distance + this->w[in_port] < distance)
                    broadcast = in_port;
            }
            else if(this->DV_table[ip].distance != -1){
                if(this->DV_table[ip].next == in_port)
                    this->DV_table[ip].distance = -1;

                if(sub_dv_table.find(ip) == sub_dv_table.end())
                    sub_dv_table.insert({ip, this->DV_table[ip]});
                else
                    sub_dv_table[ip] = this->DV_table[ip];
                broadcast = 0;
            }
        }
    }
#ifdef _DEBUG
    printf("dv_handler(): --- new DV_table begin ---\n");
    for(auto& entry : this->DV_table){
        std::cout<<"IP = "<<std::hex<<entry.first<<std::dec<<", Distance = "<<entry.second.distance<<", Next = "<<entry.second.next<<std::endl;
    }
    printf("dv_handler(): --- new DV_table end ---\n");
#endif
    // Send updated DV table.
    if(broadcast == 0 && sub_dv_table.size() != 0){
#ifdef _DEBUG
        printf("dv_handler(): propagating %d\n", broadcast);
#endif
        memset(packet, 0, HEADER_SIZE + header.length);
        dv_packet(packet, sub_dv_table);
    }
    else if(broadcast != 0 && this->DV_table.size() != 0){
#ifdef _DEBUG
        printf("dv_handler(): propagating %d\n", broadcast);
#endif
        memset(packet, 0, HEADER_SIZE + header.length);
        dv_packet(packet, this->DV_table);
    }

    delete[] dv_payload;
    return broadcast;
}

void Router::dv_packet(char* packet, std::map<uint32_t, Dis_Next> dv_table){
    size_t dv_num{dv_table.size()};
    int i{0};
    dv_entry* dv_payload{new dv_entry[dv_num]};
#ifdef _DEBUG
    printf("dv_packet(): dv_num = %ld\n", dv_num);
#endif
    for(auto& entry : dv_table){
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

int Router::port_change(int port, int value, Header header, char* packet){
    assert(value > 0 || value == -1);

    if(port > this->port_num || port <= 1){
        fprintf(stderr, "Error: Invalid port number.\n");
        return -1;
    }

#ifdef _DEBUG
    printf("port_change(): port = %d\n", port);
    printf("port_change(): old value = %d\n", this->w[port]);
    printf("port_change(): new value = %d\n", value);
#endif
    if(this->w[port] != value){
        int old_value = this->w[port];
        this->w[port] = value;

        int propagate = -1;
        std::map<uint32_t, Dis_Next> sub_dv_table;

        // Update DV_table.
        for(auto& entry : this->DV_table){
            if(entry.second.next == port){
                // Delete an edge.
                if(value == -1){
                    entry.second.distance = -1;

                    if(sub_dv_table.find(entry.first) == sub_dv_table.end())
                        sub_dv_table.insert({entry.first, this->DV_table[entry.first]});
                    else
                        sub_dv_table[entry.first] = this->DV_table[entry.first];
                    propagate = 0;
                }
                // Change edge weight.
                else if(old_value != -1){
                    entry.second.distance -= (old_value - value);

                    if(sub_dv_table.find(entry.first) == sub_dv_table.end())
                        sub_dv_table.insert({entry.first, this->DV_table[entry.first]});
                    else
                        sub_dv_table[entry.first] = this->DV_table[entry.first];
                    propagate = 0;
                }
            }
        }
#ifdef _DEBUG
        printf("port_change(): --- DV_table begin ---\n");
        for(auto& entry : this->DV_table)
            std::cout<<"IP = "<< std::hex <<entry.first<< std::dec <<", "<<"Distance = "<<entry.second.distance <<", Next = "<<entry.second.next<<std::endl;
        printf("port_change(): --- DV_table end ---\n");
#endif
        if(propagate == 0){
            memset(packet, 0, HEADER_SIZE + header.length);
            dv_packet(packet, sub_dv_table);
        }
        
        // Erase all invalid edges.
        for(auto& entry: this->DV_table){
            if(entry.second.distance == -1)
                this->DV_table.erase(entry.first);
        }
#ifdef _DEBUG
        printf("port_change(): --- erased DV_table begin ---\n");
        for(auto& entry : this->DV_table)
            std::cout<<"IP = "<<std::hex<<entry.first<<std::dec<<", "<<"Distance = "<<entry.second.distance <<", Next = "<<entry.second.next<<std::endl;
        printf("port_change(): --- erased DV_table end ---\n");
#endif
        return propagate;
    }
    return -1;
}

int Router::add_host(int port, uint32_t ip, Header header, char* packet){
    std::map<uint32_t, Dis_Next> sub_dv_table;
    if(port > this->port_num){
        fprintf(stderr, "Error: Invalid port number.\n");
        return -1;
    }
#ifdef _DEBUG
    printf("add_host(): port = %d\n", port);
    printf("add_host(): ip = %x\n", ip);
#endif
    this->w[port] = 0;
    this->DV_table[ip] = Dis_Next{0, port};

    if(sub_dv_table.find(ip) == sub_dv_table.end())
        sub_dv_table.insert({ip, this->DV_table[ip]});
    else
        sub_dv_table[ip] = this->DV_table[ip];
#ifdef _DEBUG
    printf("dv_handler(): --- DV_table begin ---\n");
    for(auto& entry : this->DV_table){
        std::cout<<"IP = "<<std::hex<<entry.first<<std::dec<<", Distance = "<<entry.second.distance<<", Next = "<<entry.second.next<<std::endl;
    }
    printf("dv_handler(): --- DV_table end ---\n");
#endif
    memset(packet, 0, HEADER_SIZE + header.length);
    dv_packet(packet, sub_dv_table);
    return 0;
}

int Router::control_handler(int in_port, Header header, char* payload, char* packet){
    int ctrl_type;
    char* internal_ip, *token;
    uint32_t in_ip, ip;
    int port, value;

    // Get control command type.
    token = strtok(payload, " ");
    if(!token){
        fprintf(stderr, "Error: Invalid payload.\n");
        return -1;
    }
    ctrl_type = atoi(token);
#ifdef _DEBUG
    printf("control_handler(): ctrl_type = %d\n", ctrl_type);
#endif
    // Execute different types of commands.
    switch(ctrl_type){
        case TRIGGER_DV_SEND: {
#ifdef _DEBUG
            printf("control_handler(): TRIGGER_DV_SEND.\n");
#endif
            memset(packet, 0, HEADER_SIZE + header.length);
            dv_packet(packet, this->DV_table);
            return 0;
        }
        break;
        case RELEASE_NAT_ITEM: {
#ifdef _DEBUG
            printf("control_handler(): RELEASE_NAT_ITEM.\n");
#endif
            in_ip = 0;
            internal_ip = strtok(NULL, " ");
            if(!internal_ip){
                fprintf(stderr, "Error: Invalid internal_ip.\n");
                return -1;
            }
#ifdef _DEBUG      
            printf("RELEASE_NAT_ITEM: internal_ip = %s\n", internal_ip);
#endif
            
            if(inet_pton(AF_INET, internal_ip, &in_ip) != 1){
                fprintf(stderr, "Error: inet_pton().\n");
                return -1;
            }
#ifdef _DEBUG
            printf("RELEASE_NAT_ITEM: in_ip = %x\n", in_ip);
#endif      
            nat_release(ntohl(in_ip));
            return -1;
        }
        break;
        case PORT_VALUE_CHANGE: {
#ifdef _DEBUG
            printf("control_handler(): PORT_VALUE_CHANGE.\n");
#endif
            // Get port.
            token = strtok(NULL, " ");
            if(!token){
                fprintf(stderr, "Error: Invalid command.\n");
                return -1;
            }
            port = atoi(token);
            assert(port > 1);
#ifdef _DEBUG
            printf("PORT_VALUE_CHANGE: port = %d\n", port);
#endif
            // Get value.
            token = strtok(NULL, " ");
            if(!token){
                fprintf(stderr, "Error: Invalid command.\n");
                return -1;
            }
            value = atoi(token);
            assert(value == -1 || value > 0);
#ifdef _DEBUG
            printf("PORT_VALUE_CHANGE: value = %d\n", value);
#endif
            // Execute command.
            return port_change(port, value, header, packet);
        }
        break;
        case ADD_HOST: {
#ifdef _DEBUG
            printf("control_handler(): ADD_HOST.\n");
#endif
            // Get port.
            token = strtok(NULL, " ");
            if(!token){
                fprintf(stderr, "Error: Invalid command.\n");
                return -1;
            }
            port = atoi(token);
            assert(port > 0);
#ifdef _DEBUG
            printf("ADD_HOST: port = %d\n", port);
#endif
            // Get ip.
            token = strtok(NULL, " ");
            if(!token){
                fprintf(stderr, "Error: Invalid command.\n");
                return -1;
            }
#ifdef _DEBUG
            printf("ADD_HOST: ip_str = %s\n", token);
#endif
            if(inet_pton(AF_INET, token, &ip) != 1){
                fprintf(stderr, "Error: inet_pton().\n");
                return -1;
            }
#ifdef _DEBUG
            printf("ADD_HOST: ip = %x\n", ntohl(ip));
#endif
            // Execute command.
            return add_host(port, ntohl(ip), header, packet);
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
#ifdef _DEBUG
    printf("[Router] port_num = %d\n", this->port_num);
    printf("[Router] external_port = %d\n", this->external_port);
    printf("[Router] external_addr = %x\n", this->external_addr);
    printf("[Router] external_mask_bit = %u\n", this->external_mask_bit);
    printf("[Router] external_mask = %x\n", this->external_mask);
    printf("[Router] available_addr = %x\n", this->available_addr);
    printf("[Router] available_mask_bit = %u\n", this->available_mask_bit);
    printf("[Router] available_mask = %x\n", this->available_mask);
    printf("[Router] pub_pos = %d\n", this->pub_pos);
    std::cout<<"[Router] DV_table size = " << (this->DV_table).size() <<std::endl;
    std::cout<<"[Router] w size = " << (this->w).size() <<std::endl;
    std::cout<<"[Router] NAT_table size = " << (this->NAT_table).size() <<std::endl;
    std::cout<<"[Router] pub_use size = " << (this->pub_use).size() << std::endl;
#endif
    return;
}

int Router::router(int in_port, char* packet) {
#ifdef _DEBUG
    printf("router(): in_port = %d\n", in_port);
#endif
    // Analyze received packet.
    Header header;
    int ret = -1;
    memcpy(&header, packet, HEADER_SIZE);
    char* payload{new char[header.length]};
    memcpy(payload, packet + HEADER_SIZE, header.length);
#ifdef _DEBUG
    std::cout<<"router(): header.dst = " << std::hex << ntohl(header.dst) << std::dec <<std::endl;
    std::cout<<"router(): header.src = " << std::hex << ntohl(header.src) << std::dec << std::endl;
    std::cout<<"router(): header.length = " << header.length << std::endl;
    std::cout<<"router(): header.type = " << header.type << std::endl;
    printf("router(): payload = %s\n", payload);
#endif

    // Handle different types.
    switch(header.type){
        case TYPE_DV:
#ifdef _DEBUG
            printf("router(): received TYPE_DV packet.\n");
#endif
            ret = dv_handler(in_port, header, payload, packet);
            break;
        case TYPE_DATA:
#ifdef _DEBUG
            printf("router(): received TYPE_DATA packet.\n");
#endif
            ret = data_handler(in_port, header, payload, packet);
            break;
        case TYPE_CONTROL:
#ifdef _DEBUG
            printf("router(): received TYPE_CONTROL packet.\n");
#endif
            ret = control_handler(in_port, header, payload, packet);
            break;
        default:
            fprintf(stderr, "Error: Invalid type.\n");
    }
    free(payload);
    return ret;
}