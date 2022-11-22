#include "router.h"

RouterBase* create_router_object() {
    return new Router;
}

void Router::router_init(int port_num, int external_port, char* external_addr, char* available_addr) {
    return;
}

int Router::router(int in_port, char* packet) {
    return 1;
}