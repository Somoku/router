#include "router_prototype.h"

class Router : public RouterBase {
public:
    void router_init(int port_num, int external_port, char* external_addr, char* available_addr);
    int router(int in_port, char* packet);
};
