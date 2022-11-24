#include "router_prototype.h"
#include <stdint.h>

#define HEADER_SIZE 12
#define MAX_PACKET 16384
#define TYPE_DV 0x00
#define TYPE_DATA 0x01
#define TYPE_CONTROL 0x02

class Router : public RouterBase {
private:
    int port_num; /* Port number of router.
                   1 is preserved for controller */
    int external_port; /* External network port number.
                        0 = No connection to external network */
    char* external_addr; /* Address range of external network.
                              0 if external_port == 0 */
    uint32_t external_mask; // Mask number of external_addr
    char* available_addr; /* Available address range of public network.
                           Null if external_port == 0 */
    uint32_t available_mask; // Mask number of available_addr
    
public:
    void router_init(int port_num, int external_port, char* external_addr, char* available_addr);
    int router(int in_port, char* packet);
    int data_handler(int in_port, Header header, char* payload, char* packet);
    int dv_handler(int in_port, Header header, char* payload, char* packet);
    int control_handler(int in_port, Header header, char* payload, char* packet);
};

struct Header {
    uint32_t src;
    uint32_t dst;
    uint8_t type;
    uint16_t length;
};