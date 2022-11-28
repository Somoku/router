#include "router_prototype.h"
#include <stdint.h>
#include <map>
#include <vector>

#define HEADER_SIZE 12
#define MAX_PACKET 16384

#define TYPE_DV 0x00
#define TYPE_DATA 0x01
#define TYPE_CONTROL 0x02

#define TRIGGER_DV_SEND 0x0
#define RELEASE_NAT_ITEM 0x1
#define PORT_VALUE_CHANGE 0x2
#define ADD_HOST 0x3

struct Header {
    uint32_t src;
    uint32_t dst;
    uint8_t type;
    uint16_t length;
};

struct Dis_Next {
    int32_t distance;
    int32_t next;
};

struct dv_entry {
    uint32_t ip;
    int32_t distance;
    int32_t next;
};

class Router : public RouterBase {
private:
    int port_num; /* Port number of router.
                   1 is preserved for controller */
    int external_port; /* External network port number.
                        0 = No connection to external network */
    uint32_t external_addr; /* Address range of external network.
                              0 if external_port == 0 */
    uint32_t external_mask_bit; // Mask number of external_addr
    uint32_t external_mask; // Mask of external_addr
    uint32_t available_addr; /* Available address range of public network.
                           Null if external_port == 0 */
    uint32_t available_mask_bit; // Mask number of available_addr
    uint32_t available_mask; // Mask of available_addr
    std::map<uint32_t, Dis_Next> DV_table; // DV table mapping from IP to distance.
    std::map<uint32_t, Dis_Next> send_dv_table; // DV table to be sent.
    std::vector<int> w; // Weight array of every port.
    std::map<uint32_t, uint32_t> NAT_table; // NAT table mapping from internal address to public address.
    std::vector<bool> pub_use; // Record allocation of public address.
    int pub_pos; // Position of current unallocated public address.
    bool update; // Whether DV table is updated.
    int way_num; // Number of ways to send packet.

public:
    void router_init(int port_num, int external_port, char* external_addr, char* available_addr);
    int router(int in_port, char* packet);
    int data_handler(int in_port, Header header, char* payload, char* packet);
    int dv_handler(int in_port, Header header, char* payload, char* packet);
    int control_handler(int in_port, Header header, char* payload, char* packet);
    Dis_Next* dv_search(uint32_t dst);
    uint32_t* nat_in2pub(uint32_t in);
    uint32_t* nat_pub2in(uint32_t pub);
    bool is_external(uint32_t dst);
    void create_packet(Header header, char* payload, char* packet);
    void dv_packet(char* packet, std::map<uint32_t, Dis_Next> dv_table);
    void nat_release(uint32_t in_ip);
    int port_change(int port, int value, Header header, char* packet);
    int add_host(int port, uint32_t ip, Header header, char* packet);
};