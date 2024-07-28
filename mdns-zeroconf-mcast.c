#define _GNU_SOURCE

#include <arpa/inet.h>
#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-client/publish.h>
#include <avahi-common/error.h>
#include <avahi-common/simple-watch.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

static const char * const veto_name = "veto";

static char* app_name = NULL;
static char* ptr_name;
static char* ptr_rdata;
static size_t ptr_rdata_sz;
static uint32_t ttl = 60 * 60;
static uint32_t intf_scope_id;
static AvahiPublishFlags publish_flags =
    AVAHI_PUBLISH_UNIQUE | AVAHI_PUBLISH_USE_MULTICAST;
static AvahiSimplePoll* simple_poll = NULL;
static AvahiRecordBrowser* browser = NULL;

static uint8_t find_ipv6_ll_addr(const char* intf,
                                 struct in6_addr* addr,
                                 uint32_t* scope_id) {
    struct ifaddrs* ifaddr;
    struct ifaddrs* ifa;
    struct sockaddr_in6* addr_ptr;
    uint8_t ret = 0;

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if ((strcmp(intf, ifa->ifa_name) != 0) || (ifa->ifa_addr == NULL) ||
            (ifa->ifa_addr->sa_family != AF_INET6))
            continue;

        addr_ptr = (struct sockaddr_in6*)ifa->ifa_addr;

        if ((addr_ptr->sin6_addr.s6_addr32[0] == htonl(0xfe800000)) &&
            (addr_ptr->sin6_addr.s6_addr32[1] == 0)) {
            *addr = addr_ptr->sin6_addr;
            *scope_id = addr_ptr->sin6_scope_id;
            ret = 1;
            break;
        }
    }

    freeifaddrs(ifaddr);

    return ret;
}

static void print_help(void) {
    printf(
        // clang-format off
        "mdns-zeroconf-mcast [OPTION]\n"
        "Options:\n"
        "  -i --intf=interface The network interface to use\n"
        "  -n --name=name      The name of the application\n"
        "                      (use \"veto\" to publish a veto)\n"
        "  -g --groupid=id     32-bit group ID in hexadecimal\n"
        "  -t --ttl=ttl        Record TTL in seconds (optional, defaults to 1 hour)\n"
        "  -h --help           Prints help message\n"
        // clang-format on
    );
}

static void print_timed_message(const char* msg) {
    time_t time_val = time(NULL);
    struct tm* time_tm = localtime(&time_val);

    printf("[%u-%02u-%02u %02u:%02u:%02u] %s\n",
           time_tm->tm_year + 1900,
           time_tm->tm_mon + 1,
           time_tm->tm_mday,
           time_tm->tm_hour,
           time_tm->tm_min,
           time_tm->tm_sec,
           msg);
}

static void record_browser_callback(AvahiRecordBrowser* b,
                                    AvahiIfIndex interface,
                                    AvahiProtocol protocol,
                                    AvahiBrowserEvent event,
                                    const char* name,
                                    uint16_t clazz,
                                    uint16_t type,
                                    const void* rdata,
                                    size_t size,
                                    AvahiLookupResultFlags flags,
                                    void* userdata) {}

static void entry_group_callback(AvahiEntryGroup* g,
                                 AvahiEntryGroupState state,
                                 void* userdata) {
    switch (state) {
        case AVAHI_ENTRY_GROUP_ESTABLISHED:
            print_timed_message("Registration successful");

            // The network is probed for existing records when first
            // publishing, but will not detect duplicates caused by a
            // network partition without a continuous query. If found,
            // then AVAHI_ENTRY_GROUP_COLLISION will be sent to the
            // entry group callback.
            browser = avahi_record_browser_new((AvahiClient*)userdata,
                                               intf_scope_id,
                                               AVAHI_PROTO_UNSPEC,
                                               ptr_name,
                                               AVAHI_DNS_CLASS_IN,
                                               AVAHI_DNS_TYPE_PTR,
                                               AVAHI_LOOKUP_USE_MULTICAST,
                                               record_browser_callback,
                                               NULL);
            break;

        case AVAHI_ENTRY_GROUP_COLLISION:
            print_timed_message("Encountered collision, exiting");
            avahi_simple_poll_quit(simple_poll);
            break;

        case AVAHI_ENTRY_GROUP_FAILURE:
            print_timed_message("Encountered registration failure, exiting");
            exit(EXIT_FAILURE);
    }
}

static void register_record(AvahiClient* c) {
    AvahiEntryGroup* group;
    int error;

    group = avahi_entry_group_new(c, entry_group_callback, c);

    error = avahi_entry_group_add_record(group,
                                         intf_scope_id,
                                         AVAHI_PROTO_UNSPEC,
                                         publish_flags,
                                         ptr_name,
                                         AVAHI_DNS_CLASS_IN,
                                         AVAHI_DNS_TYPE_PTR,
                                         ttl,
                                         ptr_rdata,
                                         ptr_rdata_sz);
    if (error) {
        printf("Error adding record: %s\n", avahi_strerror(error));
        exit(EXIT_FAILURE);
    }

    avahi_entry_group_commit(group);
}

static void client_callback(AvahiClient* c,
                            AvahiClientState state,
                            void* userdata) {
    const char* host_name;
    const char* domain_name;

    switch (state) {
        case AVAHI_CLIENT_S_RUNNING:
            host_name = avahi_client_get_host_name(c);
            domain_name = avahi_client_get_domain_name(c);

            if (strcmp(veto_name, app_name) == 0) {
                asprintf(&ptr_rdata,
                         "%c%s",
                         (char)strlen(app_name),
                         app_name);
            } else {
                asprintf(&ptr_rdata,
                        "%c%s%c%s%c%s",
                        (char)strlen(app_name),
                        app_name,
                        (char)strlen(host_name),
                        host_name,
                        (char)strlen(domain_name),
                        domain_name);
            }

            ptr_rdata_sz = strlen(ptr_rdata) + 1;  // Include null terminator

            register_record(c);

            break;

        case AVAHI_CLIENT_FAILURE:
            printf("Client failure: %s\n",
                   avahi_strerror(avahi_client_errno(c)));
            exit(EXIT_FAILURE);
    }
}

int main(int argc, char* argv[]) {
    const struct option long_options[] = {
        {"intf", required_argument, 0, 'i'},
        {"name", required_argument, 0, 'n'},
        {"groupid", required_argument, 0, 'g'},
        {"ttl", required_argument, 0, 't'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};

    int opt;
    char* intf = NULL;
    uint32_t group_id = 0;
    uint8_t group_id_set = 0;
    char addr_buf[INET6_ADDRSTRLEN];
    struct in6_addr addr_intf;
    struct in6_addr addr_mcast;
    const AvahiPoll* poll_api;
    AvahiClient* avahi;
    int error;

    while ((opt = getopt_long(argc, argv, "i:n:g:t:h", long_options, NULL)) !=
           -1) {
        switch (opt) {
            case 'i':
                intf = optarg;
                break;

            case 'n':
                app_name = optarg;
                break;

            case 'g':
                if (sscanf(optarg, "%x", &group_id) == 1) group_id_set = 1;
                break;

            case 't':
                if (sscanf(optarg, "%" PRIu32, &ttl) != 1) {
                    printf("TTL value is not correctly formatted: '%s'\n",
                           optarg);
                    exit(EXIT_FAILURE);
                }
                break;

            case 'h':
                print_help();
                exit(EXIT_SUCCESS);

            default:
                print_help();
                exit(EXIT_FAILURE);
        }
    }

    if (!intf || !app_name || !group_id_set) {
        print_help();
        exit(EXIT_FAILURE);
    }

    if (strcmp(veto_name, app_name) == 0)
        publish_flags |= AVAHI_PUBLISH_NO_PROBE;

    if (!find_ipv6_ll_addr(intf, &addr_intf, &intf_scope_id)) {
        printf(
            "Could not locate IPv6 link local address for interface "
            "'%s'\n",
            intf);
        exit(EXIT_FAILURE);
    }

    addr_mcast.s6_addr[0] = 0xff;
    addr_mcast.s6_addr[1] = 0x32;
    addr_mcast.s6_addr[2] = 0x00;
    addr_mcast.s6_addr[3] = 0xff;
    addr_mcast.s6_addr32[1] = addr_intf.s6_addr32[2];
    addr_mcast.s6_addr32[2] = addr_intf.s6_addr32[3];
    addr_mcast.s6_addr32[3] = htonl(group_id);

    inet_ntop(AF_INET6, &addr_intf, addr_buf, sizeof(addr_buf));
    printf("Found IPv6 link local address %s\n", addr_buf);

    inet_ntop(AF_INET6, &addr_mcast, addr_buf, sizeof(addr_buf));
    printf("Using IPv6 multicast address %s\n", addr_buf);

    printf("=> Ethernet multicast address 33:33:%02x:%02x:%02x:%02x\n",
           addr_mcast.s6_addr[12],
           addr_mcast.s6_addr[13],
           addr_mcast.s6_addr[14],
           addr_mcast.s6_addr[15]);

    asprintf(&ptr_name,
             "%x.%x.%x.%x.%x.%x.%x.%x.3.3.3.3.eth-addr.arpa",
             addr_mcast.s6_addr[15] & 0xf,
             addr_mcast.s6_addr[15] >> 4,
             addr_mcast.s6_addr[14] & 0xf,
             addr_mcast.s6_addr[14] >> 4,
             addr_mcast.s6_addr[13] & 0xf,
             addr_mcast.s6_addr[13] >> 4,
             addr_mcast.s6_addr[12] & 0xf,
             addr_mcast.s6_addr[12] >> 4);

    simple_poll = avahi_simple_poll_new();
    poll_api = avahi_simple_poll_get(simple_poll);

    avahi = avahi_client_new(poll_api, 0, client_callback, NULL, &error);
    if (!avahi) {
        printf("Failed to create client: %s\n", avahi_strerror(error));
        exit(EXIT_FAILURE);
    }

    avahi_simple_poll_loop(simple_poll);

    exit(EXIT_SUCCESS);
}