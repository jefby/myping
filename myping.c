/*
 *  myping.c
 *
 *  A toy implementation of the ping command in C.
 *
 *  References used:
 *    - https://stackoverflow.com/questions/8290046/icmp-sockets-linux
 *    - https://www.geeksforgeeks.org/ping-in-c/
 *    - https://www.cs.utah.edu/~swalton/listings/sockets/programs/part4/
        chap18/ping.c
 *    - https://beej.us/guide/bgnet/html
 *    - https://tools.ietf.org/html/rfc792 - Internet Control Message Protocol
 *    - https://tools.ietf.org/html/rfc3542 - Advanced Sockets Application
 *      Program Interface (API) for IPv6
 *    - https://github.com/octo/liboping/blob/master/src/liboping.c
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>

// Source: https://stackoverflow.com/a/12762101
#define MAX_ECHO_SEQUENCE (((unsigned long long) 1 << (sizeof(((struct icmphdr *) 0)->un.echo.sequence) * CHAR_BIT)) - 1)
#define RECV_DATA_MAX_SIZE (2048)
#define PING_DATA_SIZE (56)

static volatile sig_atomic_t g_interrupt = 0;
static unsigned int g_packets_sent = 0;
static unsigned int g_packets_received = 0;
static long g_min_rtt = LONG_MAX;
static long g_max_rtt = 0;
static unsigned long long g_rtt_sum = 0;
static uint8_t g_received_packet[(MAX_ECHO_SEQUENCE / CHAR_BIT) + 1] = {0};
static int ident = 0;// Will be set to current PID, used for ICMP identifier

char *strncpy_IFNAMSIZ(char *dst, const char *src) {
#ifndef IFNAMSIZ
    enum { IFNAMSIZ = 16 };
#endif
    return strncpy(dst, src, IFNAMSIZ);
}


int setsockopt_bindtodevice(int fd, const char *iface) {
    int r;
    struct ifreq ifr;
    strncpy_IFNAMSIZ(ifr.ifr_name, iface);
    /* NB: passing (iface, strlen(iface) + 1) does not work!
         * (maybe it works on _some_ kernels, but not on 2.6.26)
         * Actually, ifr_name is at offset 0, and in practice
         * just giving char[IFNAMSIZ] instead of struct ifreq works too.
         * But just in case it's not true on some obscure arch... */
    r = setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr));
    if (r)
        printf("can't bind to interface %s", iface);
    return r;
}


struct icmp_packet_t {
    struct icmphdr icmp_header;
    long sent_secs;
    long sent_nanos;
    uint8_t padding[PING_DATA_SIZE - 2 * sizeof(long)];
};

struct icmp6_packet_t {
    struct icmp6_hdr icmp_header;
    long sent_secs;
    long sent_nanos;
    uint8_t padding[PING_DATA_SIZE - 2 * sizeof(long)];
};

/*
 *  timespec_to_micros converts a struct timespec
 *  (seconds, nanoseconds) representation of time
 *  to a single long representing the number of
 *  microseconds since time 0.
 */

long long timespec_to_micros(struct timespec ts) {
    return (ts.tv_sec * 1000000) + (ts.tv_nsec / 1000);
} /* timespec_to_micros() */

/*
 *  sigint_handler sets the g_interrupt variable
 *  when the program is interrupted.
 */

void sigint_handler(int sig) {
    g_interrupt = 1;
} /* sigint_handler() */

/*
 *  set_packet_state sets the bit in the g_received_packet
 *  bitmap according to the given state (whether or not packet
 *  was received).
 */

void set_packet_state(int seq, bool state) {
    assert(seq < MAX_ECHO_SEQUENCE);
    int idx = seq / CHAR_BIT;
    int bit = seq % CHAR_BIT;

    if (state) {
        g_received_packet[idx] |= (1 << bit);
    } else {
        g_received_packet[idx] &= (uint8_t) (~(1 << bit));
    }
} /* set_packet_state() */

/*
 *  is_packet_received returns whether or not the packet
 *  was previously received.
 */

bool is_packet_received(int seq) {
    assert(seq < MAX_ECHO_SEQUENCE);
    int idx = seq / CHAR_BIT;
    int bit = seq % CHAR_BIT;

    return (g_received_packet[idx] & (1 << bit)) != 0;
} /* is_packet_received() */

/*
 *  gen_in_cksum generates an Internet checksum of
 *  a given number of bytes of data specified
 *  by RFC1071.
 *
 *  The checksum field must be cleared before
 *  computing it.
 */

uint16_t gen_in_cksum(void *buffer, int num_bytes) {
    uint16_t *data = (uint16_t *) buffer;
    uint32_t sum = 0;

    while (num_bytes > 1) {
        sum += *data;
        sum += (sum & (1 << 16)) ? 1 : 0;
        sum = (uint16_t) sum;
        data++;
        num_bytes -= sizeof(unsigned short);
    }

    if (num_bytes) {
        sum += *(unsigned char *) data;
        sum += (sum & (1 << 16)) ? 1 : 0;
        sum = (uint16_t) sum;
    }

    return ~((uint16_t) sum);
} /* gen_in_cksum() */

/*
 *  check_in_cksum checks the Internet checksum of
 *  a given number of bytes of data specified
 *  by RFC1071.
 */

bool check_in_cksum(void *buffer, int num_bytes) {
    uint16_t *data = (uint16_t *) buffer;
    uint32_t sum = 0;

    while (num_bytes > 1) {
        sum += *data;
        sum += (sum & (1 << 16)) ? 1 : 0;
        sum = (uint16_t) sum;
        data++;
        num_bytes -= sizeof(unsigned short);
    }

    if (num_bytes) {
        sum += *(unsigned char *) data;
        sum += (sum & (1 << 16)) ? 1 : 0;
        sum = (uint16_t) sum;
    }

    return (unsigned short) (sum + 1) == 0;
} /* check_in_cksum() */

/*
 *  get_in_addr returns a pointer to the sockaddr_in
 *  or the sockaddr_in6 depending on the sa_family
 *  value (AF_INET, AF_INET6) of the input sockaddr.
 *
 *  Source: Beej's Guide to Network Programming.
 */

void *get_in_addr(struct sockaddr *sockaddr) {
    if (sockaddr->sa_family == AF_INET) {
        return &(((struct sockaddr_in *) sockaddr)->sin_addr);
    }

    return &(((struct sockaddr_in6 *) sockaddr)->sin6_addr);
} /* get_in_addr() */

/*
 *  get_dest_addresses uses getaddrinfo to resolve the
 *  given host name.
 *  It returns get a linked list of struct addrinfo
 *  that will be passed into socket() and sendto().
 */

struct addrinfo *get_dest_addresses(char *destination) {
    struct addrinfo hints = {0};

    // To use SOCK_DGRAM, you must set net.ipv4.ping_group_range.
    hints.ai_socktype = SOCK_RAW;

    struct addrinfo *address = NULL;
    int status = getaddrinfo(destination, NULL, &hints, &address);
    if (status != 0) {
        fprintf(stderr, "getaddrinfo() failure: %s\n", gai_strerror(status));
        return NULL;
    }
    return address;
} /* get_dest_addresses() */

/*
 *  send_ping sends an ICMP packet to the given socket
 *  and destination address with the given sequence value.
 *
 *  The function returns the return value of sendto.
 */

int send_ping(int socket_fd, struct addrinfo *dest_addr, bool use_ipv6) {
    if (!use_ipv6) {
        struct icmp_packet_t icmp_packet = {{0}};

        icmp_packet.icmp_header.type = ICMP_ECHO;
        icmp_packet.icmp_header.code = 0;
        icmp_packet.icmp_header.un.echo.sequence = htons(g_packets_sent++);
        icmp_packet.icmp_header.un.echo.id = htons(ident);

        struct timespec sent_time = {0};
        if (clock_gettime(CLOCK_MONOTONIC, &sent_time) == -1) {
            perror("clock_gettime() failure");
        }
        icmp_packet.sent_secs = htonl((long) sent_time.tv_sec);
        icmp_packet.sent_nanos = htonl(sent_time.tv_nsec);

        set_packet_state(ntohs(icmp_packet.icmp_header.un.echo.sequence), false);

        icmp_packet.icmp_header.checksum = 0;
        uint16_t checksum = gen_in_cksum(&icmp_packet, sizeof(icmp_packet));
        icmp_packet.icmp_header.checksum = checksum;

        assert(check_in_cksum(&icmp_packet, sizeof(icmp_packet)));
        int bytes_sent = sendto(socket_fd, &icmp_packet, sizeof(icmp_packet), 0,
                                dest_addr->ai_addr, dest_addr->ai_addrlen);
        if ((bytes_sent == -1) || (bytes_sent != sizeof(icmp_packet))) {
            perror("sendto() failure");
        }

        return bytes_sent;
    } else {
        struct icmp6_packet_t icmp_packet = {{0}};

        icmp_packet.icmp_header.icmp6_type = ICMP6_ECHO_REQUEST;
        icmp_packet.icmp_header.icmp6_code = 0;
        icmp_packet.icmp_header.icmp6_seq = htons(g_packets_sent++);
        icmp_packet.icmp_header.icmp6_id = htons(ident);

        struct timespec sent_time = {0};
        if (clock_gettime(CLOCK_MONOTONIC, &sent_time) == -1) {
            perror("clock_gettime() failure");
        }
        icmp_packet.sent_secs = htonl((long) sent_time.tv_sec);
        icmp_packet.sent_nanos = htonl(sent_time.tv_nsec);

        set_packet_state(ntohs(icmp_packet.icmp_header.icmp6_seq), false);

        // Checksums are automatically computed for ICMPv6 packets
        icmp_packet.icmp_header.icmp6_cksum = 0;

        int bytes_sent = sendto(socket_fd, &icmp_packet, sizeof(icmp_packet), 0,
                                dest_addr->ai_addr, dest_addr->ai_addrlen);
        if ((bytes_sent == -1) || (bytes_sent != sizeof(icmp_packet))) {
            perror("sendto() failure");
        }

        return bytes_sent;
    }
} /* send_ping() */

/*
 *  recv_ping receives an ICMP packet from a given socket
 *  and prints out the packet's information.
 *
 *  The function returns the number of bytes received.
 */

int recv_ping(int socket_fd, bool use_ipv6) {
    // Setup for recvmsg (for parsing TTL)
    // Source: https://stackoverflow.com/a/49308499

    uint8_t data[RECV_DATA_MAX_SIZE];
    struct sockaddr_storage src_addr = {0};
    socklen_t src_addr_len = sizeof(src_addr);
    struct iovec iov[1] = {{data, sizeof(data)}};
    uint8_t ctrl_data_buffer[CMSG_SPACE(sizeof(uint8_t))];

    struct msghdr hdr = {
            .msg_name = &src_addr,
            .msg_namelen = src_addr_len,
            .msg_iov = iov,
            .msg_iovlen = 1,
            .msg_control = ctrl_data_buffer,
            .msg_controllen = sizeof(ctrl_data_buffer)};

    struct timespec recv_time = {0};

    int bytes_read = recvmsg(socket_fd, &hdr, 0);
    if (clock_gettime(CLOCK_MONOTONIC, &recv_time) == -1) {
        perror("clock_gettime() failure");
    }

    // Parse ancillary data for TTL
    int ttl = -1;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&hdr);
    for (; cmsg; cmsg = CMSG_NXTHDR(&hdr, cmsg)) {
        if ((cmsg->cmsg_level == IPPROTO_IP) &&
            (cmsg->cmsg_type == IP_TTL)) {
            memcpy(&ttl, CMSG_DATA(cmsg), sizeof(ttl));
        } else if ((cmsg->cmsg_level == IPPROTO_IPV6) &&
                   (cmsg->cmsg_type == IPV6_HOPLIMIT)) {
            // Why does the received hoplimit not change with
            // the set UNICAST_HOPS?
            memcpy(&ttl, CMSG_DATA(cmsg), sizeof(ttl));
        }
    }
    if (ttl == -1) {
        fprintf(stderr, "TTL not found in ancillary data\n");
    }

    char src_addr_name[INET6_ADDRSTRLEN];
    inet_ntop(src_addr.ss_family, get_in_addr((struct sockaddr *) &src_addr),
              src_addr_name, sizeof(src_addr_name));

    struct iphdr *ip_header = (struct iphdr *) data;

    // IPv6 headers are not included in the socket response,
    // but IPv4 headers are.
    if (!use_ipv6 && (ip_header->protocol != IPPROTO_ICMP)) {
        fprintf(stderr, "Protocol not ICMP\n");
        printf(" %d\n", ip_header->protocol);
        return bytes_read;
    }

    // ihl contains the number of 32-bit words in the header
    int ip_header_len = 0;
    if (!use_ipv6) {
        ip_header_len = ip_header->ihl * sizeof(uint32_t);
    }

    uint8_t header_type = 0;
    uint8_t header_code = 0;
    uint16_t header_seq = 0;
    uint16_t header_id = 0;
    long long sent_micros = 0;
    bool checksum_correct = false;

    if (!use_ipv6) {
        struct icmp_packet_t *recv_packet = (struct icmp_packet_t *) (data + ip_header_len);
        header_type = recv_packet->icmp_header.type;
        header_code = recv_packet->icmp_header.code;
        header_seq = ntohs(recv_packet->icmp_header.un.echo.sequence);
        header_id = ntohs(recv_packet->icmp_header.un.echo.id);

        struct timespec sent_time = {0};
        sent_time.tv_sec = (time_t) ntohl(recv_packet->sent_secs);
        sent_time.tv_nsec = ntohl(recv_packet->sent_nanos);
        sent_micros = timespec_to_micros(sent_time);

        checksum_correct = check_in_cksum(data, bytes_read);
    } else {
        struct icmp6_packet_t *recv_packet = (struct icmp6_packet_t *) (data + ip_header_len);
        header_type = recv_packet->icmp_header.icmp6_type;
        header_code = recv_packet->icmp_header.icmp6_code;
        header_seq = ntohs(recv_packet->icmp_header.icmp6_seq);
        header_id = ntohs(recv_packet->icmp_header.icmp6_id);

        struct timespec sent_time = {0};
        sent_time.tv_sec = (time_t) ntohl(recv_packet->sent_secs);
        sent_time.tv_nsec = ntohl(recv_packet->sent_nanos);
        sent_micros = timespec_to_micros(sent_time);

        // Verifying checksums for IPv6 ping packets are out of the scope of
        // this project.
        // To calculate the checksum, one must construct a pseudo-header,
        // which contains the source address. That means we have to select
        // the source address ourselves.
        // RFC 3542 describes the new IPV6_CHECKSUM socket option that will
        // automatically drop packets with an incorrect checksum, but it cannot
        // be set for ICMPv6 sockets.
        checksum_correct = true;
    }

    int icmp_len = bytes_read - ip_header_len;

    if (bytes_read == -1) {
        perror("recvfrom() failure");
    } else if (icmp_len < (use_ipv6 ? sizeof(struct icmp6_hdr) : sizeof(struct icmphdr))) {
        fprintf(stderr, "ICMP header malformed"
                        " (expected minimum size %lu, got %d)\n",
                sizeof(struct icmphdr), icmp_len);
    } else {
        // Identifier might be zero if header_code=0 (RFC 792 Page 14)
        if (((header_code != 0) && (header_id != ident)) ||
            ((header_code == 0) && (header_id != 0) && (header_id != ident))) {
            // Can safely ignore, will occur when multiple ping programs are
            // active at the same time
            // fprintf(stderr, "Echo ID incorrect"
            //                " (expected %d, got %d)\n", ident, header_id);
        } else if (header_type != (use_ipv6 ? ICMP6_ECHO_REPLY : ICMP_ECHOREPLY)) {
            if (header_type == (use_ipv6 ? ICMP6_TIME_EXCEEDED : ICMP_TIME_EXCEEDED)) {
                fprintf(stderr, "%d bytes from %s icmp_seq=%d Time to live exceeded\n",
                        bytes_read, src_addr_name,
                        header_seq);
            } else {
                // Can safely ignore (router advertisement, neighbor advertisement,
                // localhost loops back, etc.)
                //fprintf(stderr, "ICMP header type different than expected"
                //                " (expected %d, got %d)\n",
                //                (use_ipv6 ? ICMP6_ECHO_REPLY : ICMP_ECHOREPLY), header_type);
            }

            // Can also output other error messages here (ICMP_DEST_UNREACH, etc.)
        } else {
            bool is_duplicate = false;
            if (is_packet_received(header_seq)) {
                is_duplicate = true;
            } else {
                set_packet_state(header_seq, true);
                g_packets_received++;
            }

            long long recv_micros = timespec_to_micros(recv_time);
            long rtt = recv_micros - sent_micros;
            assert(rtt >= 0);

            if (!is_duplicate) {
                // duplicate packets should not affect min/max/avg rtt
                g_min_rtt = rtt < g_min_rtt ? rtt : g_min_rtt;
                g_max_rtt = rtt > g_max_rtt ? rtt : g_max_rtt;
                g_rtt_sum += rtt;
            }

            printf("%d bytes from %s "
                   "icmp_seq=%d ttl=%d time=%ld.%03ld ms loss=%.1f%%",
                   bytes_read,
                   src_addr_name,
                   header_seq,
                   ttl,
                   rtt / 1000, rtt % 1000,
                   (100.f * (g_packets_sent - g_packets_received)) / g_packets_sent);

            if (!checksum_correct) {
                printf(" - checksum error");
            }

            if (is_duplicate) {
                printf(" - duplicate packet");
            }

            printf("\n");
        }
    }
    return bytes_read;
} /* recv_ping() */

/*
 *  print_help prints instructions for program usage
 *  to stderr.
 */

void print_help() {
    fprintf(stderr, "usage: ping [-6] [-c count] [-t ttl] [-i interval] host\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "-6           Use IPv6 instead of IPv4\n");
    fprintf(stderr, "-c count     Stop after sending <count> packets\n");
    fprintf(stderr, "-t ttl       Set the IP Time to Live\n");
    fprintf(stderr, "-I interface Set the interface to bind \n");
    fprintf(stderr, "-i interval  Wait <interval> seconds between sending each packet\n");
} /* print_help() */

/*
 *  Main function for the ping program.
 */

int main(int argc, char **argv) {
    ident = getpid();

    signal(SIGINT, sigint_handler);

    bool opt_use_ipv6 = false;
    int opt_custom_ttl = -1;
    int opt_sleep_duration = 1e6;
    int opt_ping_count = -1;
    char *str_interface = NULL;

    char c = '\0';
    while ((c = getopt(argc, argv, "6t:c:i:I:")) != -1) {
        switch (c) {
            case '6':
                opt_use_ipv6 = true;
                break;
            case 't':
                opt_custom_ttl = atoi(optarg);
                break;
            case 'i':
                opt_sleep_duration = 1e6 * atof(optarg);
                break;
            case 'c':
                opt_ping_count = atoi(optarg);
                break;
            case '?':
                if ((optopt == 't') || (optopt == 'i') || (optopt == 'c')) {
                    fprintf(stderr, "Option -%c requires an argument.\n", optopt);
                    break;
                }
            case 'I':
                str_interface = strdup(optarg);
                break;

            default:
                print_help();
                return EXIT_FAILURE;
        }
    }

    if (optind != argc - 1) {
        print_help();
        return EXIT_FAILURE;
    }

    char *destination = argv[optind];

    struct addrinfo *address = get_dest_addresses(destination);
    if (!address) {
        return EXIT_FAILURE;
    }

    // Walk addrinfo linked list until one connects
    char ip_addr_str[INET6_ADDRSTRLEN];
    int socket_fd = -2;
    // addr_ptr will point to the target address
    struct addrinfo *addr_ptr = address;
    for (; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
        void *sin_addr = NULL;

        if (addr_ptr->ai_family == AF_INET) {
            if (opt_use_ipv6) {
                continue;
            }
            struct sockaddr_in *ipv4 = (struct sockaddr_in *) addr_ptr->ai_addr;
            sin_addr = &ipv4->sin_addr;
        } else {
            if (!opt_use_ipv6) {
                continue;
            }
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *) addr_ptr->ai_addr;
            sin_addr = &ipv6->sin6_addr;
        }

        inet_ntop(addr_ptr->ai_family, sin_addr, ip_addr_str, sizeof(ip_addr_str));

        socket_fd = socket(addr_ptr->ai_family, SOCK_RAW,
                           opt_use_ipv6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);
        if (socket_fd == -1) {
            continue;
        }

        printf("PING %s (%s): %d data bytes\n", destination, ip_addr_str,
               PING_DATA_SIZE);
        break;
    }

    if (socket_fd == -1) {
        if (!errno) {
            fprintf(stderr, "%s: No valid address found\n", destination);
        } else {
            perror("socket() failure");

            if (errno == EPERM) {
                fprintf(stderr, "Are you running as root?\n");
            }
        }
        return EXIT_FAILURE;
    }

    {
        // Set IP_RECVTTL to receive TTL information
        // You cannot receive IPv6 headers through recvfrom, so
        // we must use ancillary data.

        // https://www.ietf.org/rfc/rfc3542.txt
        int yes = 1;
        int status = 0;

        if (opt_use_ipv6) {
            status = setsockopt(socket_fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &yes,
                                sizeof(yes));
        } else {
            status = setsockopt(socket_fd, IPPROTO_IP, IP_RECVTTL, &yes,
                                sizeof(yes));
        }

        if (status) {
            perror("setsockopt() failure (TTL retrieval)");
        }
    }

    if (opt_custom_ttl != -1) {
        int status = 0;
        if (opt_use_ipv6) {
            status = setsockopt(socket_fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                                &opt_custom_ttl, sizeof(opt_custom_ttl));
        } else {
            status = setsockopt(socket_fd, IPPROTO_IP, IP_TTL,
                                &opt_custom_ttl, sizeof(opt_custom_ttl));
        }

        if (status) {
            perror("setsockopt() failure (specifying TTL)");
        }
    }

    if (str_interface)
        setsockopt_bindtodevice(socket_fd, str_interface);

    struct timeval timeout_tv;
    int ping_count = opt_ping_count;

    while (!g_interrupt && ping_count) {
        struct timespec start_time = {0};
        if (clock_gettime(CLOCK_MONOTONIC, &start_time) == -1) {
            perror("clock_gettime() failure");
        }

        // Send ping, then attempt to receive.
        // If timeout is reached, skip and try again.
        bool sent = false;
        while (!g_interrupt &&
               (!sent || (g_packets_received - g_packets_sent) != 0)) {
            timeout_tv.tv_sec = opt_sleep_duration / 1e6;
            timeout_tv.tv_usec = opt_sleep_duration % (int) 1e6;

            fd_set read_fds;
            fd_set write_fds;

            FD_ZERO(&read_fds);
            FD_ZERO(&write_fds);

            FD_SET(socket_fd, &read_fds);

            if (!sent) {
                FD_SET(socket_fd, &write_fds);
            }

            int status = select(socket_fd + 1, &read_fds, &write_fds, NULL, &timeout_tv);
            if (status == -1) {
                if (errno != EINTR) {
                    perror("select() failure");
                }
            } else if (status) {
                if (FD_ISSET(socket_fd, &write_fds)) {
                    if (send_ping(socket_fd, addr_ptr, opt_use_ipv6) == -1) {
                        return EXIT_FAILURE;
                    }

                    sent = true;
                } else {// read must now be available
                    assert(FD_ISSET(socket_fd, &read_fds));
                    if (recv_ping(socket_fd, opt_use_ipv6) == -1) {
                        return EXIT_FAILURE;
                    }
                }
            } else {
                break;
            }
        }

        if (ping_count != -1) {
            ping_count--;
        }

        // Sleep for any remaining time left in the specified sleep duration
        struct timespec end_time = {0};
        if (clock_gettime(CLOCK_MONOTONIC, &end_time) == -1) {
            perror("clock_gettime() failure");
        }

        long time_delta = timespec_to_micros(end_time) - timespec_to_micros(start_time);

        if (ping_count && !g_interrupt && (time_delta < opt_sleep_duration)) {
            usleep(opt_sleep_duration - time_delta);
        }
    }

    printf("\n--- %s ping statistics ---\n", destination);
    printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n",
           g_packets_sent, g_packets_received,
           100 * ((float) (g_packets_sent - g_packets_received)) / g_packets_sent);

    if (g_packets_received > 0) {
        unsigned long long g_avg_rtt = g_rtt_sum / g_packets_received;
        printf("round-trip min/avg/max = %ld.%03ld/%lld.%03lld/%ld.%03ld ms\n",
               g_min_rtt / 1000, g_min_rtt % 1000,
               g_avg_rtt / 1000, g_avg_rtt % 1000,
               g_max_rtt / 1000, g_max_rtt % 1000);
    }

    close(socket_fd);
    freeaddrinfo(address);
    address = NULL;

    return EXIT_SUCCESS;
} /* main() */
