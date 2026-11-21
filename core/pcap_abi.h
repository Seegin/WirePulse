/*
 * WirePulse - Cross-Platform libpcap / Npcap ABI Definitions
 *
 * Allows zero-header-dependency compilation against runtime libpcap.so (Linux/macOS)
 * or Npcap wpcap.dll (Windows) via dlopen/LoadLibrary, while staying 100% ABI-compatible
 * with official libpcap 1.x and Npcap 1.x headers.
 */
#ifndef WIREPULSE_PCAP_ABI_H
#define WIREPULSE_PCAP_ABI_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #define WP_EXPORT __declspec(dllexport)
#else
  #include <sys/time.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <dlfcn.h>
  #define WP_EXPORT __attribute__((visibility("default")))
#endif

#define WP_PCAP_ERRBUF_SIZE 256
#define WP_PCAP_NETMASK_UNKNOWN 0xffffffffU

/* Interface flags matching libpcap PCAP_IF_* */
#define WP_PCAP_IF_LOOPBACK                          0x00000001U
#define WP_PCAP_IF_UP                                0x00000002U
#define WP_PCAP_IF_RUNNING                           0x00000004U
#define WP_PCAP_IF_WIRELESS                          0x00000008U
#define WP_PCAP_IF_CONNECTION_STATUS                 0x00000030U
#define WP_PCAP_IF_CONNECTION_STATUS_CONNECTED       0x00000010U
#define WP_PCAP_IF_CONNECTION_STATUS_DISCONNECTED    0x00000020U

/* Common Data Link Types (DLT_*) */
#define WP_DLT_NULL       0
#define WP_DLT_EN10MB     1
#define WP_DLT_RAW        12
#define WP_DLT_LOOP       108
#define WP_DLT_LINUX_SLL  113
#define WP_DLT_LINUX_SLL2 276

typedef struct pcap pcap_t;
typedef struct pcap_dumper pcap_dumper_t;

typedef struct wp_pcap_pkthdr {
    struct timeval ts;
    uint32_t caplen;
    uint32_t len;
} wp_pcap_pkthdr_t;

typedef struct wp_pcap_addr {
    struct wp_pcap_addr *next;
    struct sockaddr *addr;
    struct sockaddr *netmask;
    struct sockaddr *broadaddr;
    struct sockaddr *dstaddr;
} wp_pcap_addr_t;

typedef struct wp_pcap_if {
    struct wp_pcap_if *next;
    char *name;
    char *description;
    wp_pcap_addr_t *addresses;
    uint32_t flags;
} wp_pcap_if_t;

typedef struct wp_bpf_insn {
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
} wp_bpf_insn_t;

typedef struct wp_bpf_program {
    uint32_t bf_len;
    wp_bpf_insn_t *bf_insns;
} wp_bpf_program_t;

/* Extra uint32_t ps_capt safely accommodates Npcap's 16-byte pcap_stat on Win32 */
typedef struct wp_pcap_stat {
    uint32_t ps_recv;
    uint32_t ps_drop;
    uint32_t ps_ifdrop;
    uint32_t ps_capt;
} wp_pcap_stat_t;

#endif /* WIREPULSE_PCAP_ABI_H */
