/*
 * WirePulse Native Capture Engine Public C API
 *
 * Wraps libpcap (Linux AF_PACKET TPACKET_V3) and Npcap (Windows wpcap.dll)
 * with clean FFI-friendly structs, kernel BPF compilation, ring-buffer sizing,
 * live capture statistics, and PCAP file I/O.
 */
#ifndef WIREPULSE_CAPTURE_ENGINE_H
#define WIREPULSE_CAPTURE_ENGINE_H

#include "pcap_abi.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wp_iface_info {
    char name[256];
    char description[256];
    char ipv4[64];
    char ipv6[128];
    uint32_t flags;
} wp_iface_info_t;

typedef struct wp_packet_view {
    int64_t ts_sec;
    int32_t ts_usec;
    uint32_t caplen;
    uint32_t origlen;
    const uint8_t *data;
} wp_packet_view_t;

typedef struct wp_capture_stats {
    uint64_t packets_captured;
    uint64_t bytes_captured;
    uint32_t kernel_recv;
    uint32_t kernel_drop;
    uint32_t iface_drop;
    int32_t datalink;
} wp_capture_stats_t;

typedef struct wp_session wp_session_t;

/* Initialize runtime loader for libpcap / wpcap.dll. Returns 0 on success, -1 on error. */
WP_EXPORT int wp_init(char *errbuf, size_t errbuf_len);

/* Returns human-readable libpcap/Npcap version string. */
WP_EXPORT const char *wp_lib_version(void);

/* Enumerate available network interfaces. Returns count >= 0, or -1 on error. */
WP_EXPORT int wp_list_interfaces(wp_iface_info_t *out_list, int max_count,
                                 char *errbuf, size_t errbuf_len);

/* Validate a BPF capture filter expression without opening a live NIC.
 * Returns 0 if valid, -1 if invalid (errbuf populated). */
WP_EXPORT int wp_validate_bpf(const char *bpf_expr, int datalink,
                              char *errbuf, size_t errbuf_len);

/* Open a live capture session using pcap_create + TPACKET_V3 ring buffer sizing. */
WP_EXPORT wp_session_t *wp_open_live(const char *iface_name,
                                     int snaplen,
                                     int promisc,
                                     int timeout_ms,
                                     int buffer_size_mb,
                                     const char *bpf_filter,
                                     char *errbuf,
                                     size_t errbuf_len);

/* Open an offline .pcap file for reading. */
WP_EXPORT wp_session_t *wp_open_offline(const char *filepath,
                                        const char *bpf_filter,
                                        char *errbuf,
                                        size_t errbuf_len);

/* Read next packet.
 * Returns: 1 = packet available, 0 = timeout (no packet yet), -1 = error, -2 = EOF/break. */
WP_EXPORT int wp_next_packet(wp_session_t *sess,
                             wp_packet_view_t *out_pkt,
                             char *errbuf,
                             size_t errbuf_len);

/* Return link-layer header type (DLT_*). */
WP_EXPORT int wp_get_datalink(wp_session_t *sess);

/* Query live kernel & session capture statistics (pcap_stats). */
WP_EXPORT int wp_get_stats(wp_session_t *sess, wp_capture_stats_t *out_stats);

/* Signal capture loop to stop cleanly (thread-safe). */
WP_EXPORT void wp_break(wp_session_t *sess);

/* Close session and free resources. */
WP_EXPORT void wp_close(wp_session_t *sess);

/* Open a PCAP dump writer bound to a session (or dead handle). */
WP_EXPORT pcap_dumper_t *wp_dump_open(wp_session_t *sess, const char *filepath,
                                      char *errbuf, size_t errbuf_len);

/* Write a raw packet record into an open PCAP dumper. */
WP_EXPORT void wp_dump_packet(pcap_dumper_t *dumper,
                              int64_t ts_sec, int32_t ts_usec,
                              uint32_t caplen, uint32_t origlen,
                              const uint8_t *data);

/* Flush and close PCAP dumper. */
WP_EXPORT void wp_dump_close(pcap_dumper_t *dumper);

#ifdef __cplusplus
}
#endif

#endif /* WIREPULSE_CAPTURE_ENGINE_H */
