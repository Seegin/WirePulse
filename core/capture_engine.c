/*
 * WirePulse - Native C11 High-Performance Packet Capture Engine
 *
 * Directly drives libpcap (Linux AF_PACKET + TPACKET_V3 ring buffer + kernel BPF)
 * and Npcap (Windows wpcap.dll) through a dynamic runtime loader.
 */
#include "capture_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Function pointer table for dynamic libpcap / Npcap resolution */
typedef const char *(*fn_pcap_lib_version)(void);
typedef int (*fn_pcap_findalldevs)(wp_pcap_if_t **, char *);
typedef void (*fn_pcap_freealldevs)(wp_pcap_if_t *);
typedef pcap_t *(*fn_pcap_create)(const char *, char *);
typedef int (*fn_pcap_set_snaplen)(pcap_t *, int);
typedef int (*fn_pcap_set_promisc)(pcap_t *, int);
typedef int (*fn_pcap_set_timeout)(pcap_t *, int);
typedef int (*fn_pcap_set_buffer_size)(pcap_t *, int);
typedef int (*fn_pcap_set_immediate_mode)(pcap_t *, int);
typedef int (*fn_pcap_activate)(pcap_t *);
typedef pcap_t *(*fn_pcap_open_offline)(const char *, char *);
typedef pcap_t *(*fn_pcap_open_dead)(int, int);
typedef int (*fn_pcap_compile)(pcap_t *, wp_bpf_program_t *, const char *, int, uint32_t);
typedef int (*fn_pcap_setfilter)(pcap_t *, wp_bpf_program_t *);
typedef void (*fn_pcap_freecode)(wp_bpf_program_t *);
typedef int (*fn_pcap_next_ex)(pcap_t *, wp_pcap_pkthdr_t **, const uint8_t **);
typedef int (*fn_pcap_datalink)(pcap_t *);
typedef int (*fn_pcap_stats)(pcap_t *, wp_pcap_stat_t *);
typedef void (*fn_pcap_breakloop)(pcap_t *);
typedef void (*fn_pcap_close)(pcap_t *);
typedef char *(*fn_pcap_geterr)(pcap_t *);
typedef const char *(*fn_pcap_statustostr)(int);
typedef pcap_dumper_t *(*fn_pcap_dump_open)(pcap_t *, const char *);
typedef void (*fn_pcap_dump)(uint8_t *, const wp_pcap_pkthdr_t *, const uint8_t *);
typedef int (*fn_pcap_dump_flush)(pcap_dumper_t *);
typedef void (*fn_pcap_dump_close)(pcap_dumper_t *);

typedef struct wp_pcap_api {
    int loaded;
#ifdef _WIN32
    HMODULE handle;
#else
    void *handle;
#endif
    fn_pcap_lib_version lib_version;
    fn_pcap_findalldevs findalldevs;
    fn_pcap_freealldevs freealldevs;
    fn_pcap_create create;
    fn_pcap_set_snaplen set_snaplen;
    fn_pcap_set_promisc set_promisc;
    fn_pcap_set_timeout set_timeout;
    fn_pcap_set_buffer_size set_buffer_size;
    fn_pcap_set_immediate_mode set_immediate_mode;
    fn_pcap_activate activate;
    fn_pcap_open_offline open_offline;
    fn_pcap_open_dead open_dead;
    fn_pcap_compile compile;
    fn_pcap_setfilter setfilter;
    fn_pcap_freecode freecode;
    fn_pcap_next_ex next_ex;
    fn_pcap_datalink datalink;
    fn_pcap_stats stats;
    fn_pcap_breakloop breakloop;
    fn_pcap_close close;
    fn_pcap_geterr geterr;
    fn_pcap_statustostr statustostr;
    fn_pcap_dump_open dump_open;
    fn_pcap_dump dump;
    fn_pcap_dump_flush dump_flush;
    fn_pcap_dump_close dump_close;
} wp_pcap_api_t;

static wp_pcap_api_t g_api = {0};

struct wp_session {
    pcap_t *handle;
    int is_live;
    int datalink;
    uint64_t packets_captured;
    uint64_t bytes_captured;
};

static void set_err(char *errbuf, size_t len, const char *msg) {
    if (!errbuf || len == 0) return;
    if (!msg) msg = "Unknown error";
    snprintf(errbuf, len, "%s", msg);
}

static void *load_sym(const char *name) {
#ifdef _WIN32
    return (void *)GetProcAddress(g_api.handle, name);
#else
    return dlsym(g_api.handle, name);
#endif
}

WP_EXPORT int wp_init(char *errbuf, size_t errbuf_len) {
    if (g_api.loaded) {
        return 0;
    }

#ifdef _WIN32
    /* Prefer Npcap directory on Windows */
    char npcap_dir[MAX_PATH];
    UINT sys_len = GetSystemDirectoryA(npcap_dir, sizeof(npcap_dir) - 16);
    if (sys_len > 0) {
        snprintf(npcap_dir + sys_len, sizeof(npcap_dir) - sys_len, "\\Npcap");
        SetDllDirectoryA(npcap_dir);
    }
    g_api.handle = LoadLibraryA("wpcap.dll");
    if (!g_api.handle) {
        set_err(errbuf, errbuf_len,
                "Failed to load Npcap wpcap.dll. Please install Npcap (https://npcap.com).");
        return -1;
    }
#else
    const char *candidates[] = {
        "libpcap.so.1",
        "libpcap.so.0.8",
        "libpcap.so",
        "libpcap.dylib",
        NULL
    };
    for (int i = 0; candidates[i] != NULL; ++i) {
        g_api.handle = dlopen(candidates[i], RTLD_LAZY | RTLD_LOCAL);
        if (g_api.handle) break;
    }
    if (!g_api.handle) {
        set_err(errbuf, errbuf_len,
                "Failed to load libpcap shared library (tried libpcap.so.1 / libpcap.so.0.8 / libpcap.so).");
        return -1;
    }
#endif

    g_api.lib_version        = (fn_pcap_lib_version)load_sym("pcap_lib_version");
    g_api.findalldevs        = (fn_pcap_findalldevs)load_sym("pcap_findalldevs");
    g_api.freealldevs        = (fn_pcap_freealldevs)load_sym("pcap_freealldevs");
    g_api.create             = (fn_pcap_create)load_sym("pcap_create");
    g_api.set_snaplen        = (fn_pcap_set_snaplen)load_sym("pcap_set_snaplen");
    g_api.set_promisc        = (fn_pcap_set_promisc)load_sym("pcap_set_promisc");
    g_api.set_timeout        = (fn_pcap_set_timeout)load_sym("pcap_set_timeout");
    g_api.set_buffer_size    = (fn_pcap_set_buffer_size)load_sym("pcap_set_buffer_size");
    g_api.set_immediate_mode = (fn_pcap_set_immediate_mode)load_sym("pcap_set_immediate_mode");
    g_api.activate           = (fn_pcap_activate)load_sym("pcap_activate");
    g_api.open_offline       = (fn_pcap_open_offline)load_sym("pcap_open_offline");
    g_api.open_dead          = (fn_pcap_open_dead)load_sym("pcap_open_dead");
    g_api.compile            = (fn_pcap_compile)load_sym("pcap_compile");
    g_api.setfilter          = (fn_pcap_setfilter)load_sym("pcap_setfilter");
    g_api.freecode           = (fn_pcap_freecode)load_sym("pcap_freecode");
    g_api.next_ex            = (fn_pcap_next_ex)load_sym("pcap_next_ex");
    g_api.datalink           = (fn_pcap_datalink)load_sym("pcap_datalink");
    g_api.stats              = (fn_pcap_stats)load_sym("pcap_stats");
    g_api.breakloop          = (fn_pcap_breakloop)load_sym("pcap_breakloop");
    g_api.close              = (fn_pcap_close)load_sym("pcap_close");
    g_api.geterr             = (fn_pcap_geterr)load_sym("pcap_geterr");
    g_api.statustostr        = (fn_pcap_statustostr)load_sym("pcap_statustostr");
    g_api.dump_open          = (fn_pcap_dump_open)load_sym("pcap_dump_open");
    g_api.dump               = (fn_pcap_dump)load_sym("pcap_dump");
    g_api.dump_flush         = (fn_pcap_dump_flush)load_sym("pcap_dump_flush");
    g_api.dump_close         = (fn_pcap_dump_close)load_sym("pcap_dump_close");

    if (!g_api.findalldevs || !g_api.create || !g_api.activate || !g_api.next_ex ||
        !g_api.compile || !g_api.setfilter || !g_api.close) {
        set_err(errbuf, errbuf_len, "Loaded pcap library is missing required core symbols.");
        return -1;
    }

    g_api.loaded = 1;
    return 0;
}

WP_EXPORT const char *wp_lib_version(void) {
    if (!g_api.loaded && wp_init(NULL, 0) != 0) {
        return "unavailable";
    }
    return g_api.lib_version ? g_api.lib_version() : "libpcap (unknown version)";
}

WP_EXPORT int wp_list_interfaces(wp_iface_info_t *out_list, int max_count,
                                 char *errbuf, size_t errbuf_len) {
    if (wp_init(errbuf, errbuf_len) != 0) return -1;
    if (!out_list || max_count <= 0) {
        set_err(errbuf, errbuf_len, "Invalid output buffer");
        return -1;
    }

    char pcap_err[WP_PCAP_ERRBUF_SIZE] = {0};
    wp_pcap_if_t *alldevs = NULL;
    if (g_api.findalldevs(&alldevs, pcap_err) != 0) {
        set_err(errbuf, errbuf_len, pcap_err);
        return -1;
    }

    int count = 0;
    for (wp_pcap_if_t *dev = alldevs; dev != NULL && count < max_count; dev = dev->next) {
        wp_iface_info_t *item = &out_list[count];
        memset(item, 0, sizeof(*item));
        if (dev->name) {
            snprintf(item->name, sizeof(item->name), "%s", dev->name);
        }
        if (dev->description) {
            snprintf(item->description, sizeof(item->description), "%s", dev->description);
        }
        item->flags = dev->flags;

        for (wp_pcap_addr_t *a = dev->addresses; a != NULL; a = a->next) {
            if (!a->addr) continue;
            if (a->addr->sa_family == AF_INET && item->ipv4[0] == '\0') {
                struct sockaddr_in *sin = (struct sockaddr_in *)a->addr;
                inet_ntop(AF_INET, &sin->sin_addr, item->ipv4, sizeof(item->ipv4));
            } else if (a->addr->sa_family == AF_INET6 && item->ipv6[0] == '\0') {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)a->addr;
                inet_ntop(AF_INET6, &sin6->sin6_addr, item->ipv6, sizeof(item->ipv6));
            }
        }
        count++;
    }

    g_api.freealldevs(alldevs);
    return count;
}

WP_EXPORT int wp_validate_bpf(const char *bpf_expr, int datalink,
                              char *errbuf, size_t errbuf_len) {
    if (wp_init(errbuf, errbuf_len) != 0) return -1;
    if (!bpf_expr || bpf_expr[0] == '\0') return 0;

    if (!g_api.open_dead) {
        set_err(errbuf, errbuf_len, "pcap_open_dead unavailable");
        return -1;
    }
    pcap_t *dead = g_api.open_dead(datalink > 0 ? datalink : WP_DLT_EN10MB, 65535);
    if (!dead) {
        set_err(errbuf, errbuf_len, "pcap_open_dead failed");
        return -1;
    }

    wp_bpf_program_t prog;
    memset(&prog, 0, sizeof(prog));
    int rc = g_api.compile(dead, &prog, bpf_expr, 1, WP_PCAP_NETMASK_UNKNOWN);
    if (rc != 0) {
        set_err(errbuf, errbuf_len, g_api.geterr ? g_api.geterr(dead) : "Invalid BPF expression");
        g_api.close(dead);
        return -1;
    }
    if (g_api.freecode) g_api.freecode(&prog);
    g_api.close(dead);
    return 0;
}

static int apply_bpf_filter(pcap_t *handle, const char *bpf_filter,
                            char *errbuf, size_t errbuf_len) {
    if (!bpf_filter || bpf_filter[0] == '\0') return 0;

    wp_bpf_program_t prog;
    memset(&prog, 0, sizeof(prog));
    if (g_api.compile(handle, &prog, bpf_filter, 1, WP_PCAP_NETMASK_UNKNOWN) != 0) {
        set_err(errbuf, errbuf_len, g_api.geterr ? g_api.geterr(handle) : "BPF compile error");
        return -1;
    }
    if (g_api.setfilter(handle, &prog) != 0) {
        set_err(errbuf, errbuf_len, g_api.geterr ? g_api.geterr(handle) : "BPF setfilter error");
        if (g_api.freecode) g_api.freecode(&prog);
        return -1;
    }
    if (g_api.freecode) g_api.freecode(&prog);
    return 0;
}

WP_EXPORT wp_session_t *wp_open_live(const char *iface_name,
                                     int snaplen,
                                     int promisc,
                                     int timeout_ms,
                                     int buffer_size_mb,
                                     const char *bpf_filter,
                                     char *errbuf,
                                     size_t errbuf_len) {
    if (wp_init(errbuf, errbuf_len) != 0) return NULL;
    if (!iface_name || iface_name[0] == '\0') {
        set_err(errbuf, errbuf_len, "Interface name is empty");
        return NULL;
    }

    char pcap_err[WP_PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = g_api.create(iface_name, pcap_err);
    if (!handle) {
        set_err(errbuf, errbuf_len, pcap_err);
        return NULL;
    }

    if (snaplen <= 0) snaplen = 65535;
    if (timeout_ms <= 0) timeout_ms = 50;
    if (buffer_size_mb <= 0) buffer_size_mb = 16;

    if (g_api.set_snaplen) g_api.set_snaplen(handle, snaplen);
    if (g_api.set_promisc) g_api.set_promisc(handle, promisc ? 1 : 0);
    if (g_api.set_timeout) g_api.set_timeout(handle, timeout_ms);
    if (g_api.set_buffer_size) {
        /* Large kernel ring buffer (TPACKET_V3 on Linux / Npcap kernel buffer on Win32) */
        g_api.set_buffer_size(handle, buffer_size_mb * 1024 * 1024);
    }
    if (g_api.set_immediate_mode) {
        /* Immediate delivery minimizes interactive GUI capture latency */
        g_api.set_immediate_mode(handle, 1);
    }

    int act_rc = g_api.activate(handle);
    if (act_rc < 0) {
        const char *status_msg = g_api.statustostr ? g_api.statustostr(act_rc) : "activate failed";
        const char *detail = g_api.geterr ? g_api.geterr(handle) : "";
        char combined[512];
        snprintf(combined, sizeof(combined), "%s: %s", status_msg, detail);
        set_err(errbuf, errbuf_len, combined);
        g_api.close(handle);
        return NULL;
    }

    if (apply_bpf_filter(handle, bpf_filter, errbuf, errbuf_len) != 0) {
        g_api.close(handle);
        return NULL;
    }

    wp_session_t *sess = (wp_session_t *)calloc(1, sizeof(wp_session_t));
    if (!sess) {
        g_api.close(handle);
        set_err(errbuf, errbuf_len, "Out of memory");
        return NULL;
    }
    sess->handle = handle;
    sess->is_live = 1;
    sess->datalink = g_api.datalink ? g_api.datalink(handle) : WP_DLT_EN10MB;
    return sess;
}

WP_EXPORT wp_session_t *wp_open_offline(const char *filepath,
                                        const char *bpf_filter,
                                        char *errbuf,
                                        size_t errbuf_len) {
    if (wp_init(errbuf, errbuf_len) != 0) return NULL;
    if (!filepath || filepath[0] == '\0') {
        set_err(errbuf, errbuf_len, "File path is empty");
        return NULL;
    }
    if (!g_api.open_offline) {
        set_err(errbuf, errbuf_len, "pcap_open_offline unavailable");
        return NULL;
    }

    char pcap_err[WP_PCAP_ERRBUF_SIZE] = {0};
    pcap_t *handle = g_api.open_offline(filepath, pcap_err);
    if (!handle) {
        set_err(errbuf, errbuf_len, pcap_err);
        return NULL;
    }

    if (apply_bpf_filter(handle, bpf_filter, errbuf, errbuf_len) != 0) {
        g_api.close(handle);
        return NULL;
    }

    wp_session_t *sess = (wp_session_t *)calloc(1, sizeof(wp_session_t));
    if (!sess) {
        g_api.close(handle);
        set_err(errbuf, errbuf_len, "Out of memory");
        return NULL;
    }
    sess->handle = handle;
    sess->is_live = 0;
    sess->datalink = g_api.datalink ? g_api.datalink(handle) : WP_DLT_EN10MB;
    return sess;
}

WP_EXPORT int wp_next_packet(wp_session_t *sess,
                             wp_packet_view_t *out_pkt,
                             char *errbuf,
                             size_t errbuf_len) {
    if (!sess || !sess->handle || !out_pkt) {
        set_err(errbuf, errbuf_len, "Invalid session or output pointer");
        return -1;
    }

    wp_pcap_pkthdr_t *hdr = NULL;
    const uint8_t *data = NULL;
    int rc = g_api.next_ex(sess->handle, &hdr, &data);
    if (rc == 1 && hdr && data) {
        out_pkt->ts_sec  = (int64_t)hdr->ts.tv_sec;
        out_pkt->ts_usec = (int32_t)hdr->ts.tv_usec;
        out_pkt->caplen  = hdr->caplen;
        out_pkt->origlen = hdr->len;
        out_pkt->data    = data;
        sess->packets_captured += 1;
        sess->bytes_captured += hdr->caplen;
        return 1;
    }
    if (rc == 0) {
        return 0; /* Timeout */
    }
    if (rc == -2) {
        return -2; /* EOF or pcap_breakloop */
    }
    set_err(errbuf, errbuf_len, g_api.geterr ? g_api.geterr(sess->handle) : "pcap_next_ex error");
    return -1;
}

WP_EXPORT int wp_get_datalink(wp_session_t *sess) {
    return sess ? sess->datalink : -1;
}

WP_EXPORT int wp_get_stats(wp_session_t *sess, wp_capture_stats_t *out_stats) {
    if (!sess || !out_stats) return -1;
    memset(out_stats, 0, sizeof(*out_stats));
    out_stats->packets_captured = sess->packets_captured;
    out_stats->bytes_captured = sess->bytes_captured;
    out_stats->datalink = sess->datalink;

    if (sess->is_live && g_api.stats && sess->handle) {
        wp_pcap_stat_t st;
        memset(&st, 0, sizeof(st));
        if (g_api.stats(sess->handle, &st) == 0) {
            out_stats->kernel_recv = st.ps_recv;
            out_stats->kernel_drop = st.ps_drop;
            out_stats->iface_drop  = st.ps_ifdrop;
        }
    }
    return 0;
}

WP_EXPORT void wp_break(wp_session_t *sess) {
    if (sess && sess->handle && g_api.breakloop) {
        g_api.breakloop(sess->handle);
    }
}

WP_EXPORT void wp_close(wp_session_t *sess) {
    if (!sess) return;
    if (sess->handle && g_api.close) {
        g_api.close(sess->handle);
    }
    free(sess);
}

WP_EXPORT pcap_dumper_t *wp_dump_open(wp_session_t *sess, const char *filepath,
                                      char *errbuf, size_t errbuf_len) {
    if (!sess || !sess->handle || !filepath) {
        set_err(errbuf, errbuf_len, "Invalid arguments for dump_open");
        return NULL;
    }
    if (!g_api.dump_open) {
        set_err(errbuf, errbuf_len, "pcap_dump_open unavailable");
        return NULL;
    }
    pcap_dumper_t *d = g_api.dump_open(sess->handle, filepath);
    if (!d) {
        set_err(errbuf, errbuf_len, g_api.geterr ? g_api.geterr(sess->handle) : "pcap_dump_open failed");
    }
    return d;
}

WP_EXPORT void wp_dump_packet(pcap_dumper_t *dumper,
                              int64_t ts_sec, int32_t ts_usec,
                              uint32_t caplen, uint32_t origlen,
                              const uint8_t *data) {
    if (!dumper || !data || !g_api.dump) return;
    wp_pcap_pkthdr_t hdr;
    hdr.ts.tv_sec  = (long)ts_sec;
    hdr.ts.tv_usec = (long)ts_usec;
    hdr.caplen     = caplen;
    hdr.len        = origlen;
    g_api.dump((uint8_t *)dumper, &hdr, data);
}

WP_EXPORT void wp_dump_close(pcap_dumper_t *dumper) {
    if (!dumper) return;
    if (g_api.dump_flush) g_api.dump_flush(dumper);
    if (g_api.dump_close) g_api.dump_close(dumper);
}
