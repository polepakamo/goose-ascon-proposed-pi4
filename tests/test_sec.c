/* test_sec.c - host-side unit tests for goose_sec.c (no libIEC61850, no Ascon needed).
 *   gcc -std=c99 -O2 -I../lib test_sec.c ../lib/goose_sec.c -o test_sec && ./test_sec
 */
#include "goose_sec.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL line %d: %s\n", __LINE__, #c); fails++; } } while (0)

static void test_nonce_ber(void)
{
    uint8_t a[16], b[16], c[16], d[16], e[16];
    const uint8_t t[8] = {1,2,3,4,5,6,7,8};

    gs_nonce_ber(a, 7, 3, t);
    gs_nonce_ber(b, 7, 3, t);
    CHECK(memcmp(a, b, 16) == 0);
    CHECK(a[0] == 0x07 && a[1] == 0x03 && a[2] == 1 && a[9] == 8 && a[10] == 0);
    gs_nonce_ber(e, 128, 0, t);
    CHECK(e[0] == 0x00 && e[1] == 0x80 && e[2] == 0x00 && e[3] == 1);

    /* the ASSUMED baseline nonce collides for different counters */
    gs_nonce_ber(a, 1, 512, t);
    gs_nonce_ber(b, 258, 0, t);
    CHECK(memcmp(a, b, 16) == 0);
    gs_nonce_ber(c, 1, 257, t);
    gs_nonce_ber(d, 257, 1, t);
    CHECK(memcmp(c, d, 16) == 0);
    gs_nonce_ber(a, 1, 2, t);
    gs_nonce_ber(b, 2, 1, t);
    CHECK(memcmp(a, b, 16) != 0);
}

static void test_nonce_fixed(void)
{
    uint8_t a[16], b[16];
    const uint8_t t[8] = {1,2,3,4,5,6,7,8};

    /* layout: stNum | sqNum | t, big endian */
    gs_nonce_fixed(a, 0x01020304u, 0x0a0b0c0du, t);
    CHECK(a[0] == 1 && a[1] == 2 && a[2] == 3 && a[3] == 4);
    CHECK(a[4] == 0x0a && a[5] == 0x0b && a[6] == 0x0c && a[7] == 0x0d);
    CHECK(memcmp(a + 8, t, 8) == 0);

    /* the pairs that collide under the BER nonce are distinct here */
    gs_nonce_fixed(a, 1, 512, t);
    gs_nonce_fixed(b, 258, 0, t);
    CHECK(memcmp(a, b, 16) != 0);
    gs_nonce_fixed(a, 1, 257, t);
    gs_nonce_fixed(b, 257, 1, t);
    CHECK(memcmp(a, b, 16) != 0);

    /* injectivity over a small range */
    {
        static uint8_t seen[300][16];
        int n = 0, i, st, sq, dup = 0;
        for (st = 0; st < 20; st++)
            for (sq = 0; sq < 15; sq++) {
                gs_nonce_fixed(seen[n], (uint32_t)st, (uint32_t)sq, t);
                for (i = 0; i < n; i++) if (!memcmp(seen[i], seen[n], 16)) dup++;
                n++;
            }
        CHECK(dup == 0);
    }
}

static void test_window(void)
{
    gs_window_t w;
    gs_window_init(&w);

    CHECK(gs_window_peek(&w, 5, 0) == 0);          /* first frame accepted        */
    gs_window_commit(&w, 5, 0);
    CHECK(gs_window_peek(&w, 5, 0) == -1);         /* duplicate rejected          */
    CHECK(gs_window_peek(&w, 5, 2) == 0);          /* gap (sq 1 lost) accepted    */
    gs_window_commit(&w, 5, 2);
    CHECK(gs_window_peek(&w, 5, 1) == 0);          /* late sq 1 still accepted    */
    gs_window_commit(&w, 5, 1);
    CHECK(gs_window_peek(&w, 5, 1) == -1);         /* but only once               */
    CHECK(gs_window_peek(&w, 4, 0) == -1);         /* older state rejected        */
    CHECK(gs_window_peek(&w, 6, 0) == 0);          /* newer state accepted        */

    /* peek must not change state (commit only after authentication) */
    {
        gs_window_t before = w;
        (void)gs_window_peek(&w, 5, 9);
        (void)gs_window_peek(&w, 9, 9);
        CHECK(memcmp(&before, &w, sizeof(w)) == 0);
    }

    /* a forged high sqNum that never authenticates (never committed) must not
     * block later legitimate frames */
    gs_window_init(&w);
    gs_window_commit(&w, 1, 0);
    CHECK(gs_window_peek(&w, 1, 127) == 0);        /* looks fresh, but never committed */
    CHECK(gs_window_peek(&w, 1, 1) == 0);          /* legitimate frame still accepted  */

    /* window edge: 64 slots */
    gs_window_init(&w);
    gs_window_commit(&w, 1, 100);
    CHECK(gs_window_peek(&w, 1, 37) == 0);         /* d = 63 */
    CHECK(gs_window_peek(&w, 1, 36) == -1);        /* d = 64 */

    /* stNum wrap-around uses serial arithmetic */
    gs_window_init(&w);
    gs_window_commit(&w, 0xfffffffeu, 3);
    CHECK(gs_window_peek(&w, 0xffffffffu, 0) == 0);
    CHECK(gs_window_peek(&w, 1, 0) == 0);          /* 1 is "after" 0xfffffffe */
    CHECK(gs_window_peek(&w, 0xfffffffdu, 0) == -1);
}

static void test_ext(void)
{
    uint8_t nonce[16], tag[16], ext[128];
    const uint8_t *av, *iv, *mac;
    int avl, ivl, n, k;
    for (k = 0; k < 16; k++) { nonce[k] = (uint8_t)k; tag[k] = (uint8_t)(0xA0 + k); }

    n = gs_build_ext(ext, 16, nonce, tag);
    CHECK(n == 55 && n == gs_ext_len(16));
    CHECK(gs_parse_ext(ext, n, &av, &avl, &iv, &ivl, &mac) == 0);
    CHECK(ivl == 16 && memcmp(iv, nonce, 16) == 0 && memcmp(mac, tag, 16) == 0);
    CHECK(avl == 37 && av == ext);

    n = gs_build_ext(ext, 20, nonce, tag);
    CHECK(n == 59 && n == gs_ext_len(20));
    CHECK(gs_parse_ext(ext, n, &av, &avl, &iv, &ivl, &mac) == 0);
    CHECK(ivl == 20 && memcmp(iv, nonce, 16) == 0 && memcmp(mac, tag, 16) == 0);

    CHECK(gs_parse_ext(ext, n - 5, &av, &avl, &iv, &ivl, &mac) != 0);
}

static void test_ber(void)
{
    uint8_t b[8]; int h, l;
    const uint8_t a[] = {0x61, 0x03, 1, 2, 3};
    const uint8_t c[] = {0x61, 0x81, 0xB0};
    CHECK(gs_ber_tl(a, 5, &h, &l) == 0 && h == 2 && l == 3);
    CHECK(gs_ber_tl(a, 4, &h, &l) != 0);
    CHECK(gs_ber_tl(c, 3, &h, &l) != 0);
    CHECK(gs_ber_put_len(b, 5) == 1 && b[0] == 5);
    CHECK(gs_ber_put_len(b, 200) == 2 && b[0] == 0x81 && b[1] == 200);
    CHECK(gs_ber_put_len(b, 300) == 3 && b[0] == 0x82 && b[1] == 1 && b[2] == 44);
}

static void test_log(void)
{
    gs_rec_t r, o; int i;
    memset(&r, 0, sizeof r);
    for (i = 0; i < 1000; i++) { r.st = (uint32_t)i; gs_log_push(&r); }
    for (i = 0; i < 1000; i++) { CHECK(gs_log_pop(&o) == 1 && o.st == (uint32_t)i); }
    CHECK(gs_log_pop(&o) == 0);
    CHECK(gs_log_dropped() == 0);
}

int main(void)
{
    test_nonce_ber(); test_nonce_fixed(); test_window(); test_ext(); test_ber(); test_log();
    if (fails) { printf("%d check(s) FAILED\n", fails); return 1; }
    printf("all goose_sec tests passed\n");
    return 0;
}
