/*
 * test_collision.c - what a nonce collision costs, with the real Ascon-AEAD128, and that the
 * fixed-width nonce avoids it. Built by build.sh on the Pi (needs the Ascon objects):
 *
 *   gcc -O2 -Ilib -Ithird_party/ascon/asconaead128 tests/test_collision.c lib/goose_sec.c build/ascon_*.o
 *
 * Two different GOOSE states, (stNum=1, sqNum=512) and (stNum=258, sqNum=0), carry different
 * breaker commands. With the BER-concatenated nonce (an ASSUMPTION about the baseline: the
 * Banerjee paper does not state its nonce) they get the SAME nonce; with identical key and AAD the
 * keystream of the first block is then identical and C1 xor C2 == P1 xor P2, which leaks the
 * plaintext relation without any key. With the fixed-width nonce the two nonces differ.
 */
#include "goose_sec.h"
#include <stdio.h>
#include <string.h>

extern int crypto_aead_encrypt(unsigned char*, unsigned long long*, const unsigned char*,
                               unsigned long long, const unsigned char*, unsigned long long,
                               const unsigned char*, const unsigned char*, const unsigned char*);

static int xor_leak(const uint8_t* n1, const uint8_t* n2, const uint8_t* m1, const uint8_t* m2)
{
    uint8_t ad[16], c1[64], c2[64];
    unsigned long long l1, l2;
    int i, leak = 1;
    memset(ad, 0x42, sizeof ad);
    crypto_aead_encrypt(c1, &l1, m1, 20, ad, sizeof ad, NULL, n1, GS_KEY);
    crypto_aead_encrypt(c2, &l2, m2, 20, ad, sizeof ad, NULL, n2, GS_KEY);
    /* first block only: later blocks absorb plaintext into the state */
    for (i = 0; i < 8; i++)
        if ((uint8_t)(c1[i] ^ c2[i]) != (uint8_t)(m1[i] ^ m2[i])) leak = 0;
    return leak;
}

int main(void)
{
    const uint8_t t[8] = {0x66, 0x1a, 0x2b, 0x3c, 0x00, 0x00, 0x00, 0x18};
    const uint8_t m1[20] = "BRK:OPEN-----------";
    const uint8_t m2[20] = "BRK:CLOSE----------";
    uint8_t na[16], nb[16], fa[16], fb[16];
    int ber_same, ber_leak, fix_same, fix_leak, ok;

    gs_nonce_ber(na, 1, 512, t);   gs_nonce_ber(nb, 258, 0, t);
    gs_nonce_fixed(fa, 1, 512, t); gs_nonce_fixed(fb, 258, 0, t);
    ber_same = memcmp(na, nb, 16) == 0;
    fix_same = memcmp(fa, fb, 16) == 0;
    ber_leak = xor_leak(na, nb, m1, m2);
    fix_leak = xor_leak(fa, fb, m1, m2);

    printf("assumed BER nonce : identical=%s   C1^C2 == P1^P2 (first block): %s\n",
           ber_same ? "YES" : "no", ber_leak ? "YES (keystream reuse)" : "no");
    printf("fixed-width nonce : identical=%s   C1^C2 == P1^P2 (first block): %s\n",
           fix_same ? "YES" : "no", fix_leak ? "YES (keystream reuse)" : "no");
    ok = ber_same && ber_leak && !fix_same && !fix_leak;
    printf(ok ? "PASS\n" : "FAIL\n");
    return ok ? 0 : 1;
}
