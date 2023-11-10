// SPDX-License-Identifier: LGPL-3.0-or-later
//
// Original code by	Hristo Venev
// https://git.venev.name/hristo/rpi-eeprom-compress/
//
// compile with:
// gcc compress.c -O3 -shared -o compress.so

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

struct backref {
    size_t cost;
    uint8_t mlen, moff;
};

struct node {
    size_t off, len;
    struct node *next[256];
};

static void free_nodes(struct node **p) {
    for(size_t i = 0; i < 256; i++) {
        struct node *n = p[i];
        if(!n) continue;
        free_nodes(n->next);
        free(n);
    }
}

inline static void init_nodes(struct node **p) {
    memset(p, 0, 256 * sizeof(*p));
}

static struct backref *compress_data(const uint8_t *data, size_t len) {
    struct node *root[256];
    init_nodes(root);

    if(len >= (size_t)-1 / sizeof(struct backref) - 1) {
        errno = ENOMEM;
        return NULL;
    }
    struct backref *best = malloc((len + 1) * sizeof(struct backref));
    if(!best) {
        return NULL;
    }

    best[0] = (struct backref){
        .cost = 0,
    };

    for(size_t suff_len = 1; suff_len <= len; suff_len++) {
        size_t min_cost = best[suff_len - 1].cost + 9;
        uint8_t min_mlen = 0;
        uint8_t min_moff = 0;

        size_t at = suff_len;
        size_t bound = at < 256 ? 0 : at - 256;
        struct node **p = root;
        while(at > bound) {
            size_t left = at - bound;

            p += data[at - 1];
            struct node *n = *p;
            size_t mlen;
            if(!n) {
                n = calloc(1, sizeof(struct node));
                if(!n) goto fail;
                mlen = left;
                *p = n;
            } else {
                assert(n->len > 0);
                assert(n->off < at);
                size_t moff = at - n->off;
                if(moff > 256) {
                    free_nodes(n->next);
                    init_nodes(n->next);
                    mlen = left;
                } else {
                    const uint8_t *cmp1 = data + at;
                    const uint8_t *cmp2 = data + n->off;
                    if(n->len < left) left = n->len;
                    mlen = 0;
                    while(mlen < left) {
                        if(*--cmp1 != *--cmp2) break;
                        mlen++;
                    }
                    assert(mlen > 0);

                    for(size_t i = mlen; i > 0; i--) {
                        size_t base = at - i;
                        size_t cost = best[base].cost + 17;
                        assert(suff_len - base <= 256);
                        if(cost < min_cost) {
                            assert(suff_len - base > 1);
                            min_cost = cost;
                            min_mlen = suff_len - base - 1;
                            min_moff = moff - 1;
                        }
                    }

                    if(mlen != n->len) {
                        n->len -= mlen;
                        n->off -= mlen;
                        struct node *n2 = calloc(1, sizeof(struct node));
                        if(!n2) goto fail;
                        n2->next[*cmp2] = n;
                        n = n2;
                        *p = n;
                    }
                }
            }
            n->off = at;
            n->len = mlen;
            p = n->next;
            at -= mlen;
        }

        best[suff_len] = (struct backref){
            .cost = min_cost,
            .mlen = min_mlen,
            .moff = min_moff,
        };
    }

    free_nodes(root);
    return best;

fail:;
    int e = errno;
    free_nodes(root);
    errno = e;
    return NULL;
}

static int reconstruct(const uint8_t *data, size_t len, uint8_t *out, size_t out_len, struct backref *back) {
    size_t cost = back[len].cost;
    size_t bytes = (cost + 7) / 8;
    uint8_t *buf = malloc(bytes);
    if(!buf) return -1;

    uint8_t *at = buf + bytes;
    uint8_t cmd = 0;
    while(len) {
        assert(cost == back[len].cost);
        cmd <<= 1;
        if(back[len].mlen == 0) {
            cost -= 9;
            *--at = data[--len];
        } else {
            cmd |= 1;
            cost -= 17;
            *--at = back[len].mlen;
            *--at = back[len].moff;
            len -= (size_t)back[len].mlen + 1;
        }
        if(cost % 8 == 0) {
            *--at = cmd;
            cmd = 0;
        }
    }
    assert(cost == 0);
    assert(at == buf);
    if (bytes > out_len)
        return -1;
    memcpy(out, buf, bytes);
    free(buf);
    return bytes;
}

int compress(const uint8_t *data, size_t data_len, uint8_t *out, size_t out_len) {
    struct backref *best = compress_data(data, data_len);
    int r = reconstruct(data, data_len, out, out_len, best);
    free(best);
    return r;
}
