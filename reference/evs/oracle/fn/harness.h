/*
 * Shared helpers for the function-level oracles in this directory.
 *
 * Each oracle/fn/<module>.c is a program `fn_<module> corpus FUNCTION COUNT SEED` that calls one
 * reference function COUNT times on deterministic, edge-heavy inputs and prints one line per call:
 *
 *     name=v,v,v name=v ... -> name=v,v,v name=v ...
 *
 * inputs left of the arrow, outputs (including any in/out state after the call) right of it, every
 * value a decimal integer. tests/evs_fn_oracle/common.rs parses exactly this format.
 */
#ifndef EVS_ORACLE_HARNESS_H
#define EVS_ORACLE_HARNESS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include "stl.h"
#include <sys/resource.h>

/* A harness that crashes must not trigger a core dump / crash reporter: the Rust test fails on the
 * non-zero exit status instead. */
static void __attribute__((constructor)) harness_disable_core_dumps(void)
{
    struct rlimit limit = {0, 0};
    setrlimit(RLIMIT_CORE, &limit);
}

extern Flag Overflow;
extern Flag Carry;

static unsigned long long harness_state;

/* No core dumps: a harness that dies on an input the reference cannot take must not reach the desktop
 * crash reporter (the Rust side fails loudly on the child's exit status). */
static void no_core_dumps(void) { struct rlimit none = {0, 0}; setrlimit(RLIMIT_CORE, &none); }

static void seed_random(const char *seed) { no_core_dumps(); harness_state = strtoull(seed, NULL, 10) * 2654435761ULL + 1; }

static unsigned int next_random(void)
{
    harness_state = harness_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return (unsigned int)(harness_state >> 33);
}

/* Uniform in [low, high]. */
static int random_range(int low, int high) { return low + (int)(next_random() % (unsigned int)(high - low + 1)); }

/* A Word16 that is an edge value half the time, uniform otherwise. */
static Word16 random16(void)
{
    static const Word16 edges[] = {0, 1, -1, 2, -2, 32767, -32768, 32766, -32767, 16383, 16384, -16384};
    if (next_random() & 1) return edges[next_random() % (sizeof(edges) / sizeof(edges[0]))];
    return (Word16)next_random();
}

static Word32 random32(void)
{
    static const Word32 edges[] = {0, 1, -1, 0x7fffffff, (Word32)0x80000000, 0x40000000, (Word32)0xc0000000, 0x8000};
    if (next_random() & 1) return edges[next_random() % (sizeof(edges) / sizeof(edges[0]))];
    return (Word32)((next_random() << 16) ^ next_random());
}

/* A vector of plausible signal: a random walk of the given magnitude, so filters see real-looking data
 * rather than only white noise; mix it with random16() where corner cases matter. */
static void random_signal(Word16 *x, int n, int magnitude)
{
    int value = 0;
    for (int i = 0; i < n; i++) {
        value += random_range(-magnitude / 4, magnitude / 4);
        if (value > magnitude) value = magnitude;
        if (value < -magnitude) value = -magnitude;
        x[i] = (Word16)value;
    }
}

static void put16(const char *name, const Word16 *x, int n)
{
    printf(" %s=", name);
    for (int i = 0; i < n; i++) printf(i ? ",%d" : "%d", x[i]);
}

static void put32(const char *name, const Word32 *x, int n)
{
    printf(" %s=", name);
    for (int i = 0; i < n; i++) printf(i ? ",%d" : "%d", x[i]);
}

static void put_u16(const char *name, const UWord16 *x, int n)
{
    printf(" %s=", name);
    for (int i = 0; i < n; i++) printf(i ? ",%u" : "%u", x[i]);
}

static void put1(const char *name, long long v) { printf(" %s=%lld", name, v); }

static void arrow(void) { printf(" ->"); }
static void end_line(void) { printf("\n"); }

#endif
