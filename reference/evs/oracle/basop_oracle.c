/*
 * Differential oracle for the STL2009 / EVS basic operators.
 *
 * Built out of tree against the TS 26.442 reference sources by `oracle/build.sh`; never part of the
 * Rust build. Two modes:
 *
 *   basop_oracle eval OP ARG... [overflow carry]
 *       Print the reference result for one call, as `result [hi lo] overflow carry`.
 *   basop_oracle corpus COUNT SEED
 *       Print COUNT edge-heavy pseudo-random cases per operator, one per line:
 *       `OP in... -> out... overflow carry`, for tests/evs_basop_oracle.rs to replay.
 *
 * All integers are printed in decimal. The flags are the reference globals after the call.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stl.h"
#include "basop_mpy.h"
#include "oper_32b.h"
#include "math_32.h"

extern Flag Overflow;
extern Flag Carry;

static unsigned long long state;

static unsigned int next_random(void)
{
    state = state * 6364136223846793005ULL + 1442695040888963407ULL;
    return (unsigned int)(state >> 33);
}

static const Word32 edges32[] = {
    0, 1, -1, 2, -2, 0x7fffffff, (Word32)0x80000000, 0x7ffffffe, (Word32)0x80000001,
    0x3fffffff, 0x40000000, (Word32)0xc0000000, (Word32)0xbfffffff, 0x00008000, 0x00007fff,
    0x0000ffff, 0x00010000, (Word32)0xffff8000, (Word32)0xffff0000, 0x12345678, (Word32)0xedcba988
};

static const Word16 edges16[] = {
    0, 1, -1, 2, -2, 0x7fff, (Word16)0x8000, 0x7ffe, (Word16)0x8001, 0x3fff, 0x4000,
    (Word16)0xc000, 0x00ff, 0x0100, 15, 16, 17, 31, 32, 33, -15, -16, -17, -31, -32, -33
};

static Word32 any32(void)
{
    if (next_random() & 1)
        return edges32[next_random() % (sizeof(edges32) / sizeof(edges32[0]))];
    return (Word32)((next_random() << 16) ^ next_random());
}

static Word16 any16(void)
{
    if (next_random() & 1)
        return edges16[next_random() % (sizeof(edges16) / sizeof(edges16[0]))];
    return (Word16)next_random();
}

/* A shift count: mostly in [-40, 40], sometimes anything. */
static Word16 count16(void)
{
    if (next_random() % 8 == 0)
        return any16();
    return (Word16)((int)(next_random() % 81) - 40);
}

static void flags_in(int overflow, int carry)
{
    Overflow = (Flag)overflow;
    Carry = (Flag)carry;
}

static void flags_out(void)
{
    printf(" %d %d\n", Overflow ? 1 : 0, Carry ? 1 : 0);
}

/* One call. `a` holds the decimal operands; returns 0 on an unknown operator. */
static int eval(const char *op, const long long *a)
{
    Word32 hi32;
    UWord16 lo16;
    UWord32 lo32, uhi32;
    UWord16 flag16;

    if (!strcmp(op, "L_mult0")) printf("%d", L_mult0((Word16)a[0], (Word16)a[1]));
    else if (!strcmp(op, "L_mac0")) printf("%d", L_mac0((Word32)a[0], (Word16)a[1], (Word16)a[2]));
    else if (!strcmp(op, "L_msu0")) printf("%d", L_msu0((Word32)a[0], (Word16)a[1], (Word16)a[2]));
    else if (!strcmp(op, "i_mult")) printf("%d", i_mult((Word16)a[0], (Word16)a[1]));
    else if (!strcmp(op, "mac_r")) printf("%d", mac_r((Word32)a[0], (Word16)a[1], (Word16)a[2]));
    else if (!strcmp(op, "msu_r")) printf("%d", msu_r((Word32)a[0], (Word16)a[1], (Word16)a[2]));
    else if (!strcmp(op, "L_mls")) printf("%d", L_mls((Word32)a[0], (Word16)a[1]));
    else if (!strcmp(op, "div_l")) printf("%d", div_l((Word32)a[0], (Word16)a[1]));
    else if (!strcmp(op, "lshl")) printf("%d", lshl((Word16)a[0], (Word16)a[1]));
    else if (!strcmp(op, "lshr")) printf("%d", lshr((Word16)a[0], (Word16)a[1]));
    else if (!strcmp(op, "L_lshl")) printf("%d", L_lshl((Word32)a[0], (Word16)a[1]));
    else if (!strcmp(op, "L_lshr")) printf("%d", L_lshr((Word32)a[0], (Word16)a[1]));
    else if (!strcmp(op, "shl_r")) printf("%d", shl_r((Word16)a[0], (Word16)a[1]));
    else if (!strcmp(op, "L_shl_r")) printf("%d", L_shl_r((Word32)a[0], (Word16)a[1]));
    else if (!strcmp(op, "norm_ul")) printf("%d", norm_ul((UWord32)a[0]));
    else if (!strcmp(op, "UL_addNs")) { lo32 = UL_addNs((UWord32)a[0], (UWord32)a[1], &flag16); printf("%u %u", lo32, flag16); }
    else if (!strcmp(op, "UL_subNs")) { lo32 = UL_subNs((UWord32)a[0], (UWord32)a[1], &flag16); printf("%u %u", lo32, flag16); }
    else if (!strcmp(op, "Mpy_32_16_uu")) { Mpy_32_16_uu((UWord32)a[0], (UWord16)a[1], &uhi32, &lo16); printf("%u %u", uhi32, lo16); }
    else if (!strcmp(op, "Mpy_32_32_uu")) { Mpy_32_32_uu((UWord32)a[0], (UWord32)a[1], &uhi32, &lo32); printf("%u %u", uhi32, lo32); }
    else if (!strcmp(op, "UL_Mpy_32_32")) printf("%u", UL_Mpy_32_32((UWord32)a[0], (UWord32)a[1]));
    else if (!strcmp(op, "Mpy_32_16_ss")) { Mpy_32_16_ss((Word32)a[0], (Word16)a[1], &hi32, &lo16); printf("%d %u", hi32, lo16); }
    else if (!strcmp(op, "Mpy_32_32_ss")) { Mpy_32_32_ss((Word32)a[0], (Word32)a[1], &hi32, &lo32); printf("%d %u", hi32, lo32); }
    else if (!strcmp(op, "L_add_c")) printf("%d", L_add_c((Word32)a[0], (Word32)a[1]));
    else if (!strcmp(op, "L_sub_c")) printf("%d", L_sub_c((Word32)a[0], (Word32)a[1]));
    else if (!strcmp(op, "L_macNs")) printf("%d", L_macNs((Word32)a[0], (Word16)a[1], (Word16)a[2]));
    else if (!strcmp(op, "L_msuNs")) printf("%d", L_msuNs((Word32)a[0], (Word16)a[1], (Word16)a[2]));
    else if (!strcmp(op, "Mpy_32_16_1")) printf("%d", Mpy_32_16_1((Word32)a[0], (Word16)a[1]));
    else if (!strcmp(op, "Mpy_32_16_r")) printf("%d", Mpy_32_16_r((Word32)a[0], (Word16)a[1]));
    else if (!strcmp(op, "Mpy_32_32")) printf("%d", Mpy_32_32((Word32)a[0], (Word32)a[1]));
    else if (!strcmp(op, "Mpy_32_32_r")) printf("%d", Mpy_32_32_r((Word32)a[0], (Word32)a[1]));
    else if (!strcmp(op, "Madd_32_16")) printf("%d", Madd_32_16((Word32)a[0], (Word32)a[1], (Word16)a[2]));
    else if (!strcmp(op, "Msub_32_16")) printf("%d", Msub_32_16((Word32)a[0], (Word32)a[1], (Word16)a[2]));
    else if (!strcmp(op, "Div_32")) printf("%d", Div_32((Word32)a[0], (Word16)a[1], (Word16)a[2]));
    else return 0;
    return 1;
}

/* Operand shapes: '3' = Word32, '1' = Word16, 's' = shift count, 'u' = UWord32, 'h' = UWord16. */
struct shape { const char *op; const char *args; };

static const struct shape shapes[] = {
    {"L_mult0", "11"}, {"L_mac0", "311"}, {"L_msu0", "311"}, {"i_mult", "11"},
    {"mac_r", "311"}, {"msu_r", "311"}, {"L_mls", "31"}, {"lshl", "1s"}, {"lshr", "1s"},
    {"L_lshl", "3s"}, {"L_lshr", "3s"}, {"shl_r", "1s"}, {"L_shl_r", "3s"}, {"norm_ul", "u"},
    {"UL_addNs", "uu"}, {"UL_subNs", "uu"}, {"Mpy_32_16_uu", "uh"}, {"Mpy_32_32_uu", "uu"},
    {"UL_Mpy_32_32", "uu"}, {"Mpy_32_16_ss", "31"}, {"Mpy_32_32_ss", "33"}, {"L_add_c", "33"},
    {"L_sub_c", "33"}, {"L_macNs", "311"}, {"L_msuNs", "311"}, {"Mpy_32_16_1", "31"},
    {"Mpy_32_16_r", "31"}, {"Mpy_32_32", "33"}, {"Mpy_32_32_r", "33"}, {"Madd_32_16", "331"},
    {"Msub_32_16", "331"},
};

static void corpus(long count)
{
    size_t s;
    long i;
    for (s = 0; s < sizeof(shapes) / sizeof(shapes[0]); s++) {
        for (i = 0; i < count; i++) {
            long long a[4];
            int n, overflow = next_random() & 1, carry = next_random() & 1;
            for (n = 0; shapes[s].args[n]; n++) {
                switch (shapes[s].args[n]) {
                case '3': a[n] = any32(); break;
                case '1': a[n] = any16(); break;
                case 's':
                    a[n] = count16();
                    /* The logical shifts recurse forever on -32768 (-(-32768) wraps to itself). */
                    if (strstr(shapes[s].op, "lsh") && a[n] == -32768)
                        a[n] = -32767;
                    break;
                case 'u': a[n] = (UWord32)any32(); break;
                default:  a[n] = (UWord16)any16(); break;
                }
            }
            printf("%s", shapes[s].op);
            for (int k = 0; k < n; k++) printf(" %lld", a[k]);
            printf(" %d %d ->", overflow, carry);
            flags_in(overflow, carry);
            printf(" ");
            eval(shapes[s].op, a);
            flags_out();
        }
    }
    /* div_l and Div_32 only accept the operand domain their callers guarantee: a non-negative
     * numerator below a positive (Div_32: normalised) denominator. Outside it the reference exits. */
    for (i = 0; i < count; i++) {
        long long a[3];
        Word16 den = (Word16)(next_random() % 0x7fff + 1);
        a[0] = (Word32)(next_random() % ((unsigned int)den << 16));
        a[1] = den;
        printf("div_l %lld %lld 0 0 -> ", a[0], a[1]);
        flags_in(0, 0);
        eval("div_l", a);
        flags_out();
    }
    for (i = 0; i < count; i++) {
        long long a[3];
        Word16 hi = (Word16)(0x4000 + next_random() % 0x3fff);
        Word16 lo = (Word16)(next_random() & 0x7fff);
        Word32 denom = ((Word32)hi << 16) + ((Word32)lo << 1);
        a[0] = (Word32)(next_random() % (unsigned int)denom);
        a[1] = hi;
        a[2] = lo;
        printf("Div_32 %lld %lld %lld 0 0 -> ", a[0], a[1], a[2]);
        flags_in(0, 0);
        eval("Div_32", a);
        flags_out();
    }
}

int main(int argc, char **argv)
{
    if (argc >= 3 && !strcmp(argv[1], "eval")) {
        long long a[4] = {0, 0, 0, 0};
        int n = argc - 3, overflow = 0, carry = 0;
        int k;
        /* Trailing "overflow carry" pair is optional: detect it by the operator's arity. */
        size_t s;
        for (s = 0; s < sizeof(shapes) / sizeof(shapes[0]); s++)
            if (!strcmp(shapes[s].op, argv[2]) && (int)strlen(shapes[s].args) + 2 == n) {
                overflow = atoi(argv[argc - 2]);
                carry = atoi(argv[argc - 1]);
                n -= 2;
            }
        for (k = 0; k < n && k < 4; k++) a[k] = atoll(argv[3 + k]);
        flags_in(overflow, carry);
        if (!eval(argv[2], a)) {
            fprintf(stderr, "unknown operator %s\n", argv[2]);
            return 1;
        }
        flags_out();
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "corpus")) {
        state = strtoull(argv[3], NULL, 10);
        corpus(atol(argv[2]));
        return 0;
    }
    fprintf(stderr, "usage: basop_oracle eval OP ARG... [overflow carry] | corpus COUNT SEED\n");
    return 2;
}
