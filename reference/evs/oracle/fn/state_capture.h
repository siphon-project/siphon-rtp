/* Whole-state comparison helpers for the oracles that include init_dec.c with STATE_DUMP_LIBRARY:
 * print the state before a call (prefix "in.") and, after it, only the fields that changed
 * (prefix "st."); tests/evs_fn_oracle/state_case.rs overlays the changes on the "before" state,
 * so the comparison still covers every field. Include after init_dec.c. */
#ifndef EVS_ORACLE_STATE_CAPTURE_H
#define EVS_ORACLE_STATE_CAPTURE_H

#include <stdio.h>
#include <string.h>

/* The state dump as a string (keys without prefix). */
static char *capture_state(Decoder_State_fx *st)
{
    char *buffer = NULL;
    size_t length = 0;
    FILE *saved = stdout;
    fflush(stdout);
    stdout = open_memstream(&buffer, &length);
    rd_dump_DecoderState("", st);
    fclose(stdout);
    stdout = saved;
    return buffer;
}

/* Print a captured state with prefix "in.". */
static void put_state_in(const char *state)
{
    for (const char *p = state; *p;) {
        const char *end = strchr(p + 1, ' ');
        size_t len = end ? (size_t)(end - p) : strlen(p);
        printf(" in.%.*s", (int)len - 1, p + 1);
        p += len;
    }
}

/* Print the "after" state as only the fields that changed (prefix "st."). */
static void put_changed(const char *before, const char *after)
{
    while (*after) {
        const char *a_end = strchr(after + 1, ' '), *b_end = strchr(before + 1, ' ');
        size_t a_len = a_end ? (size_t)(a_end - after) : strlen(after);
        size_t b_len = b_end ? (size_t)(b_end - before) : strlen(before);
        if (a_len != b_len || memcmp(after, before, a_len)) printf(" st.%.*s", (int)a_len - 1, after + 1);
        after += a_len;
        before += b_len;
    }
}

#endif
