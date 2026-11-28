/* Function-level oracle for lib_com/core_com_config_fx.c. */
#include "harness.h"
#include "prot_fx.h"

static const Word32 rates[] = {5900, 7200, 8000, 9600, 13200, 16400, 24400, 32000, 48000, 64000, 96000, 128000, 13201, 64001, 32001};

static void case_config(void)
{
    Word32 bitrate = rates[next_random() % 15];
    Word16 bandwidth = (Word16)random_range(0, 3), rf = (Word16)random_range(0, 1), igf = (Word16)random_range(0, 1);
    static const Word32 srs[] = {8000, 12800, 16000, 25600, 32000, 48000, 44100};
    Word32 sr = srs[next_random() % 7];
    Word32 core_sr = getCoreSamplerateMode2(bitrate, bandwidth, rf);
    Word16 pit_min, pit_fr1, pit_fr1b, pit_fr2, pit_max, res;
    Word32 pitch_sr = (Word32[]){12800, 16000, 25600, 32000}[next_random() % 4];
    res = initPitchLagParameters(pitch_sr, &pit_min, &pit_fr1, &pit_fr1b, &pit_fr2, &pit_max);
    put1("bitrate", bitrate); put1("bandwidth", bandwidth); put1("rf", rf); put1("igf", igf); put1("sr", sr);
    put1("pitch_sr", pitch_sr);
    arrow();
    put1("core_sr", core_sr); put1("tcxonly", getTcxonly(bitrate)); put1("ctx_hm", getCtxHm(bitrate, rf));
    put1("resq", getResq(bitrate)); put1("tns", getTnsAllowed(bitrate, igf));
    put1("fscale", sr == 44100 ? 0 : sr2fscale(sr)); put1("tcx_bw", getTcxBandwidth(bandwidth));
    put1("tcxltp", getTcxLtp(sr)); put1("lines", getNumTcxCodedLines(bandwidth));
    put1("lpc_ari", getTcxLpcShapedAri(bitrate, bandwidth, rf));
    put1("pit_min", pit_min); put1("pit_fr1", pit_fr1); put1("pit_fr1b", pit_fr1b); put1("pit_fr2", pit_fr2);
    put1("pit_max", pit_max); put1("pit_res_max", res);
    end_line();
}

int main(int argc, char **argv)
{
    if (argc != 5 || strcmp(argv[1], "corpus")) { fprintf(stderr, "usage: corpus FUNCTION COUNT SEED\n"); return 2; }
    seed_random(argv[4]);
    for (long i = 0, n = atol(argv[3]); i < n; i++) {
        if (!strcmp(argv[2], "config")) case_config();
        else { fprintf(stderr, "unknown function %s\n", argv[2]); return 2; }
    }
    return 0;
}
