//! Generated from the TS 26.442 `rom_basop_util.c` by `reference/evs/oracle/gen_rom.sh`; do not edit.

#[allow(unused_imports)]
use super::*;

/// `ldCoeff` (rom_basop_util.c).
pub static LDCOEFF: [i16; 7] = [-32768, -16384, -10923, -8192, -6554, -5461, -4681];

/// `exp2_tab_long` (rom_basop_util.c).
pub static EXP2_TAB_LONG: [u32; 32] = [
    1073741824, 1097253708, 1121280436, 1145833280, 1170923762, 1196563654, 1222764986, 1249540052,
    1276901417, 1304861917, 1333434672, 1362633090, 1392470869, 1422962010, 1454120821, 1485961921,
    1518500250, 1551751076, 1585730000, 1620452965, 1655936265, 1692196547, 1729250827, 1767116489,
    1805811301, 1845353420, 1885761398, 1927054196, 1969251188, 2012372174, 2056437387, 2101467502,
];

/// `exp2w_tab_long` (rom_basop_util.c).
pub static EXP2W_TAB_LONG: [u32; 32] = [
    1073741824, 1074468888, 1075196443, 1075924492, 1076653033, 1077382068, 1078111597, 1078841619,
    1079572136, 1080303147, 1081034654, 1081766656, 1082499153, 1083232146, 1083965636, 1084699622,
    1085434106, 1086169087, 1086904565, 1087640541, 1088377016, 1089113990, 1089851462, 1090589434,
    1091327906, 1092066877, 1092806349, 1093546322, 1094286796, 1095027771, 1095769248, 1096511227,
];

/// `exp2x_tab_long` (rom_basop_util.c).
pub static EXP2X_TAB_LONG: [u32; 32] = [
    1073741824, 1073764537, 1073787251, 1073809965, 1073832680, 1073855395, 1073878111, 1073900827,
    1073923544, 1073946261, 1073968978, 1073991697, 1074014415, 1074037134, 1074059854, 1074082574,
    1074105294, 1074128015, 1074150737, 1074173459, 1074196181, 1074218904, 1074241627, 1074264351,
    1074287076, 1074309800, 1074332526, 1074355251, 1074377978, 1074400704, 1074423432, 1074446159,
];

/// `SqrtTable` (rom_basop_util.c).
pub static SQRTTABLE: [i32; 32] = [
    1518523433, 1542066430, 1565255397, 1588105840, 1610632162, 1632847777, 1654765196, 1676396113,
    1697751477, 1718841556, 1739675999, 1760263880, 1780613751, 1800733680, 1820631289, 1840313789,
    1859788009, 1879060423, 1898137178, 1917024115, 1935726789, 1954250490, 1972600260, 1990780907,
    2008797024, 2026652997, 2044353024, 2061901118, 2079301127, 2096556738, 2113671487, 2130648768,
];

/// `SqrtDiffTable` (rom_basop_util.c).
pub static SQRTDIFFTABLE: [i16; 32] = [
    22991, 22645, 22315, 21998, 21695, 21404, 21124, 20855, 20596, 20346, 20105, 19873, 19648,
    19431, 19221, 19018, 18821, 18630, 18444, 18264, 18090, 17920, 17755, 17594, 17437, 17285,
    17137, 16992, 16851, 16714, 16579, 16448,
];

/// `ISqrtTable` (rom_basop_util.c).
pub static ISQRTTABLE: [i32; 32] = [
    2147385221, 2114604581, 2083280583, 2053308460, 2024593698, 1997050781, 1970602120, 1945177133,
    1920711450, 1897146228, 1874427557, 1852505940, 1831335837, 1810875272, 1791085476, 1771930586,
    1753377363, 1735394958, 1717954690, 1701029855, 1684595556, 1668628547, 1653107097, 1638010862,
    1623320776, 1609018949, 1595088574, 1581513846, 1568279887, 1555372673, 1542778977, 1530486310,
];

/// `ISqrtDiffTable` (rom_basop_util.c).
pub static ISQRTDIFFTABLE: [i16; 32] = [
    32012, 30590, 29270, 28042, 26897, 25829, 24829, 23892, 23013, 22186, 21408, 20674, 19981,
    19326, 18706, 18118, 17561, 17032, 16528, 16049, 15593, 15158, 14742, 14346, 13967, 13604,
    13257, 12924, 12605, 12299, 12005, 11722,
];

/// `InvTable` (rom_basop_util.c).
pub static INVTABLE: [i32; 32] = [
    2147221056, 2082168974, 2020942198, 1963212986, 1908689993, 1857113354, 1808250548, 1761892889,
    1717852554, 1675960034, 1636061960, 1598019224, 1561705358, 1527005136, 1493813345, 1462033724,
    1431578034, 1402365234, 1374320767, 1347375921, 1321467268, 1296536167, 1272528318, 1249393372,
    1227084573, 1205558446, 1184774516, 1164695048, 1145284825, 1126510937, 1108342598, 1090750977,
];

/// `InvIntTable` (rom_basop_util.c).
pub static INVINTTABLE: [i16; 65] = [
    32767, 32767, 16384, 10923, 8192, 6554, 5461, 4681, 4096, 3641, 3277, 2979, 2731, 2521, 2341,
    2185, 2048, 1928, 1820, 1725, 1638, 1560, 1489, 1425, 1365, 1311, 1260, 1214, 1170, 1130, 1092,
    1057, 1024, 993, 964, 936, 910, 886, 862, 840, 819, 799, 780, 762, 745, 728, 712, 697, 683,
    669, 655, 643, 630, 618, 607, 596, 585, 575, 565, 555, 546, 537, 529, 520, 512,
];

/// `InvDiffTable` (rom_basop_util.c).
pub static INVDIFFTABLE: [i16; 32] = [
    31764, 29896, 28188, 26623, 25184, 23859, 22636, 21504, 20455, 19481, 18576, 17731, 16943,
    16207, 15517, 14871, 14264, 13694, 13157, 12651, 12173, 11723, 11296, 10893, 10511, 10148,
    9804, 9478, 9167, 8871, 8590, 8321,
];

/// `BASOP_util_normReciprocal` (rom_basop_util.c).
pub static BASOP_UTIL_NORMRECIPROCAL: [i32; 161] = [
    0, 2147483647, 1073741824, 715827883, 536870912, 429496730, 357913941, 306783378, 268435456,
    238609294, 214748365, 195225786, 178956971, 165191050, 153391689, 143165577, 134217728,
    126322568, 119304647, 113025455, 107374182, 102261126, 97612893, 93368854, 89478485, 85899346,
    82595525, 79536431, 76695845, 74051160, 71582788, 69273666, 67108864, 65075262, 63161284,
    61356676, 59652324, 58040099, 56512728, 55063683, 53687091, 52377650, 51130563, 49941480,
    48806446, 47721859, 46684427, 45691141, 44739243, 43826197, 42949673, 42107522, 41297762,
    40518559, 39768216, 39045157, 38347922, 37675152, 37025580, 36398028, 35791394, 35204650,
    34636833, 34087042, 33554432, 33038210, 32537631, 32051995, 31580642, 31122951, 30678338,
    30246248, 29826162, 29417584, 29020049, 28633115, 28256364, 27889398, 27531842, 27183337,
    26843546, 26512144, 26188825, 25873297, 25565282, 25264514, 24970740, 24683720, 24403223,
    24129030, 23860929, 23598721, 23342214, 23091222, 22845571, 22605091, 22369621, 22139007,
    21913098, 21691754, 21474836, 21262214, 21053761, 20849356, 20648881, 20452225, 20259280,
    20069941, 19884108, 19701685, 19522579, 19346700, 19173961, 19004280, 18837576, 18673771,
    18512790, 18354561, 18199014, 18046081, 17895697, 17747799, 17602325, 17459217, 17318416,
    17179869, 17043521, 16909320, 16777216, 16647160, 16519105, 16393005, 16268816, 16146494,
    16025997, 15907286, 15790321, 15675063, 15561476, 15449523, 15339169, 15230381, 15123124,
    15017368, 14913081, 14810232, 14708792, 14608732, 14510025, 14412642, 14316558, 14221746,
    14128182, 14035841, 13944699, 13854733, 13765921, 13678240, 13591669, 13506187, 13421773,
];

/// `f_atan_expand_range` (rom_basop_util.c).
pub static F_ATAN_EXPAND_RANGE: [i16; 19] = [
    25480, 25608, 25672, 25704, 25720, 25728, 25732, 25734, 25735, 25735, 25736, 25736, 25736,
    25736, 25736, 25736, 25736, 25736, 25736,
];

/// `SineTable512` (rom_basop_util.c).
#[rustfmt::skip]
pub static SINETABLE512: [PWord16; 257] = [
    PWord16 { v: PWord16V { re: 32767, im: 0 } },
    PWord16 { v: PWord16V { re: 32767, im: 101 } },
    PWord16 { v: PWord16V { re: 32767, im: 201 } },
    PWord16 { v: PWord16V { re: 32767, im: 302 } },
    PWord16 { v: PWord16V { re: 32766, im: 402 } },
    PWord16 { v: PWord16V { re: 32764, im: 503 } },
    PWord16 { v: PWord16V { re: 32762, im: 603 } },
    PWord16 { v: PWord16V { re: 32760, im: 704 } },
    PWord16 { v: PWord16V { re: 32758, im: 804 } },
    PWord16 { v: PWord16V { re: 32756, im: 905 } },
    PWord16 { v: PWord16V { re: 32753, im: 1005 } },
    PWord16 { v: PWord16V { re: 32749, im: 1106 } },
    PWord16 { v: PWord16V { re: 32746, im: 1206 } },
    PWord16 { v: PWord16V { re: 32742, im: 1307 } },
    PWord16 { v: PWord16V { re: 32738, im: 1407 } },
    PWord16 { v: PWord16V { re: 32733, im: 1507 } },
    PWord16 { v: PWord16V { re: 32729, im: 1608 } },
    PWord16 { v: PWord16V { re: 32723, im: 1708 } },
    PWord16 { v: PWord16V { re: 32718, im: 1809 } },
    PWord16 { v: PWord16V { re: 32712, im: 1909 } },
    PWord16 { v: PWord16V { re: 32706, im: 2009 } },
    PWord16 { v: PWord16V { re: 32700, im: 2110 } },
    PWord16 { v: PWord16V { re: 32693, im: 2210 } },
    PWord16 { v: PWord16V { re: 32686, im: 2310 } },
    PWord16 { v: PWord16V { re: 32679, im: 2411 } },
    PWord16 { v: PWord16V { re: 32672, im: 2511 } },
    PWord16 { v: PWord16V { re: 32664, im: 2611 } },
    PWord16 { v: PWord16V { re: 32656, im: 2711 } },
    PWord16 { v: PWord16V { re: 32647, im: 2811 } },
    PWord16 { v: PWord16V { re: 32638, im: 2912 } },
    PWord16 { v: PWord16V { re: 32629, im: 3012 } },
    PWord16 { v: PWord16V { re: 32620, im: 3112 } },
    PWord16 { v: PWord16V { re: 32610, im: 3212 } },
    PWord16 { v: PWord16V { re: 32600, im: 3312 } },
    PWord16 { v: PWord16V { re: 32590, im: 3412 } },
    PWord16 { v: PWord16V { re: 32579, im: 3512 } },
    PWord16 { v: PWord16V { re: 32568, im: 3612 } },
    PWord16 { v: PWord16V { re: 32557, im: 3712 } },
    PWord16 { v: PWord16V { re: 32546, im: 3812 } },
    PWord16 { v: PWord16V { re: 32534, im: 3911 } },
    PWord16 { v: PWord16V { re: 32522, im: 4011 } },
    PWord16 { v: PWord16V { re: 32509, im: 4111 } },
    PWord16 { v: PWord16V { re: 32496, im: 4211 } },
    PWord16 { v: PWord16V { re: 32483, im: 4310 } },
    PWord16 { v: PWord16V { re: 32470, im: 4410 } },
    PWord16 { v: PWord16V { re: 32456, im: 4510 } },
    PWord16 { v: PWord16V { re: 32442, im: 4609 } },
    PWord16 { v: PWord16V { re: 32428, im: 4709 } },
    PWord16 { v: PWord16V { re: 32413, im: 4808 } },
    PWord16 { v: PWord16V { re: 32398, im: 4907 } },
    PWord16 { v: PWord16V { re: 32383, im: 5007 } },
    PWord16 { v: PWord16V { re: 32368, im: 5106 } },
    PWord16 { v: PWord16V { re: 32352, im: 5205 } },
    PWord16 { v: PWord16V { re: 32336, im: 5305 } },
    PWord16 { v: PWord16V { re: 32319, im: 5404 } },
    PWord16 { v: PWord16V { re: 32303, im: 5503 } },
    PWord16 { v: PWord16V { re: 32286, im: 5602 } },
    PWord16 { v: PWord16V { re: 32268, im: 5701 } },
    PWord16 { v: PWord16V { re: 32251, im: 5800 } },
    PWord16 { v: PWord16V { re: 32233, im: 5899 } },
    PWord16 { v: PWord16V { re: 32214, im: 5998 } },
    PWord16 { v: PWord16V { re: 32196, im: 6097 } },
    PWord16 { v: PWord16V { re: 32177, im: 6195 } },
    PWord16 { v: PWord16V { re: 32158, im: 6294 } },
    PWord16 { v: PWord16V { re: 32138, im: 6393 } },
    PWord16 { v: PWord16V { re: 32119, im: 6491 } },
    PWord16 { v: PWord16V { re: 32099, im: 6590 } },
    PWord16 { v: PWord16V { re: 32078, im: 6688 } },
    PWord16 { v: PWord16V { re: 32058, im: 6787 } },
    PWord16 { v: PWord16V { re: 32037, im: 6885 } },
    PWord16 { v: PWord16V { re: 32015, im: 6983 } },
    PWord16 { v: PWord16V { re: 31994, im: 7081 } },
    PWord16 { v: PWord16V { re: 31972, im: 7180 } },
    PWord16 { v: PWord16V { re: 31950, im: 7278 } },
    PWord16 { v: PWord16V { re: 31927, im: 7376 } },
    PWord16 { v: PWord16V { re: 31904, im: 7473 } },
    PWord16 { v: PWord16V { re: 31881, im: 7571 } },
    PWord16 { v: PWord16V { re: 31858, im: 7669 } },
    PWord16 { v: PWord16V { re: 31834, im: 7767 } },
    PWord16 { v: PWord16V { re: 31810, im: 7864 } },
    PWord16 { v: PWord16V { re: 31786, im: 7962 } },
    PWord16 { v: PWord16V { re: 31761, im: 8059 } },
    PWord16 { v: PWord16V { re: 31737, im: 8157 } },
    PWord16 { v: PWord16V { re: 31711, im: 8254 } },
    PWord16 { v: PWord16V { re: 31686, im: 8351 } },
    PWord16 { v: PWord16V { re: 31660, im: 8449 } },
    PWord16 { v: PWord16V { re: 31634, im: 8546 } },
    PWord16 { v: PWord16V { re: 31608, im: 8643 } },
    PWord16 { v: PWord16V { re: 31581, im: 8740 } },
    PWord16 { v: PWord16V { re: 31554, im: 8836 } },
    PWord16 { v: PWord16V { re: 31527, im: 8933 } },
    PWord16 { v: PWord16V { re: 31499, im: 9030 } },
    PWord16 { v: PWord16V { re: 31471, im: 9127 } },
    PWord16 { v: PWord16V { re: 31443, im: 9223 } },
    PWord16 { v: PWord16V { re: 31415, im: 9319 } },
    PWord16 { v: PWord16V { re: 31386, im: 9416 } },
    PWord16 { v: PWord16V { re: 31357, im: 9512 } },
    PWord16 { v: PWord16V { re: 31328, im: 9608 } },
    PWord16 { v: PWord16V { re: 31298, im: 9704 } },
    PWord16 { v: PWord16V { re: 31268, im: 9800 } },
    PWord16 { v: PWord16V { re: 31238, im: 9896 } },
    PWord16 { v: PWord16V { re: 31207, im: 9992 } },
    PWord16 { v: PWord16V { re: 31177, im: 10088 } },
    PWord16 { v: PWord16V { re: 31146, im: 10183 } },
    PWord16 { v: PWord16V { re: 31114, im: 10279 } },
    PWord16 { v: PWord16V { re: 31082, im: 10374 } },
    PWord16 { v: PWord16V { re: 31050, im: 10469 } },
    PWord16 { v: PWord16V { re: 31018, im: 10565 } },
    PWord16 { v: PWord16V { re: 30986, im: 10660 } },
    PWord16 { v: PWord16V { re: 30953, im: 10755 } },
    PWord16 { v: PWord16V { re: 30920, im: 10850 } },
    PWord16 { v: PWord16V { re: 30886, im: 10945 } },
    PWord16 { v: PWord16V { re: 30853, im: 11039 } },
    PWord16 { v: PWord16V { re: 30819, im: 11134 } },
    PWord16 { v: PWord16V { re: 30784, im: 11228 } },
    PWord16 { v: PWord16V { re: 30750, im: 11323 } },
    PWord16 { v: PWord16V { re: 30715, im: 11417 } },
    PWord16 { v: PWord16V { re: 30680, im: 11511 } },
    PWord16 { v: PWord16V { re: 30644, im: 11605 } },
    PWord16 { v: PWord16V { re: 30608, im: 11699 } },
    PWord16 { v: PWord16V { re: 30572, im: 11793 } },
    PWord16 { v: PWord16V { re: 30536, im: 11887 } },
    PWord16 { v: PWord16V { re: 30499, im: 11980 } },
    PWord16 { v: PWord16V { re: 30462, im: 12074 } },
    PWord16 { v: PWord16V { re: 30425, im: 12167 } },
    PWord16 { v: PWord16V { re: 30388, im: 12261 } },
    PWord16 { v: PWord16V { re: 30350, im: 12354 } },
    PWord16 { v: PWord16V { re: 30312, im: 12447 } },
    PWord16 { v: PWord16V { re: 30274, im: 12540 } },
    PWord16 { v: PWord16V { re: 30235, im: 12633 } },
    PWord16 { v: PWord16V { re: 30196, im: 12725 } },
    PWord16 { v: PWord16V { re: 30157, im: 12818 } },
    PWord16 { v: PWord16V { re: 30118, im: 12910 } },
    PWord16 { v: PWord16V { re: 30078, im: 13003 } },
    PWord16 { v: PWord16V { re: 30038, im: 13095 } },
    PWord16 { v: PWord16V { re: 29997, im: 13187 } },
    PWord16 { v: PWord16V { re: 29957, im: 13279 } },
    PWord16 { v: PWord16V { re: 29916, im: 13371 } },
    PWord16 { v: PWord16V { re: 29875, im: 13463 } },
    PWord16 { v: PWord16V { re: 29833, im: 13554 } },
    PWord16 { v: PWord16V { re: 29792, im: 13646 } },
    PWord16 { v: PWord16V { re: 29750, im: 13737 } },
    PWord16 { v: PWord16V { re: 29707, im: 13828 } },
    PWord16 { v: PWord16V { re: 29665, im: 13919 } },
    PWord16 { v: PWord16V { re: 29622, im: 14010 } },
    PWord16 { v: PWord16V { re: 29579, im: 14101 } },
    PWord16 { v: PWord16V { re: 29535, im: 14192 } },
    PWord16 { v: PWord16V { re: 29492, im: 14282 } },
    PWord16 { v: PWord16V { re: 29448, im: 14373 } },
    PWord16 { v: PWord16V { re: 29404, im: 14463 } },
    PWord16 { v: PWord16V { re: 29359, im: 14553 } },
    PWord16 { v: PWord16V { re: 29314, im: 14643 } },
    PWord16 { v: PWord16V { re: 29269, im: 14733 } },
    PWord16 { v: PWord16V { re: 29224, im: 14823 } },
    PWord16 { v: PWord16V { re: 29178, im: 14912 } },
    PWord16 { v: PWord16V { re: 29132, im: 15002 } },
    PWord16 { v: PWord16V { re: 29086, im: 15091 } },
    PWord16 { v: PWord16V { re: 29040, im: 15180 } },
    PWord16 { v: PWord16V { re: 28993, im: 15269 } },
    PWord16 { v: PWord16V { re: 28946, im: 15358 } },
    PWord16 { v: PWord16V { re: 28899, im: 15447 } },
    PWord16 { v: PWord16V { re: 28851, im: 15535 } },
    PWord16 { v: PWord16V { re: 28803, im: 15624 } },
    PWord16 { v: PWord16V { re: 28755, im: 15712 } },
    PWord16 { v: PWord16V { re: 28707, im: 15800 } },
    PWord16 { v: PWord16V { re: 28658, im: 15888 } },
    PWord16 { v: PWord16V { re: 28610, im: 15976 } },
    PWord16 { v: PWord16V { re: 28560, im: 16064 } },
    PWord16 { v: PWord16V { re: 28511, im: 16151 } },
    PWord16 { v: PWord16V { re: 28461, im: 16239 } },
    PWord16 { v: PWord16V { re: 28411, im: 16326 } },
    PWord16 { v: PWord16V { re: 28361, im: 16413 } },
    PWord16 { v: PWord16V { re: 28311, im: 16500 } },
    PWord16 { v: PWord16V { re: 28260, im: 16587 } },
    PWord16 { v: PWord16V { re: 28209, im: 16673 } },
    PWord16 { v: PWord16V { re: 28158, im: 16760 } },
    PWord16 { v: PWord16V { re: 28106, im: 16846 } },
    PWord16 { v: PWord16V { re: 28054, im: 16932 } },
    PWord16 { v: PWord16V { re: 28002, im: 17018 } },
    PWord16 { v: PWord16V { re: 27950, im: 17104 } },
    PWord16 { v: PWord16V { re: 27897, im: 17190 } },
    PWord16 { v: PWord16V { re: 27844, im: 17275 } },
    PWord16 { v: PWord16V { re: 27791, im: 17361 } },
    PWord16 { v: PWord16V { re: 27738, im: 17446 } },
    PWord16 { v: PWord16V { re: 27684, im: 17531 } },
    PWord16 { v: PWord16V { re: 27630, im: 17616 } },
    PWord16 { v: PWord16V { re: 27576, im: 17700 } },
    PWord16 { v: PWord16V { re: 27522, im: 17785 } },
    PWord16 { v: PWord16V { re: 27467, im: 17869 } },
    PWord16 { v: PWord16V { re: 27412, im: 17953 } },
    PWord16 { v: PWord16V { re: 27357, im: 18037 } },
    PWord16 { v: PWord16V { re: 27301, im: 18121 } },
    PWord16 { v: PWord16V { re: 27246, im: 18205 } },
    PWord16 { v: PWord16V { re: 27190, im: 18288 } },
    PWord16 { v: PWord16V { re: 27133, im: 18372 } },
    PWord16 { v: PWord16V { re: 27077, im: 18455 } },
    PWord16 { v: PWord16V { re: 27020, im: 18538 } },
    PWord16 { v: PWord16V { re: 26963, im: 18621 } },
    PWord16 { v: PWord16V { re: 26906, im: 18703 } },
    PWord16 { v: PWord16V { re: 26848, im: 18786 } },
    PWord16 { v: PWord16V { re: 26791, im: 18868 } },
    PWord16 { v: PWord16V { re: 26733, im: 18950 } },
    PWord16 { v: PWord16V { re: 26674, im: 19032 } },
    PWord16 { v: PWord16V { re: 26616, im: 19114 } },
    PWord16 { v: PWord16V { re: 26557, im: 19195 } },
    PWord16 { v: PWord16V { re: 26498, im: 19277 } },
    PWord16 { v: PWord16V { re: 26439, im: 19358 } },
    PWord16 { v: PWord16V { re: 26379, im: 19439 } },
    PWord16 { v: PWord16V { re: 26320, im: 19520 } },
    PWord16 { v: PWord16V { re: 26259, im: 19601 } },
    PWord16 { v: PWord16V { re: 26199, im: 19681 } },
    PWord16 { v: PWord16V { re: 26139, im: 19761 } },
    PWord16 { v: PWord16V { re: 26078, im: 19841 } },
    PWord16 { v: PWord16V { re: 26017, im: 19921 } },
    PWord16 { v: PWord16V { re: 25956, im: 20001 } },
    PWord16 { v: PWord16V { re: 25894, im: 20081 } },
    PWord16 { v: PWord16V { re: 25833, im: 20160 } },
    PWord16 { v: PWord16V { re: 25771, im: 20239 } },
    PWord16 { v: PWord16V { re: 25708, im: 20318 } },
    PWord16 { v: PWord16V { re: 25646, im: 20397 } },
    PWord16 { v: PWord16V { re: 25583, im: 20475 } },
    PWord16 { v: PWord16V { re: 25520, im: 20554 } },
    PWord16 { v: PWord16V { re: 25457, im: 20632 } },
    PWord16 { v: PWord16V { re: 25394, im: 20710 } },
    PWord16 { v: PWord16V { re: 25330, im: 20788 } },
    PWord16 { v: PWord16V { re: 25266, im: 20865 } },
    PWord16 { v: PWord16V { re: 25202, im: 20943 } },
    PWord16 { v: PWord16V { re: 25138, im: 21020 } },
    PWord16 { v: PWord16V { re: 25073, im: 21097 } },
    PWord16 { v: PWord16V { re: 25008, im: 21174 } },
    PWord16 { v: PWord16V { re: 24943, im: 21251 } },
    PWord16 { v: PWord16V { re: 24878, im: 21327 } },
    PWord16 { v: PWord16V { re: 24812, im: 21403 } },
    PWord16 { v: PWord16V { re: 24746, im: 21479 } },
    PWord16 { v: PWord16V { re: 24680, im: 21555 } },
    PWord16 { v: PWord16V { re: 24614, im: 21631 } },
    PWord16 { v: PWord16V { re: 24548, im: 21706 } },
    PWord16 { v: PWord16V { re: 24481, im: 21781 } },
    PWord16 { v: PWord16V { re: 24414, im: 21856 } },
    PWord16 { v: PWord16V { re: 24347, im: 21931 } },
    PWord16 { v: PWord16V { re: 24279, im: 22006 } },
    PWord16 { v: PWord16V { re: 24212, im: 22080 } },
    PWord16 { v: PWord16V { re: 24144, im: 22154 } },
    PWord16 { v: PWord16V { re: 24076, im: 22228 } },
    PWord16 { v: PWord16V { re: 24008, im: 22302 } },
    PWord16 { v: PWord16V { re: 23939, im: 22375 } },
    PWord16 { v: PWord16V { re: 23870, im: 22449 } },
    PWord16 { v: PWord16V { re: 23801, im: 22522 } },
    PWord16 { v: PWord16V { re: 23732, im: 22595 } },
    PWord16 { v: PWord16V { re: 23663, im: 22668 } },
    PWord16 { v: PWord16V { re: 23593, im: 22740 } },
    PWord16 { v: PWord16V { re: 23523, im: 22812 } },
    PWord16 { v: PWord16V { re: 23453, im: 22884 } },
    PWord16 { v: PWord16V { re: 23383, im: 22956 } },
    PWord16 { v: PWord16V { re: 23312, im: 23028 } },
    PWord16 { v: PWord16V { re: 23241, im: 23099 } },
    PWord16 { v: PWord16V { re: 23170, im: 23170 } },
];

/// `SineTable320` (rom_basop_util.c).
pub static SINETABLE320: [PWord16; 161] = [
    PWord16 {
        v: PWord16V { re: 32767, im: 0 },
    },
    PWord16 {
        v: PWord16V { re: 32767, im: 161 },
    },
    PWord16 {
        v: PWord16V { re: 32766, im: 322 },
    },
    PWord16 {
        v: PWord16V { re: 32764, im: 483 },
    },
    PWord16 {
        v: PWord16V { re: 32762, im: 643 },
    },
    PWord16 {
        v: PWord16V { re: 32758, im: 804 },
    },
    PWord16 {
        v: PWord16V { re: 32754, im: 965 },
    },
    PWord16 {
        v: PWord16V {
            re: 32749,
            im: 1126,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32743,
            im: 1286,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32736,
            im: 1447,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32729,
            im: 1608,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32720,
            im: 1768,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32711,
            im: 1929,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32701,
            im: 2090,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32691,
            im: 2250,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32679,
            im: 2411,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32667,
            im: 2571,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32654,
            im: 2731,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32640,
            im: 2892,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32626,
            im: 3052,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32610,
            im: 3212,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32594,
            im: 3372,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32577,
            im: 3532,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32559,
            im: 3692,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32541,
            im: 3851,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32522,
            im: 4011,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32501,
            im: 4171,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32481,
            im: 4330,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32459,
            im: 4490,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32437,
            im: 4649,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32413,
            im: 4808,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32389,
            im: 4967,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32365,
            im: 5126,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32339,
            im: 5285,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32313,
            im: 5444,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32286,
            im: 5602,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32258,
            im: 5760,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32229,
            im: 5919,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32200,
            im: 6077,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32169,
            im: 6235,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32138,
            im: 6393,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32107,
            im: 6550,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32074,
            im: 6708,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32041,
            im: 6865,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 32007,
            im: 7022,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31972,
            im: 7180,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31936,
            im: 7336,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31900,
            im: 7493,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31863,
            im: 7650,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31825,
            im: 7806,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31786,
            im: 7962,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31747,
            im: 8118,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31706,
            im: 8274,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31665,
            im: 8429,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31624,
            im: 8585,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31581,
            im: 8740,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31538,
            im: 8895,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31494,
            im: 9049,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31449,
            im: 9204,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31403,
            im: 9358,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31357,
            im: 9512,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31310,
            im: 9666,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31262,
            im: 9819,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31214,
            im: 9973,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31164,
            im: 10126,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31114,
            im: 10279,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31063,
            im: 10431,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31012,
            im: 10584,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30959,
            im: 10736,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30906,
            im: 10888,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30853,
            im: 11039,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30798,
            im: 11191,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30743,
            im: 11342,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30687,
            im: 11492,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30630,
            im: 11643,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30572,
            im: 11793,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30514,
            im: 11943,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30455,
            im: 12093,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30395,
            im: 12242,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30335,
            im: 12391,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30274,
            im: 12540,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30212,
            im: 12688,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30149,
            im: 12836,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30086,
            im: 12984,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30022,
            im: 13132,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 29957,
            im: 13279,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 29891,
            im: 13426,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 29825,
            im: 13572,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 29758,
            im: 13719,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 29690,
            im: 13865,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 29622,
            im: 14010,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 29553,
            im: 14155,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 29483,
            im: 14300,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 29412,
            im: 14445,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 29341,
            im: 14589,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 29269,
            im: 14733,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 29197,
            im: 14876,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 29123,
            im: 15019,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 29049,
            im: 15162,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 28974,
            im: 15305,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 28899,
            im: 15447,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 28823,
            im: 15588,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 28746,
            im: 15730,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 28668,
            im: 15871,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 28590,
            im: 16011,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 28511,
            im: 16151,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 28431,
            im: 16291,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 28351,
            im: 16430,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 28270,
            im: 16569,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 28188,
            im: 16708,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 28106,
            im: 16846,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 28023,
            im: 16984,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 27939,
            im: 17121,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 27855,
            im: 17258,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 27770,
            im: 17395,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 27684,
            im: 17531,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 27598,
            im: 17666,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 27511,
            im: 17802,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 27423,
            im: 17937,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 27335,
            im: 18071,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 27246,
            im: 18205,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 27156,
            im: 18338,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 27066,
            im: 18472,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 26975,
            im: 18604,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 26883,
            im: 18736,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 26791,
            im: 18868,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 26698,
            im: 18999,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 26604,
            im: 19130,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 26510,
            im: 19261,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 26415,
            im: 19390,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 26320,
            im: 19520,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 26223,
            im: 19649,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 26127,
            im: 19777,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 26029,
            im: 19905,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 25931,
            im: 20033,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 25833,
            im: 20160,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 25733,
            im: 20286,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 25633,
            im: 20413,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 25533,
            im: 20538,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 25432,
            im: 20663,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 25330,
            im: 20788,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 25228,
            im: 20912,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 25125,
            im: 21035,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 25021,
            im: 21159,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 24917,
            im: 21281,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 24812,
            im: 21403,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 24707,
            im: 21525,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 24601,
            im: 21646,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 24494,
            im: 21766,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 24387,
            im: 21886,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 24279,
            im: 22006,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 24171,
            im: 22125,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 24062,
            im: 22243,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 23953,
            im: 22361,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 23843,
            im: 22478,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 23732,
            im: 22595,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 23621,
            im: 22711,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 23509,
            im: 22827,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 23397,
            im: 22942,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 23284,
            im: 23056,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 23170,
            im: 23170,
        },
    },
];

/// `SineWindow10` (rom_basop_util.c).
pub static SINEWINDOW10: [PWord16; 5] = [
    PWord16 {
        v: PWord16V {
            re: 32667,
            im: 2571,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 31863,
            im: 7650,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 30274,
            im: 12540,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 27939,
            im: 17121,
        },
    },
    PWord16 {
        v: PWord16V {
            re: 24917,
            im: 21281,
        },
    },
];
