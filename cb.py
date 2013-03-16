# set UNREAD to False to prove you have read this file.
UNREAD = True

# You can define targets either in CIDR + a list, or as an iteration.
# Comment out targets_iter if you are not using it, or your target range
# will be overwritten by it!
# targets = ['192.168.11.200/24']
targets_iter = ['192.168.11.200', '192.168.11.254']

# -- Options (see scapy documentation for details)
# - for how long you want to wait between sending packets
inter=0
# - for how often you wan to retry
retry=-2
# - and how long you want to wait
timeout=3

# This defines the size of your batches
concurrent=256

# Here you set how many of the top TCP ports you want to scan
toptcpports=7 # all = 4238, taken from http://nmap.org/svn/nmap-services

# -- PROTOCOLS

# which ICMP type you want to send
ICMPtypes = [8,13,15,17]

# which UDP ports you want to connect to (hoping for ICMP response)
UDPports = [161,500,4500,randport]

# -- SNMP
SNMPcommunities=['public','private','0','0392a0','1234','2read','4changes','ANYCOM','Admin','C0de','CISCO','CR52401','IBM','ILMI','Intermec','NoGaH$@!','OrigEquipMfr','PRIVATE','PUBLIC','Private','Public','SECRET','SECURITY','SNMP','SNMP_trap','SUN','SWITCH','SYSTEM','Secret','Security','Switch','System','TENmanUFactOryPOWER','TEST','access','adm','admin','agent','agent_steal','all','all private','all public','apc','bintec','blue','c','cable-d','canon_admin','cc','cisco','community','core','debug','default','dilbert','enable','field','field-service','freekevin','fubar','guest','hello','hp_admin','ibm','ilmi','intermec','internal','l2','l3','manager','mngt','monitor','netman','network','none','openview','pass','password','pr1v4t3','proxy','publ1c','read','read-only','read-write','readwrite','red','regional','rmon','rmon_admin','ro','root','router','rw','rwa','san-fran','sanfran','scotty','secret','security','seri','snmp','snmpd','snmptrap','solaris','sun','superuser','switch','system','tech','test','test2','tiv0li','tivoli','trap','world','write','xyzzy','yellow']

# -- ISAKMP. quite a lot of work to get this working, you might not want to mess with this
ISAKMPports= [500,4500]
ISAKMPtransforms= [[('Encryption', '3DES-CBC'), ('Hash', 'SHA'), ('Authentication', 'PSK'), ('GroupDesc', '1024MODPgr'), ('LifeType', 'Seconds'), ('LifeDuration', 28800L)],[('Encryption', '3DES-CBC'), ('Hash', 'MD5'), ('Authentication', 'PSK'), ('GroupDesc', '1024MODPgr'), ('LifeType', 'Seconds'), ('LifeDuration', 28800L)],[('Encryption', 'DES-CBC'), ('Hash', 'SHA'), ('Authentication', 'PSK'), ('GroupDesc', '1024MODPgr'), ('LifeType', 'Seconds'), ('LifeDuration', 28800L)],[('Encryption', 'DES-CBC'), ('Hash', 'MD5'), ('Authentication', 'PSK'), ('GroupDesc', '1024MODPgr'), ('LifeType', 'Seconds'), ('LifeDuration', 28800L)],[('Encryption', '3DES-CBC'), ('Hash', 'SHA'), ('Authentication', 'PSK'), ('GroupDesc', '768MODPgr'), ('LifeType', 'Seconds'), ('LifeDuration', 28800L)],[('Encryption', '3DES-CBC'), ('Hash', 'MD5'), ('Authentication', 'PSK'), ('GroupDesc', '768MODPgr'), ('LifeType', 'Seconds'), ('LifeDuration', 28800L)],[('Encryption', 'DES-CBC'), ('Hash', 'SHA'), ('Authentication', 'PSK'), ('GroupDesc', '768MODPgr'), ('LifeType', 'Seconds'), ('LifeDuration', 28800L)],[('Encryption', 'DES-CBC'), ('Hash', 'MD5'), ('Authentication', 'PSK'), ('GroupDesc', '768MODPgr'), ('LifeType', 'Seconds'), ('LifeDuration', 28800L)]]
# insane list. Best look at http://nmap.org/svn/nmap-services if you want to update this.
TCPports=[80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,1723,111,995,993,5900,1025,587,8888,199,1720,465,548,113,81,6001,10000,514,5060,179,1026,2000,8443,8000,32768,554,26,1433,49152,2001,515,8008,49154,1027,5666,646,5000,5631,631,49153,8081,2049,88,79,5800,106,2121,1110,49155,6000,513,990,5357,427,49156,543,544,5101,144,7,389,8009,3128,444,9999,5009,7070,5190,3000,5432,1900,3986,13,1029,9,5051,6646,49157,1028,873,1755,2717,4899,9100,119,37,1000,3001,5001,82,10010,1030,9090,2107,1024,2103,6004,1801,5050,19,8031,1041,255,1048,1049,1053,1054,1056,1064,1065,2967,3703,17,808,3689,1031,1044,1071,5901,100,9102,1039,2869,4001,5120,8010,9000,2105,636,1038,2601,1,7000,1066,1069,625,311,280,254,4000,1761,5003,2002,1998,2005,1032,1050,6112,3690,1521,2161,1080,6002,2401,902,4045,787,7937,1058,2383,32771,1033,1040,1059,50000,5555,10001,1494,3,593,2301,3268,7938,1022,1234,1035,1036,1037,1074,8002,9001,464,497,1935,2003,6666,6543,24,1352,3269,1111,407,500,20,2006,1034,1218,3260,15000,4444,264,33,2004,1042,42510,999,3052,1023,222,1068,888,7100,563,1717,992,2008,32770,7001,32772,2007,8082,5550,512,1043,2009,5801,1700,2701,7019,50001,4662,2065,42,2010,161,2602,3333,9535,5100,2604,4002,5002,1047,1051,1052,1055,1060,1062,1311,2702,3283,4443,5225,5226,6059,6789,8089,8192,8193,8194,8651,8652,8701,9415,9593,9594,9595,16992,16993,20828,23502,32769,33354,35500,52869,55555,55600,64623,64680,65000,65389,1067,13782,366,5902,9050,85,1002,5500,1863,1864,5431,8085,10243,45100,49999,51103,49,90,6667,1503,6881,27000,340,1500,8021,2222,5566,8088,8899,9071,1501,5102,6005,9101,9876,32773,32774,163,5679,146,648,1666,901,83,3476,5004,5214,8001,8083,8084,9207,14238,30,912,12345,2030,2605,6,541,4,1248,3005,8007,306,880,2500,1086,1088,1097,2525,4242,8291,9009,52822,900,6101,2809,7200,211,800,987,1083,12000,32775,705,711,20005,6969,13783,1045,1046,1057,1061,1063,1070,1072,1073,1075,1077,1078,1079,1081,1082,1085,1093,1094,1096,1098,1099,1100,1104,1106,1107,1108,1148,1169,1272,1310,1687,1718,1783,1840,1947,2100,2119,2135,2144,2160,2190,2260,2381,2399,2492,2607,2718,2811,2875,3017,3031,3071,3211,3300,3301,3323,3325,3351,3367,3404,3551,3580,3659,3766,3784,3801,3827,3998,4003,4126,4129,4449,5030,5222,5269,5414,5633,5718,5810,5825,5877,5910,5911,5925,5959,5960,5961,5962,5987,5988,5989,6123,6129,6156,6389,6580,6788,6901,7106,7625,7627,7741,7777,7778,7911,8086,8087,8181,8222,8333,8400,8402,8600,8649,8873,8994,9002,9010,9011,9080,9220,9290,9485,9500,9502,9503,9618,9900,9968,10002,10012,10024,10025,10566,10616,10617,10621,10626,10628,10629,11110,11967,13456,14000,14442,15002,15003,15660,16001,16016,16018,17988,19101,19801,19842,20000,20031,20221,20222,21571,22939,24800,25734,27715,28201,30000,30718,31038,32781,32782,33899,34571,34572,34573,40193,48080,49158,49159,49160,50003,50006,50800,57294,58080,60020,63331,65129,89,691,212,1001,1999,2020,32776,2998,6003,7002,50002,32,898,2033,3372,5510,99,425,749,5903,43,458,5405,6106,6502,7007,13722,1087,1089,1124,1152,1183,1186,1247,1296,1334,1580,1782,2126,2179,2191,2251,2522,3011,3030,3077,3261,3369,3370,3371,3493,3546,3737,3828,3851,3871,3880,3918,3995,4006,4111,4446,5054,5200,5280,5298,5822,5859,5904,5915,5922,5963,7103,7402,7435,7443,7512,8011,8090,8100,8180,8254,8500,8654,9091,9110,9666,9877,9943,9944,9998,10004,10778,15742,16012,18988,19283,19315,19780,24444,27352,27353,27355,32784,49163,49165,49175,50389,50636,51493,55055,56738,61532,61900,62078,1021,9040,32777,32779,616,666,700,2021,32778,84,545,1112,1524,2040,4321,5802,38292,49400,1084,1600,2048,2111,3006,32780,2638,6547,6699,9111,16080,555,667,720,801,1443,1533,2034,2106,5560,6007,1090,1091,1114,1117,1119,1122,1131,1138,1151,1175,1199,1201,1271,1862,2323,2393,2394,2608,2725,2909,3003,3168,3221,3322,3324,3390,3517,3527,3800,3809,3814,3826,3869,3878,3889,3905,3914,3920,3945,3971,4004,4005,4279,4445,4550,4567,4848,4900,5033,5061,5080,5087,5221,5440,5544,5678,5730,5811,5815,5850,5862,5906,5907,5950,5952,6025,6100,6510,6565,6566,6567,6689,6692,6779,6792,6839,7025,7496,7676,7800,7920,7921,7999,8022,8042,8045,8093,8099,8200,8290,8292,8300,8383,8800,9003,9081,9099,9200,9418,9575,9878,9898,9917,10003,10009,10180,10215,11111,12174,12265,14441,15004,16000,16113,17877,18040,18101,19350,25735,26214,27356,30951,32783,32785,40911,41511,44176,44501,49161,49167,49176,50300,50500,52673,52848,54045,54328,55056,56737,57797,60443,70,417,617,714,722,777,981,1009,2022,4224,4998,6346,301,524,668,765,1076,2041,5999,10082,259,416,1007,1417,1434,1984,2038,2068,4343,6009,7004,44443,109,687,726,911,1010,1461,2035,2046,4125,6006,7201,9103,125,481,683,903,1011,1455,2013,2043,2047,6668,6669,256,406,783,843,2042,2045,5998,9929,31337,44442,1092,1095,1102,1105,1113,1121,1123,1126,1130,1132,1137,1141,1145,1147,1149,1154,1163,1164,1165,1166,1174,1185,1187,1192,1198,1213,1216,1217,1233,1236,1244,1259,1277,1287,1300,1301,1309,1322,1328,1556,1583,1594,1641,1658,1688,1719,1721,1805,1812,1839,1875,1914,1971,1972,1974,2099,2170,2196,2200,2288,2366,2382,2557,2710,2800,2910,2920,2968,3007,3013,3050,3119,3162,3304,3307,3376,3400,3410,3514,3684,3697,3700,3731,3792,3808,3820,3824,3846,3848,3849,3852,3853,3859,3863,3870,3872,3888,3907,3916,3929,3931,3941,3944,3957,3963,3968,3969,3972,3981,3990,3993,3994,4009,4040,4080,4096,4143,4147,4164,4200,4252,4430,4555,4600,4658,4875,4949,5040,5063,5074,5081,5151,5212,5223,5242,5279,5339,5353,5501,5807,5812,5818,5823,5868,5869,5899,5905,5909,5914,5918,5938,5940,5968,5981,6051,6060,6068,6203,6247,6481,6500,6504,6520,6550,6600,6711,6732,6896,7024,7050,7051,7080,7123,7241,7272,7278,7281,7438,7725,7744,7749,7770,7878,7900,7913,7929,8015,8016,8019,8050,8095,8097,8098,8189,8293,8294,8385,8481,8540,8648,8675,8676,8686,8765,8766,8877,8889,8987,8996,9098,9191,9197,9198,9409,9443,9444,9501,9600,9621,9643,9673,9815,9914,9941,9988,10008,10011,10022,10023,10034,10058,10160,10873,12006,12021,12059,12215,12262,12380,12452,13724,15001,15402,16705,16800,16851,17595,18018,18264,19900,20002,21792,22222,23052,23796,26000,26470,27357,28211,29672,29831,30005,30704,31727,32791,32792,32803,32816,32822,32835,33453,33554,35513,37839,38185,38188,39136,39376,39659,40000,40811,41064,41523,44709,46200,46996,47544,49164,49168,49171,49186,49195,49236,49401,50050,51191,51413,52660,52710,52735,52847,52849,52850,52851,52853,53211,53313,53314,53535,55020,55576,57665,58001,58002,58630,58632,58838,59110,59200,59201,59202,60123,60146,60642,61613,65310,502,623,639,701,710,725,780,803,913,930,1103,1109,1220,1347,2012,2232,2241,2501,4559,5680,6222,10005,27,86,102,123,250,419,441,442,447,475,540,856,874,931,953,1158,1222,1270,2044,5010,8118,9992,18000,55,57,87,210,223,251,556,709,713,829,980,1008,1013,1212,1550,2433,2628,3025,3299,5520,5803,6008,6103,7003,9152,10083,77,127,157,220,333,523,557,610,657,674,684,732,748,792,825,840,904,943,1006,1020,1241,1350,1351,1516,1526,1547,2011,2067,4333,7010,225,257,600,602,655,659,660,729,730,731,757,778,782,786,790,795,822,823,839,846,862,905,969,971,996,998,1012,1014,1015,1353,1357,1522,2025,2201,2903,3399,3456,3632,6050,6662,59,98,252,388,411,606,621,641,669,690,715,728,740,754,758,802,805,806,859,864,878,918,921,922,924,928,1004,1005,1127,1337,1413,1414,1525,2112,2600,3999,5011,6017,6670,12346,38037,44334,1101,1116,1118,1125,1128,1134,1135,1136,1143,1144,1150,1153,1156,1157,1159,1162,1167,1168,1173,1176,1179,1180,1182,1184,1188,1190,1191,1194,1195,1196,1200,1204,1207,1208,1209,1210,1211,1215,1221,1223,1228,1229,1239,1240,1243,1249,1250,1251,1261,1262,1264,1268,1276,1279,1282,1290,1291,1297,1299,1302,1303,1305,1306,1307,1308,1314,1315,1316,1317,1318,1319,1321,1324,1327,1330,1331,1336,1339,1340,1558,1559,1560,1565,1566,1569,1584,1592,1598,1605,1607,1615,1620,1622,1632,1635,1638,1645,1677,1683,1691,1694,1699,1701,1703,1707,1708,1709,1711,1712,1713,1715,1722,1730,1735,1736,1745,1750,1752,1753,1791,1792,1799,1800,1806,1807,1808,1811,1823,1825,1835,1858,1861,1871,1901,1911,1912,1918,1924,1927,1954,1958,1973,1975,1976,1981,2031,2062,2069,2070,2080,2081,2082,2083,2086,2087,2095,2096,2101,2104,2115,2124,2134,2142,2148,2150,2187,2197,2203,2224,2250,2253,2261,2262,2265,2269,2270,2271,2280,2291,2292,2300,2302,2304,2312,2313,2325,2326,2330,2335,2340,2371,2372,2391,2418,2425,2435,2436,2438,2439,2449,2456,2463,2472,2505,2531,2532,2550,2551,2558,2567,2580,2583,2584,2598,2606,2622,2623,2631,2644,2691,2700,2706,2711,2712,2723,2728,2734,2804,2806,2812,2847,2850,2882,2888,2889,2898,2901,2902,2908,2930,2957,2958,2973,2984,2987,2988,2991,2997,3002,3014,3023,3057,3062,3063,3080,3089,3102,3103,3118,3121,3146,3167,3190,3200,3210,3220,3240,3263,3280,3281,3291,3310,3311,3319,3334,3362,3363,3365,3368,3374,3388,3396,3414,3415,3419,3425,3430,3439,3443,3479,3483,3485,3486,3497,3503,3505,3506,3511,3513,3515,3519,3520,3526,3530,3532,3577,3586,3599,3600,3602,3603,3621,3622,3636,3637,3652,3653,3656,3658,3663,3669,3670,3672,3680,3681,3683,3712,3728,3742,3749,3765,3787,3788,3790,3793,3795,3796,3798,3799,3803,3806,3810,3811,3812,3813,3817,3823,3825,3830,3831,3837,3839,3842,3847,3850,3856,3860,3868,3876,3879,3882,3890,3897,3899,3901,3902,3904,3906,3908,3909,3911,3913,3915,3919,3922,3923,3928,3930,3935,3936,3937,3940,3943,3946,3948,3949,3952,3956,3961,3962,3964,3967,3975,3979,3980,3982,3983,3989,3991,3992,3996,3997,4007,4010,4016,4020,4022,4024,4025,4029,4035,4036,4039,4056,4058,4065,4087,4090,4100,4101,4112,4113,4118,4119,4120,4121,4135,4141,4158,4161,4174,4190,4192,4206,4220,4234,4262,4294,4297,4298,4300,4302,4325,4328,4342,4355,4356,4357,4358,4369,4374,4375,4376,4384,4388,4401,4407,4414,4415,4418,4433,4442,4447,4454,4464,4471,4476,4516,4517,4530,4534,4545,4558,4570,4599,4601,4602,4606,4609,4644,4649,4665,4687,4689,4700,4712,4745,4760,4767,4770,4771,4778,4793,4800,4819,4859,4860,4876,4877,4881,4903,4912,4931,4999,5005,5012,5013,5014,5015,5016,5017,5020,5021,5023,5052,5053,5055,5066,5070,5088,5090,5095,5096,5098,5111,5114,5121,5122,5125,5133,5137,5147,5152,5201,5202,5219,5233,5234,5235,5250,5252,5259,5261,5291,5347,5370,5377,5423,5433,5441,5442,5444,5457,5458,5473,5475,5502,5552,5553,5554,5557,5580,5581,5611,5612,5620,5621,5622,5665,5667,5672,5711,5721,5722,5723,5732,5734,5737,5804,5806,5808,5814,5817,5820,5821,5824,5826,5827,5831,5834,5836,5838,5839,5840,5845,5848,5849,5852,5853,5854,5858,5860,5871,5874,5875,5878,5881,5887,5888,5908,5912,5917,5920,5921,5923,5924,5926,5927,5931,5934,5936,5939,5945,5948,5949,5953,5954,5958,5966,5969,5971,5974,5975,6010,6015,6021,6030,6052,6055,6062,6063,6065,6067,6077,6085,6090,6091,6113,6115,6120,6126,6161,6250,6251,6259,6273,6274,6309,6310,6323,6324,6349,6350,6412,6503,6535,6579,6606,6628,6644,6647,6650,6709,6710,6725,6734,6780,6877,6888,6897,6920,6922,6942,6956,6972,6973,7033,7043,7067,7068,7071,7072,7092,7099,7101,7102,7104,7119,7121,7184,7218,7231,7300,7320,7325,7345,7400,7451,7456,7500,7501,7553,7555,7600,7628,7637,7654,7685,7688,7771,7772,7780,7788,7789,7813,7830,7852,7853,7854,7895,7975,7998,8003,8005,8006,8014,8018,8023,8025,8029,8037,8052,8060,8064,8092,8110,8116,8133,8144,8201,8202,8232,8245,8248,8255,8268,8273,8282,8295,8308,8339,8401,8403,8409,8445,8451,8452,8453,8454,8455,8470,8471,8472,8474,8477,8479,8484,8515,8530,8531,8539,8562,8601,8621,8640,8644,8655,8658,8673,8680,8736,8752,8756,8772,8790,8798,8801,8843,8865,8878,8879,8880,8882,8887,8898,8900,8925,8954,8980,8999,9004,9005,9013,9020,9021,9022,9037,9044,9061,9065,9084,9125,9128,9130,9131,9133,9160,9161,9170,9183,9202,9210,9211,9287,9300,9343,9351,9364,9400,9454,9464,9478,9493,9513,9527,9583,9592,9613,9616,9619,9620,9628,9648,9654,9661,9665,9667,9674,9679,9680,9683,9694,9700,9745,9777,9812,9814,9823,9825,9826,9830,9844,9875,9901,9908,9909,9910,9911,9912,9915,9919,9950,9971,9975,9979,9990,9995,10006,10007,10018,10019,10020,10035,10042,10045,10064,10093,10101,10115,10238,10245,10246,10255,10280,10338,10347,10357,10387,10414,10443,10494,10500,10509,10529,10535,10550,10551,10552,10553,10554,10555,10556,10565,10567,10601,10602,10699,10754,10842,10852,10878,10900,11000,11001,11003,11007,11019,11026,11031,11032,11033,11089,11100,11180,11200,11224,11250,11288,11296,11401,11552,11697,11735,11813,11862,11863,11940,12001,12002,12005,12009,12019,12031,12034,12077,12080,12090,12096,12097,12121,12132,12137,12146,12156,12171,12192,12225,12240,12243,12251,12271,12275,12296,12340,12414,12699,12702,12766,12865,12891,12892,12955,12962,13017,13093,13130,13132,13140,13142,13149,13167,13188,13192,13193,13194,13229,13250,13261,13264,13265,13306,13318,13340,13359,13502,13580,13695,13723,13730,13766,13784,13846,13899,14001,14147,14218,14237,14254,14418,14443,14444,14534,14545,14693,14733,14827,14891,14916,15005,15050,15145,15190,15191,15275,15317,15344,15448,15550,15631,15645,15646,15670,15677,15722,15730,15758,15915,16048,16161,16270,16273,16283,16286,16297,16349,16372,16464,16723,16724,16725,16797,16845,16900,16901,17016,17017,17070,17089,17129,17251,17255,17409,17413,17700,17701,17702,17715,17801,17802,17860,17867,17969,17985,17997,18012,18015,18080,18148,18231,18336,18337,18380,18439,18505,18517,18569,18669,18874,18887,18910,18962,19010,19130,19200,19201,19353,19403,19464,19501,19612,19634,19715,19852,19995,19996,20001,20011,20017,20021,20032,20039,20052,20076,20080,20085,20089,20102,20106,20111,20118,20125,20127,20147,20179,20180,20223,20224,20225,20226,20227,20228,20280,20473,20734,20883,20934,20940,20990,21011,21078,21473,21631,21634,21728,21891,21915,22022,22063,22100,22125,22128,22177,22200,22223,22290,22341,22350,22555,22563,22711,22719,22727,22769,22882,22959,22969,23017,23040,23219,23228,23270,23296,23342,23382,23430,23451,23723,23887,23953,24218,24392,24416,24552,24554,24616,24999,25000,25001,25174,25260,25262,25288,25327,25445,25473,25486,25565,25703,25717,25847,26001,26007,26340,26417,26669,26972,27015,27016,27055,27074,27075,27087,27204,27316,27350,27351,27372,27521,27537,27770,28114,28142,28374,28567,28717,28850,28851,28924,28967,29045,29152,29243,29507,29810,30001,30087,30195,30299,30519,30599,30644,30659,30705,30896,31033,31058,31072,31339,31386,31438,31522,31657,31728,32006,32022,32031,32088,32102,32200,32219,32260,32261,32764,32765,32767,32788,32789,32790,32797,32798,32799,32807,32814,32815,32820,32837,32842,32858,32868,32869,32871,32888,32897,32898,32904,32905,32908,32910,32911,32932,32944,32960,32961,32976,33000,33011,33017,33070,33087,33124,33175,33192,33200,33203,33277,33327,33335,33337,33367,33395,33444,33522,33523,33550,33604,33605,33841,33879,33882,33889,33895,34021,34036,34096,34189,34317,34341,34381,34401,34507,34510,34683,34728,34765,34783,34833,34875,35033,35050,35116,35131,35217,35272,35349,35392,35393,35401,35506,35553,35593,35731,35879,35900,35901,35906,35929,35986,36046,36104,36105,36256,36275,36368,36436,36508,36530,36552,36659,36677,36694,36710,36748,36823,36824,36914,36950,36962,36983,37121,37151,37174,37185,37218,37393,37522,37607,37614,37647,37674,37777,37789,37855,38029,38194,38205,38224,38270,38313,38331,38358,38446,38481,38546,38561,38570,38761,38764,38780,38805,38936,39067,39117,39265,39293,39380,39433,39482,39489,39630,39732,39763,39774,39795,39869,39883,39895,39917,40001,40002,40003,40005,40011,40306,40393,40400,40457,40489,40513,40614,40628,40712,40732,40754,40812,40834,40951,41123,41142,41250,41281,41318,41342,41345,41348,41398,41442,41551,41632,41773,41794,41795,41808,42001,42035,42127,42158,42251,42276,42322,42449,42452,42559,42560,42575,42590,42632,42675,42679,42685,42735,42906,42990,43000,43002,43018,43027,43103,43139,43143,43212,43231,43242,43425,43654,43690,43734,43823,43868,44004,44101,44119,44200,44380,44410,44431,44479,44505,44541,44616,44628,44704,44711,44965,44981,45038,45050,45136,45164,45220,45226,45413,45438,45463,45602,45624,45697,45777,45864,45960,46034,46069,46115,46171,46182,46310,46372,46418,46436,46593,46813,46992,47012,47029,47119,47197,47267,47348,47372,47448,47567,47581,47595,47624,47634,47700,47777,47806,47850,47858,47860,47966,47969,48009,48067,48083,48127,48153,48167,48356,48434,48619,48631,48648,48682,48783,48813,48925,48966,48967,48973,49002,49048,49132,49166,49169,49170,49172,49173,49179,49189,49190,49191,49196,49197,49201,49202,49203,49204,49211,49213,49216,49228,49232,49235,49241,49275,49302,49352,49372,49398,49452,49498,49500,49519,49520,49521,49522,49597,49603,49678,49751,49762,49765,49803,49927,50016,50019,50040,50101,50189,50198,50202,50205,50224,50246,50258,50277,50356,50513,50529,50545,50576,50577,50585,50692,50733,50787,50809,50815,50831,50833,50834,50835,50836,50849,50854,50887,50903,50945,50997,51011,51020,51037,51067,51118,51139,51233,51234,51235,51240,51300,51343,51351,51366,51423,51460,51484,51485,51488,51515,51582,51658,51771,51772,51800,51809,51906,51909,51961,51965,52000,52001,52002,52003,52025,52046,52071,52173,52225,52226,52230,52237,52262,52391,52477,52506,52573,52665,52675,52893,52948,53085,53178,53189,53212,53240,53319,53361,53370,53460,53469,53491,53633,53639,53656,53690,53742,53782,53827,53852,53910,53958,54075,54101,54127,54235,54263,54276,54321,54323,54514,54551,54605,54658,54688,54722,54741,54873,54907,54987,54991,55000,55183,55187,55227,55312,55350,55382,55400,55426,55479,55527,55556,55568,55569,55579,55635,55652,55684,55721,55758,55773,55781,55901,55907,55910,55948,56016,56055,56259,56293,56507,56535,56591,56668,56681,56723,56725,56810,56822,56827,56973,56975,57020,57103,57123,57325,57335,57347,57350,57352,57387,57398,57479,57576,57678,57681,57702,57730,57733,57891,57896,57923,57928,57988,57999,58072,58107,58109,58164,58252,58305,58310,58374,58430,58446,58456,58468,58498,58562,58570,58610,58622,58634,58699,58721,58908,58970,58991,59087,59107,59122,59149,59160,59191,59239,59340,59499,59504,59509,59510,59525,59565,59684,59778,59810,59829,59841,59987,60000,60002,60003,60055,60086,60111,60177,60227,60243,60279,60377,60401,60403,60485,60492,60504,60544,60579,60612,60621,60628,60713,60728,60743,60753,60782,60783,60789,60794,60989,61159,61169,61170,61402,61473,61516,61616,61617,61669,61722,61734,61827,61851,61942,62006,62042,62080,62188,62312,62519,62570,62674,62866,63105,63156,63423,63675,63803,64080,64127,64320,64438,64507,64551,64726,64727,64890,65048,65311,65488,65514,11,47,66,400,446,509,578,591,635,642,678,706,743,762,769,779,789,809,811,815,817,830,834,844,858,863,914,925,926,935,942,961,965,967,973,979,983,1019,1441,1444,1492,1495,1507,1989,3985,4008,5308,5632,5977,6105,7005,22273,27001,31416,32786,32787,54320,10,12,52,68,75,76,91,101,104,122,158,219,237,440,449,501,510,525,538,577,603,615,620,629,634,649,653,664,665,682,695,707,716,727,733,750,771,798,804,807,810,814,824,828,833,835,847,860,861,889,894,897,899,916,923,946,949,952,958,974,984,985,989,1139,1358,1359,1364,1366,1420,1652,1663,1680,3045,3049,3064,3398,4199,6110,9991,27010,16,28,45,50,92,112,221,230,249,268,300,334,343,353,448,450,456,491,492,507,605,609,627,630,632,638,640,647,651,658,661,663,673,696,702,719,724,735,736,741,745,760,761,791,813,816,819,820,826,831,836,841,850,851,855,866,870,872,875,881,883,906,919,927,929,936,938,941,945,948,950,962,988,1016,1018,1178,1214,1346,1349,1356,1370,1384,1385,1388,1389,1399,1400,1402,1404,1445,1465,1474,1484,1517,1523,1551,1552,1651,1988,1991,2014,2018,2024,2120,2307,2430,3086,3900,4557,4660,5145,5191,5232,5300,5400,5978,6347,6401,6665,7273,7597,8076,9104,27374,14,15,35,40,51,60,69,97,103,137,180,182,194,201,213,214,231,253,262,402,454,505,511,553,560,561,611,622,624,628,633,637,644,654,656,670,675,676,680,681,685,689,692,694,703,704,708,718,721,723,734,751,756,770,788,794,796,797,799,812,821,832,837,854,867,868,869,879,886,891,895,909,933,939,944,947,951,959,960,963,964,968,970,975,991,994,997,1003,1017,1348,1354,1369,1372,1373,1379,1381,1387,1401,1403,1405,1412,1435,1466,1467,1475,1476,1486,1496,1497,1515,1527,1535,1539,1650,1664,1668,1762,1995,1996,1997,2015,2026,2064,3141,3264,3292,3397,4480,4500,5530,6143,6588,6701,7009,8123,8892,9105,9106,9107,11371,13720,14141,18182,18184,27665,47557,29,31,34,38,44,58,71,73,74,93,94,95,114,115,118,120,129,133,136,138,176,177,181,193,196,200,202,204,206,224,233,235,236,260,261,273,276,303,308,315,325,336,350,355,362,397,399,401,403,404,410,412,415,418,422,437,453,462,466,486,493,536,568,601,604,607,608,619,626,645,672,677,686,688,697,698,699,712,717,737,738,746,747,755,759,763,764,774,776,784,785,793,818,827,838,842,848,849,852,853,857,865,871,876,877,882,884,885,887,890,892,907,908,915,920,934,956,957,966,972,978,982,1355,1362,1365,1368,1376,1386,1390,1393,1394,1397,1398,1409,1410,1422,1424,1426,1432,1436,1437,1438,1439,1442,1446,1454,1456,1472,1479,1483,1493,1498,1499,1510,1511,1513,1519,1528,1529,1531,1537,1538,1544,1545,1548,1549,1661,1662,1667,1763,1827,1986,1990,1992,1994,2023,2027,2053,2431,2432,2627,3457,3531,4132,4144,5301,5302,5997,6111,6142,6145,6146,6147,6400,6544,6700,7006,7008,7634,8770,9051,13713,16444,18181,18183,26208,65301,2,8,48,54,56,65,67,72,96,108,116,117,124,128,130,132,141,142,148,149,150,151,162,168,173,174,184,185,189,190,191,192,205,209,216,217,226,228,229,234,238,248,258,265,267,270,271,277,284,288,289,293,294,295,305,316,322,326,329,337,346,351,352,358,360,361,364,369,370,373,380,383,391,392,408,413,414,420,423,428,432,434,435,438,439,451,452,457,460,470,472,473,479,480,485,487,496,516,518,522,526,528,530,533,535,542,552,564,569,570,571,572,582,583,596,598,599,612,613,614,618,643,652,662,739,742,744,752,753,766,767,768,773,775,781,845,893,896,910,932,937,954,955,976,977,986,1360,1361,1363,1367,1371,1374,1383,1391,1395,1396,1407,1408,1411,1416,1418,1419,1423,1427,1429,1430,1440,1448,1449,1451,1453,1457,1458,1459,1462,1464,1469,1470,1473,1480,1482,1488,1491,1502,1505,1508,1509,1518,1532,1540,1541,1542,1543,1670,1671,1672,1987,1993,2016,2019,2028,2108,2564,2766,3421,3984,4133,4672,4987,5193,5303,5490,5713,5714,5717,6141,6548,7326,7464,13701,13714,13715,13718,13721,15151,17007,17300,18187,19150,27002,27003,27005,27007,27009,43188]

# Function to support timestamps
from datetime import datetime
timestamp = datetime.now().strftime("%Y%m%d.%H%M%S")
database = timestamp + '.barentsz.db'
import random
randport = random.randrange(1025,65535)