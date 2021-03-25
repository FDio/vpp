commit f49f397958729d2501b40cc8429248f92954c395
Author: Andrew Yourtchenko <ayourtch@gmail.com>
Date:   Thu Mar 25 10:29:51 2021 +0000

    WIP: add libfuzzer-enabled VPP build
    
    This is just to capture something that I got working.
    
    warning: Looking at the diff will make you cringe and swear and cry.
    Everything in the 1km radius of the it displayed on the screen can be affected.
    
    Rationale:
    
    libfuzzer is awesome but it wants smaller chunks of code. While its undoubtedly
    obvious that making pieces of VPP code individually linkable to a fuzz driver
    is definitely a positive constraint that will improve the code quality by itself,
    we live in the real world and would be nice to have a lower barrier to entry.
    
    So, this contraption was born.
    
    The idea is:
    
    1) link the entire VPP with libfuzzer, BUT intercept the libfuzzer's main
    and do not run it, instead run the regular VPP main for initialization of
    all the global state
    
    2) provide per-module fuzz drivers that will test the piece of VPP code
    without ripping it out of VPP proper, and possibly with using some not-so-nonsensical
    global state.
    
    3) provide a CLI that will first change the pointer to the fuzzer driver to
    be that specialized one, and then call the previously fuzzer's main() to initialize
    and drive the fuzzer.
    
    4) profit!
    
    This change captures the certain success while being at stage (1).
    
    I compiled this with:
    
    VPP_EXTRA_CMAKE_ARGS=-DVPP_ENABLE_FUZZER=ON -DVPP_USE_LTO=OFF
    
    as "make debug"
    
    LD_LIBRARY_PATH=${HOME}/vpp/build-root/install-vpp_debug-native/vpp/lib/ ${HOME}/vpp/build-root/build-vpp_debug-native/vpp/bin/vpp  "unix { interactive cli-listen /tmp/vpp-api-cli.sock } plugins { plugin dpdk_plugin.so { disable } } socksvr { socket-name /tmp/api.sock }"
    
    The result will be:
    
    yourtch@ayourtch-lnx:~/vpp$ LD_LIBRARY_PATH=${HOME}/vpp/build-root/install-vpp_debug-native/vpp/lib/ ${HOME}/vpp/build-root/build-vpp_debug-native/vpp/bin/vpp  "unix { interactive cli-listen /tmp/vpp-api-cli.sock } plugins { plugin dpdk_plugin.so { disable } } socksvr { socket-name /tmp/api.sock }"
    clib_sysfs_prealloc_hugepages:261: pre-allocating 19 additional 2048K hugepages on numa node 0
    buffer      [warn  ]: numa[0] falling back to non-hugepage backed buffer pool (vlib_physmem_shared_map_create: pmalloc_map_pages: failed to mmap 19 pages at 0x1000000000 fd 5 numa 0 flags 0x11: Cannot allocate memory)
    perfmon              [warn  ]: skipping source 'intel-uncore' - intel_uncore_init: no uncore units found
    vat-plug/load        [error ]: vat_plugin_register: oddbuf plugin not loaded...
        _______    _        _   _____  ___
     __/ __/ _ \  (_)__    | | / / _ \/ _ \
     _/ _// // / / / _ \   | |/ / ___/ ___/
     /_/ /____(_)_/\___/   |___/_/  /_/
    
    DBGvpp# fuzz-test
    acl_clear_aclplugin_fn:145: fuzzing...
    INFO: Seed: 4138520444
    INFO: Loaded 103 modules   (565769 inline 8-bit counters): 16173 [0x7f5203333788, 0x7f52033376b5), 3218 [0x7f520362a8a8, 0x7f520362b53a), 17651 [0x7f5203a76e30, 0x7f5203a7b323), 267933 [0x7f5205fdeb50, 0x7f52060201ed), 4798 [0x7f52066ff488, 0x7f5206700746), 13110 [0x7c88a8, 0x7cbbde), 1187 [0x7f51c2757881, 0x7f51c2757d24), 10051 [0x7f51c25055d0, 0x7f51c2507d13), 1197 [0x7f51c21c3978, 0x7f51c21c3e25), 5309 [0x7f51c1f85b18, 0x7f51c1f86fd5), 273 [0x7f51c1cd91f0, 0x7f51c1cd9301), 1355 [0x7f51c1ac8b39, 0x7f51c1ac9084), 5770 [0x7f51c18779f1, 0x7f51c187907b), 415 [0x7f51c15aacd9, 0x7f51c15aae78), 1318 [0x7f51bfa7d2d0, 0x7f51bfa7d7f6), 335 [0x7f51bf842419, 0x7f51bf842568), 484 [0x7f51bf62c3d9, 0x7f51bf62c5bd), 2658 [0x7f51bf40d918, 0x7f51bf40e37a), 764 [0x7f51beee1380, 0x7f51beee167c), 4487 [0x7f51bf18d2e0, 0x7f51bf18e467), 8123 [0x7f51bec9cf70, 0x7f51bec9ef2b), 529 [0x7f51be9833c1, 0x7f51be9835d2), 2873 [0x7f51be760e89, 0x7f51be7619c2), 4027 [0x7f51be4e9f98, 0x7f51be4eaf53), 1660 [0x7f51be25ac81, 0x7f51be25b2fd), 13845 [0x7f51bdfe2d20, 0x7f51bdfe6335), 4870 [0x7f51bdc071d0, 0x7f51bdc084d6), 5054 [0x7f51bd94c3b0, 0x7f51bd94d76e), 2879 [0x7f51bd68db28, 0x7f51bd68e667), 1585 [0x7f51bd41a759, 0x7f51bd41ad8a), 3895 [0x7f51bd1d5171, 0x7f51bd1d60a8), 5995 [0x7f51bcf2d979, 0x7f51bcf2f0e4), 528 [0x7f51bcc5c6b9, 0x7f51bcc5c8c9), 12325 [0x7f51bca13050, 0x7f51bca16075), 847 [0x7f51bc636690, 0x7f51bc6369df), 2430 [0x7f51bc410c18, 0x7f51bc411596), 693 [0x7f51bc1b9580, 0x7f51bc1b9835), 2128 [0x7f51bbf97269, 0x7f51bbf97ab9), 2517 [0x7f51bbd322b0, 0x7f51bbd32c85), 12868 [0x7f51bbaa66d8, 0x7f51bbaa991c), 2055 [0x7f51bb6fbaa8, 0x7f51bb6fc2af), 1159 [0x7f51bb4a28e9, 0x7f51bb4a2d70), 3669 [0x7f51bb264970, 0x7f51bb2657c5), 610 [0x7f51bafd9439, 0x7f51bafd969b), 7091 [0x7f51bada3d80, 0x7f51bada5933), 771 [0x7f51baab0a58, 0x7f51baab0d5b), 14164 [0x7f51ba85bb90, 0x7f51ba85f2e4), 8067 [0x7f51ba463aa0, 0x7f51ba465a23), 1931 [0x7f51ba14d8f0, 0x7f51ba14e07b), 18199 [0x7f51b9ebcf08, 0x7f51b9ec161f), 7000 [0x7f51b9a5a0e8, 0x7f51b9a5bc40), 1738 [0x7f51b9739848, 0x7f51b9739f12), 1396 [0x7f51b94f7400, 0x7f51b94f7974), 907 [0x7f51b92bd6b9, 0x7f51b92bda44), 2038 [0x7f51b9090a08, 0x7f51b90911fe), 3187 [0x7f51b8e38c48, 0x7f51b8e398bb), 5296 [0x7f51b8ba9db8, 0x7f51b8bab268), 691 [0x7f51b88996e9, 0x7f51b889999c), 435 [0x7f51b867c589, 0x7f51b867c73c), 712 [0x7f51b8460729, 0x7f51b84609f1), 1323 [0x7f51b823f0f1, 0x7f51b823f61c), 622 [0x7f51b800b671, 0x7f51b800b8df), 780 [0x7f51b7dedb41, 0x7f51b7dede4d), 1393 [0x7f51b7bcc778, 0x7f51b7bccce9), 635 [0x7f51b7993981, 0x7f51b7993bfc), 878 [0x7f51b775a3e8, 0x7f51b775a756), 2387 [0x7f51b752be10, 0x7f51b752c763), 4415 [0x7f51b72c9758, 0x7f51b72ca897), 4849 [0x7f51b7026518, 0x7f51b7027809), 3716 [0x7f51b6d683a8, 0x7f51b6d6922c), 98 [0x7f51b44d8120, 0x7f51b44d8182), 352 [0x7f51b42d1210, 0x7f51b42d1370), 173 [0x7f51b40bf104, 0x7f51b40bf1b1), 113 [0x7f51b3eb6128, 0x7f51b3eb6199), 129 [0x7f51b3cae128, 0x7f51b3cae1a9), 212 [0x7f51b3aa7118, 0x7f51b3aa71ec), 90 [0x7f51b389e110, 0x7f51b389e16a), 918 [0x7f51b3695178, 0x7f51b369550e), 1406 [0x7f51b3471568, 0x7f51b3471ae6), 197 [0x7f51b32411c8, 0x7f51b324128d), 458 [0x7f51b3032208, 0x7f51b30323d2), 128 [0x7f51b2e1c118, 0x7f51b2e1c198), 118 [0x7f51b2c15160, 0x7f51b2c151d6), 331 [0x7f51b2a0d1b0, 0x7f51b2a0d2fb), 4385 [0x7f51b27ee630, 0x7f51b27ef751), 290 [0x7f51b25641d0, 0x7f51b25642f2), 80 [0x7f51b2358100, 0x7f51b2358150), 310 [0x7f51b2152180, 0x7f51b21522b6), 1444 [0x7f51b1f402d0, 0x7f51b1f40874), 214 [0x7f51b1d11170, 0x7f51b1d11246), 201 [0x7f51b1b07178, 0x7f51b1b07241), 203 [0x7f51b18fe128, 0x7f51b18fe1f3), 689 [0x7f51b16f23b0, 0x7f51b16f2661), 89 [0x7f51b14d6110, 0x7f51b14d6169), 649 [0x7f51b12ce260, 0x7f51b12ce4e9), 368 [0x7f51b10b3210, 0x7f51b10b3380), 481 [0x7f51b0c85b98, 0x7f51b0c85d79), 544 [0x7f51b0e9e3b0, 0x7f51b0e9e5d0), 134 [0x7f51b0a74120, 0x7f51b0a741a6), 99 [0x7f51b086d120, 0x7f51b086d183), 265 [0x7f51b06661c8, 0x7f51b06662d1), 92 [0x7f51b0457118, 0x7f51b0457174), 238 [0x7f51b0456140, 0x7f51b045622e),
    INFO: Loaded 103 PC tables (565769 PCs): 16173 [0x7f52033376b8,0x7f5203376988), 3218 [0x7f520362b540,0x7f5203637e60), 17651 [0x7f5203a7b328,0x7f5203ac0258), 267933 [0x7f52060201f0,0x7f5206436bc0), 4798 [0x7f5206700748,0x7f5206713328), 13110 [0x7cbbe0,0x7fef40), 1187 [0x7f51c2757d28,0x7f51c275c758), 10051 [0x7f51c2507d18,0x7f51c252f148), 1197 [0x7f51c21c3e28,0x7f51c21c88f8), 5309 [0x7f51c1f86fd8,0x7f51c1f9bba8), 273 [0x7f51c1cd9308,0x7f51c1cda418), 1355 [0x7f51c1ac9088,0x7f51c1ace538), 5770 [0x7f51c1879080,0x7f51c188f920), 415 [0x7f51c15aae78,0x7f51c15ac868), 1318 [0x7f51bfa7d7f8,0x7f51bfa82a58), 335 [0x7f51bf842568,0x7f51bf843a58), 484 [0x7f51bf62c5c0,0x7f51bf62e400), 2658 [0x7f51bf40e380,0x7f51bf4189a0), 764 [0x7f51beee1680,0x7f51beee4640), 4487 [0x7f51bf18e468,0x7f51bf19fcd8), 8123 [0x7f51bec9ef30,0x7f51becbeae0), 529 [0x7f51be9835d8,0x7f51be9856e8), 2873 [0x7f51be7619c8,0x7f51be76cd58), 4027 [0x7f51be4eaf58,0x7f51be4fab08), 1660 [0x7f51be25b300,0x7f51be261ac0), 13845 [0x7f51bdfe6338,0x7f51be01c488), 4870 [0x7f51bdc084d8,0x7f51bdc1b538), 5054 [0x7f51bd94d770,0x7f51bd961350), 2879 [0x7f51bd68e668,0x7f51bd699a58), 1585 [0x7f51bd41ad90,0x7f51bd4210a0), 3895 [0x7f51bd1d60a8,0x7f51bd1e5418), 5995 [0x7f51bcf2f0e8,0x7f51bcf46798), 528 [0x7f51bcc5c8d0,0x7f51bcc5e9d0), 12325 [0x7f51bca16078,0x7f51bca462c8), 847 [0x7f51bc6369e0,0x7f51bc639ed0), 2430 [0x7f51bc411598,0x7f51bc41ad78), 693 [0x7f51bc1b9838,0x7f51bc1bc388), 2128 [0x7f51bbf97ac0,0x7f51bbf9ffc0), 2517 [0x7f51bbd32c88,0x7f51bbd3c9d8), 12868 [0x7f51bbaa9920,0x7f51bbadbd60), 2055 [0x7f51bb6fc2b0,0x7f51bb704320), 1159 [0x7f51bb4a2d70,0x7f51bb4a75e0), 3669 [0x7f51bb2657c8,0x7f51bb273d18), 610 [0x7f51bafd96a0,0x7f51bafdbcc0), 7091 [0x7f51bada5938,0x7f51badc1468), 771 [0x7f51baab0d60,0x7f51baab3d90), 14164 [0x7f51ba85f2e8,0x7f51ba896828), 8067 [0x7f51ba465a28,0x7f51ba485258), 1931 [0x7f51ba14e080,0x7f51ba155930), 18199 [0x7f51b9ec1620,0x7f51b9f08790), 7000 [0x7f51b9a5bc40,0x7f51b9a771c0), 1738 [0x7f51b9739f18,0x7f51b9740bb8), 1396 [0x7f51b94f7978,0x7f51b94fd0b8), 907 [0x7f51b92bda48,0x7f51b92c12f8), 2038 [0x7f51b9091200,0x7f51b9099160), 3187 [0x7f51b8e398c0,0x7f51b8e45ff0), 5296 [0x7f51b8bab268,0x7f51b8bbfd68), 691 [0x7f51b88999a0,0x7f51b889c4d0), 435 [0x7f51b867c740,0x7f51b867e270), 712 [0x7f51b84609f8,0x7f51b8463678), 1323 [0x7f51b823f620,0x7f51b82448d0), 622 [0x7f51b800b8e0,0x7f51b800dfc0), 780 [0x7f51b7dede50,0x7f51b7df0f10), 1393 [0x7f51b7bcccf0,0x7f51b7bd2400), 635 [0x7f51b7993c00,0x7f51b79963b0), 878 [0x7f51b775a758,0x7f51b775de38), 2387 [0x7f51b752c768,0x7f51b7535c98), 4415 [0x7f51b72ca898,0x7f51b72dbc88), 4849 [0x7f51b7027810,0x7f51b703a720), 3716 [0x7f51b6d69230,0x7f51b6d77a70), 98 [0x7f51b44d8188,0x7f51b44d87a8), 352 [0x7f51b42d1370,0x7f51b42d2970), 173 [0x7f51b40bf1b8,0x7f51b40bfc88), 113 [0x7f51b3eb61a0,0x7f51b3eb68b0), 129 [0x7f51b3cae1b0,0x7f51b3cae9c0), 212 [0x7f51b3aa71f0,0x7f51b3aa7f30), 90 [0x7f51b389e170,0x7f51b389e710), 918 [0x7f51b3695510,0x7f51b3698e70), 1406 [0x7f51b3471ae8,0x7f51b34772c8), 197 [0x7f51b3241290,0x7f51b3241ee0), 458 [0x7f51b30323d8,0x7f51b3034078), 128 [0x7f51b2e1c198,0x7f51b2e1c998), 118 [0x7f51b2c151d8,0x7f51b2c15938), 331 [0x7f51b2a0d300,0x7f51b2a0e7b0), 4385 [0x7f51b27ef758,0x7f51b2800968), 290 [0x7f51b25642f8,0x7f51b2565518), 80 [0x7f51b2358150,0x7f51b2358650), 310 [0x7f51b21522b8,0x7f51b2153618), 1444 [0x7f51b1f40878,0x7f51b1f462b8), 214 [0x7f51b1d11248,0x7f51b1d11fa8), 201 [0x7f51b1b07248,0x7f51b1b07ed8), 203 [0x7f51b18fe1f8,0x7f51b18feea8), 689 [0x7f51b16f2668,0x7f51b16f5178), 89 [0x7f51b14d6170,0x7f51b14d6700), 649 [0x7f51b12ce4f0,0x7f51b12d0d80), 368 [0x7f51b10b3380,0x7f51b10b4a80), 481 [0x7f51b0c85d80,0x7f51b0c87b90), 544 [0x7f51b0e9e5d0,0x7f51b0ea07d0), 134 [0x7f51b0a741a8,0x7f51b0a74a08), 99 [0x7f51b086d188,0x7f51b086d7b8), 265 [0x7f51b06662d8,0x7f51b0667368), 92 [0x7f51b0457178,0x7f51b0457738), 238 [0x7f51b0456230,0x7f51b0457110),
    INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
    INFO: A corpus is not provided, starting from an empty corpus
    :#2     INITED cov: 1 ft: 5 corp: 1/1b exec/s: 0 rss: 237Mb
    Fuzz called 16377 tim#16384     pulse  cov: 1 ft: 5 corp: 1/1b lim: 163 exec/s: 8192 rss: 236Mb
    Fuzz called 32761 tim#32768     pulse  cov: 1 ft: 5 corp: 1/1b lim: 325 exec/s: 8192 rss: 236Mb
    ^C
    ayourtch@ayourtch-lnx:~/vpp$
    
    If you do any changes to fuzzer.c, first run make build, then do "touch
    src/vppinfra/format.c" and then run make build again.
    I winged the cmake into doing the thing I needed, but it's
    very grotesque...
    
    Change-Id: I8e0ae948cde2eb44ab73a316ee77d84123838e5e
    Signed-off-by: Andrew Yourtchenko <ayourtch@gmail.com>
