/*
* Copyright (2008-2009) Intel Corporation All Rights Reserved. 
* The source code contained or described herein and all documents 
* related to the source code ("Material") are owned by Intel Corporation 
* or its suppliers or licensors. Title to the Material remains with 
* Intel Corporation or its suppliers and licensors. The Material 
* contains trade secrets and proprietary and confidential information 
* of Intel or its suppliers and licensors. The Material is protected 
* by worldwide copyright and trade secret laws and treaty provisions. 
* No part of the Material may be used, copied, reproduced, modified, 
* published, uploaded, posted, transmitted, distributed, or disclosed 
* in any way without Intel(R)s prior express written permission.
*
* No license under any patent, copyright, trade secret or other 
* intellectual property right is granted to or conferred upon you by 
* disclosure or delivery of the Materials, either expressly, by implication,
* inducement, estoppel or otherwise. Any license under such intellectual 
* property rights must be express and approved by Intel in writing.
*/

#if defined (__GNUC__) 
#define IACA_SSC_MARK( MARK_ID )						\
__asm__ __volatile__ (									\
					  "\n\t  movl $"#MARK_ID", %%ebx"	\
					  "\n\t  .byte 0x64, 0x67, 0x90"	\
					  : : : "memory" );

#else
#define IACA_SSC_MARK(x) {__asm  mov ebx, x\
	__asm  _emit 0x64 \
	__asm  _emit 0x67 \
	__asm  _emit 0x90 }
#endif

#define IACA_START {IACA_SSC_MARK(111)}
#define IACA_END {IACA_SSC_MARK(222)}

#ifdef _WIN64
#include <intrin.h>
#define IACA_VC64_START __writegsbyte(111, 111);
#define IACA_VC64_END   __writegsbyte(222, 222);
#endif

/**************** asm *****************
;START_MARKER
mov ebx, 111
db 0x64, 0x67, 0x90

;END_MARKER
mov ebx, 222
db 0x64, 0x67, 0x90

**************************************/
