#include <stdio.h>
#include <stdint.h>
#include <vppinfra/clib.h>
#include <vlibapi/api.h>

#include <vlib/cli.h>


extern int vpp_main(int argc, char **argv);
extern void __libc_start_main(void *m, int argc, char **argv, void *init, void *fini);
extern void __libc_csu_fini();
extern void __libc_csu_init();

__clib_export void fuzzer_main() {
	// int argc = 0;
	// char **argv = 0;
	asm("xor %rbp, %rbp");
	asm("mov %rdx, %r9");
	asm("pop %rsi"); // something...
	asm("pop %rsi"); // argc
	asm("mov %rsp, %rdx"); // argv
	asm("and $0xfffffffffffffff0,%rsp");
	asm("push %rdx");
	asm("push %rsp");
	// asm("mov __libc_csu_fini, %r8"); 
	//asm("mov 0, %r8"); 
	// asm("mov __libc_csu_init, %rcx"); // init
	asm("mov %0, %%r8" :: "r"(__libc_csu_fini)); // argv
	asm("mov %0, %%rcx" :: "r"(__libc_csu_init)); // argv
	asm("mov %0, %%rdi" :: "r"(vpp_main)); // argv
	/// asm volatile("mov %%rsi,%0" :"=g"(argc): :"memory"); // x = 3;
	// asm volatile("mov %%rcx,%0" :"=g"(argv): :"memory"); // x = 3;
	//asm("movl %esp, argc");
	// asm("movl %ecx, argv");
	// asm("jmp _start");
	asm("call __libc_start_main");
	// vpp_main(argc, argv);
	// argc = 0;
	// argv = 0;
	//__libc_start_main(vpp_main, argc, argv, 0, 0);
	exit(0);
}


__clib_export int LLVMFuzzerTestOneInput(const void *data, uword size) {
    static ulong counter = 0;
    printf("Fuzz called %ld times!\r", counter++);
    return 0;  // Non-zero return values are reserved for future use.
}


