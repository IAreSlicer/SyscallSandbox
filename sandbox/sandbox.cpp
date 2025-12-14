#include <linux/prctl.h>
#include <sys/prctl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ucontext.h>
#include <fcntl.h>
#include <cassert>
#include <cstdint>

#define ASSERT_ELSE_PERROR(cond)	\
    do {							\
        bool x = static_cast<bool>(cond);	\
        if (!x) {							\
            fflush(stdout);					\
            fflush(stderr);					\
            fprintf(stderr,"%s:%d: %s: Assertion `%s` failed: ", __FILE__, __LINE__, __func__, #cond);	\
            perror("");						\
            fflush(stderr);					\
            abort();						\
        }									\
    } while (false)

// taken from https://github.com/ColinIanKing/stress-ng/blob/master/stress-usersyscall.c
#ifndef SYS_USER_DISPATCH
# define SYS_USER_DISPATCH 2 /* syscall user dispatch triggered */
#endif

extern "C" void* (syscall_dispatcher_start)(void);
extern "C" void* (syscall_dispatcher_end)(void);
extern "C" long enter_syscall(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);

char filter_selector = SYSCALL_DISPATCH_FILTER_ALLOW;

template<size_t NUM>
static constexpr long long SYSCALL_ARG(const gregset_t gregs) {
	static_assert(NUM > 0 && NUM <= 6);
	return (long long[]){gregs[REG_RDI], gregs[REG_RSI], gregs[REG_RDX], gregs[REG_R10], gregs[REG_R8], gregs[REG_R9]}[NUM-1];
}

// note: avoid using C++ standard library functions and global objects here
// because this library is loaded first before other shared libraries are loaded 
// and global C++ objects are constructed

#define MAX_SYSCALLS 512
static int policy_syscalls[MAX_SYSCALLS];
static int policy_count = 0;


// reference: https://github.com/balexios/simple-sud-library 
void ____asm_impl(void) {
	/*
	 * enter_syscall triggers a kernel-space system call
	 */
	asm volatile (
		".globl enter_syscall \n\t"
		"enter_syscall: \n\t"
		"movq %rdi, %rax \n\t"
		"movq %rsi, %rdi \n\t"
		"movq %rdx, %rsi \n\t"
		"movq %rcx, %rdx \n\t"
		"movq %r8, %r10 \n\t"
		"movq %r9, %r8 \n\t"
		"movq 8(%rsp),%r9 \n\t"
		"syscall \n\t"
		"ret \n\t"
	);
}

static int is_syscall_allowed(int syscall_num) {
    for (int i = 0; i < policy_count; i++) {
        if (policy_syscalls[i] == syscall_num) {
            return 1;
        }
    }
    return 0;
}

static void handle_sigsys(int sig, siginfo_t* info, void* ucontextv) {
	filter_selector = SYSCALL_DISPATCH_FILTER_ALLOW;

	assert(sig == SIGSYS);
	assert(info->si_signo == SIGSYS);
	assert(info->si_code == SYS_USER_DISPATCH);
	assert(info->si_errno == 0);

	// emulate the system call
	const auto uctxt = (ucontext_t*)ucontextv;
	const auto gregs = uctxt->uc_mcontext.gregs;
	assert(gregs[REG_RAX] == info->si_syscall);

	int syscall_num = (int)info->si_syscall;
	fprintf(stderr, "Trapping (syscall number = %d)\n", syscall_num);
	
	// check if syscall is in the policy
	if (!is_syscall_allowed(syscall_num)) {
		fprintf(stderr, "Syscall %d is not in the policy. Terminating the program.\n", syscall_num);
		_exit(1);
	}
	
	// if syscall is in the policy, we execute it
	gregs[REG_RAX] = enter_syscall(info->si_syscall, SYSCALL_ARG<1>(gregs), SYSCALL_ARG<2>(gregs), SYSCALL_ARG<3>(gregs), SYSCALL_ARG<4>(gregs), SYSCALL_ARG<5>(gregs), SYSCALL_ARG<6>(gregs));

	filter_selector = SYSCALL_DISPATCH_FILTER_BLOCK;

	asm volatile (
		"movq $0xf, %%rax \n\t"
		"leaveq \n\t"
		"add $0x8, %%rsp \n\t"
		".globl syscall_dispatcher_start \n\t"
		"syscall_dispatcher_start: \n\t"
		"syscall \n\t"
		"nop \n\t"
		".globl syscall_dispatcher_end \n\t"
		"syscall_dispatcher_end: \n\t"
		:
		:
		: "rsp", "rax", "cc" // for some stupid reason adding rsp in the clobbers is considered deprecated ... so we need to use -Wno-deprecated flag
	);
}

static void load_policy() {
    // read the path of the current executable
    // /proc/self/exe is a special linux file that points to the executable
    char path[256] = {0};  
    ssize_t len = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (len == -1) {
        fprintf(stderr, "Cannot read /proc/self/exe.\n");
        _exit(1);
    }
    path[len] = '\0';
    
    // extract program name
    char *progname = strrchr(path, '/');
    if (progname) {
        progname++;
    } else {
        progname = path;
    }
    
    // read policy file from ../policy/policy_syscalls_<progname>.txt
    char policy_file[512];
    snprintf(policy_file, sizeof(policy_file), "../policy/policy_syscalls_%s.txt", progname);
    int fd = open(policy_file, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Policy file cannot be found.\n");
        _exit(1);
    }
    char buffer[4096];
    ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    if (bytes_read <= 0) {
        fprintf(stderr, "Policy file is empty or could not be read.\n");
        _exit(1);
    }
    buffer[bytes_read] = '\0';

    // read syscall numbers from the file
    char *ptr = buffer;
    while (*ptr && policy_count < MAX_SYSCALLS) {
        while (*ptr == ' ' || *ptr == '\t' || *ptr == '\n' || *ptr == '\r') {
            ptr++;
        }
        if (*ptr >= '0' && *ptr <= '9') {
            int num = atoi(ptr);
            policy_syscalls[policy_count++] = num;
            while (*ptr >= '0' && *ptr <= '9') {
                ptr++;
            }
        } else if (*ptr) {
            ptr++;
        }
    }
    
    if (policy_count == 0) {
        fprintf(stderr, "No syscalls found in policy file\n");
        _exit(1);
    }
}

static void filter_setup() {
	struct sigaction sa = {};
	sa.sa_sigaction = handle_sigsys;
	sa.sa_flags = SA_SIGINFO;

    ASSERT_ELSE_PERROR(sigemptyset(&sa.sa_mask) == 0);
	ASSERT_ELSE_PERROR(sigaction(SIGSYS, &sa, NULL) == 0);

	ASSERT_ELSE_PERROR(prctl(PR_SET_SYSCALL_USER_DISPATCH,
							 PR_SYS_DISPATCH_ON,
							 syscall_dispatcher_start,
							 ((int64_t)syscall_dispatcher_end - (int64_t)syscall_dispatcher_start + 1),
							 &filter_selector) == 0);

	printf("Filter enabled.\n");
	filter_selector = SYSCALL_DISPATCH_FILTER_BLOCK;
}

// __attribute__ runs at library load time
void __attribute__((constructor)) init() {
    load_policy();
    filter_setup();
}