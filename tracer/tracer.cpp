    #include <sys/ptrace.h>
    #include <sys/types.h>
    #include <sys/wait.h>
    #include <sys/user.h>
    #include <unistd.h>
    #include <iostream>
    #include <set>

    using namespace std;

    int main(int argc, char* argv[]) {
        if (argc < 2) {  
            return -1;
        }
        
        pid_t child = fork();
        set<long> syscalls;
        
        // Traced process
        if (child == 0) {
            ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
            execvp(argv[1], &argv[1]); 
            exit(1);
        // Tracer Process
        } else {
            int status;
            
            // Wait for child to stop on its first instruction
            waitpid(child, &status, 0);
            
            // Set options to trace system calls
            ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
            
            while (true) {
                // Hold at the next syscall
                ptrace(PTRACE_SYSCALL, child, 0, 0);
                waitpid(child, &status, 0);
                
                if (WIFEXITED(status)) {
                    // Program has exited
                    break;
                }
                
                struct user_regs_struct regs;
                ptrace(PTRACE_GETREGS, child, 0, &regs);
                
                // On linux x86_64, syscall number is in orig_rax
                long syscall_num = regs.orig_rax;
                syscalls.insert(syscall_num);
            }
        }
        
        for (long syscall_num : syscalls) {
            cout << syscall_num << endl;
        }
        
        return 0;
    }