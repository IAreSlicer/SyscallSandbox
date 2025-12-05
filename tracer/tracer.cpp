    #include <sys/ptrace.h>
    #include <sys/types.h>
    #include <sys/wait.h>
    #include <sys/user.h>
    #include <unistd.h>
    #include <iostream>
    #include <set>
    #include <fstream>  

    using namespace std;

    int main(int argc, char* argv[]) {
        if (argc < 2) {  
            return -1;
        }
        
        pid_t child = fork();
        set<int> syscalls;
        
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
                int syscall_num = regs.orig_rax;
                syscalls.insert(syscall_num);
            }
        }
        
        
   const char* output_file = "policy_syscalls.txt";

    // Read syscalls from the file
    std::set<int> all_syscalls;

    {
        std::ifstream in(output_file);
        int num;

        // If the file does not exist yet, the loop does nothing
        while (in >> num) {
            all_syscalls.insert(num);
        }
    }

    // Add the syscalls we saw in this run
    for (int syscall_num : syscalls) {
        all_syscalls.insert(syscall_num);
    }

    // Write the union back to the file (overwrite old content)
    {
        std::ofstream out(output_file, std::ios::trunc);
        if (!out) {
            std::cerr << "Failed to open " << output_file << " for writing\n";
            return 1;
        }

        for (int syscall_num : all_syscalls) {
            out << syscall_num << '\n';
        }
    }

        
        return 0;
    }