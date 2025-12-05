#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <iostream>
#include <set>
#include <fstream>  
#include <sstream>
#include <string>

using namespace std;

std::string get_basename(const std::string& path) {
    size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos) return path;
    return path.substr(pos + 1);
}


int main(int argc, char* argv[]) {
    if (argc < 2) {  
        cerr << "Usage: ./tracer <program> [args...]" << endl;
        return 1;
    }
    
    pid_t child = fork();
    set<int> syscalls;
    
    if (child == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (child == 0) {
        //Traced Child
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1) {
            perror("ptrace");
            exit(EXIT_FAILURE);
        }
        execvp(argv[1], &argv[1]); 
        exit(127);
    // Tracer Process
    } else {
        int status;
        
        // Wait for child to stop on its first instruction
        if (waitpid(child, &status, 0) == -1) {
            perror("waitpid");
            return 1;
        }
        
        // Set options to trace system calls
        ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
        
        while (true) {
            // Hold at the next syscall
            ptrace(PTRACE_SYSCALL, child, 0, 0);
            waitpid(child, &status, 0);
            
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
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
        
    // Set file name to be safe
    string prog = get_basename(argv[1]);
    string output_file = "policy_syscalls_" + prog + ".txt";

    // Read syscalls from the file
    set<int> all_syscalls;
    {
        ifstream in(output_file);
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
        ofstream out(output_file, ios::trunc);
        if (!out) {
            cerr << "Failed to open " << output_file << " for writing" << endl;
            return 1;
        }

        for (int syscall_num : all_syscalls) {
            out << syscall_num << endl;
        }
    }
    return 0;
}