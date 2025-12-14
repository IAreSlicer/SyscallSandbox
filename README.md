# Systems Security – Assignment 1 Repo

This repository contains the implementation of a syscall tracer and sandbox.

---

## Running Instructions

### 1. Compile the program

Example:
```bash
g++ example_app/hello_world.cpp -o example_app/hello_world
```

---

### 2. Build and run the tracer on your program

Example:
```bash
cd tracer
make
./tracer ../example_app/hello_world
```

This generates policy files in the tracer directory `policy_syscalls_hello_world.txt`.

**Note:** You may want to run the application multiple times to cover all execution paths.

---

### 3. Move the generated policy files to the policy directory

Example:
```bash
mv tracer/policy_syscalls_hello_world.txt policy/
```

---

### 4. Build and run the sandbox on your program

Example:
```bash
cd sandbox
make
LD_PRELOAD=./libsandbox.so ../example_app/hello_world
```

**Note:** The sandbox automatically loads the policy file based on the program name in the format `../policy/policy_syscalls_<program_name>.txt`.