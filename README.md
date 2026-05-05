
# 💧 sharedtears: Non-Cooperative Process Hijacking PoC

Allows an operator to snapshot a running process by leveraging the `ptrace` subsystem and forces it to execute arbitrary syscalls without termination or crashing.

---

## 🛠️ Injection Flow

The tool operates at the **ABI (Application Binary Interface)** level, interacting directly with the Linux Kernel and the x86_64 CPU architecture.

*   **Process Hijack**: Uses `PTRACE_ATTACH` on the target PID, sending a `SIGSTOP` to the process.
*   **Snapshotting**: Captures the complete state of CPU registers ($RAX$, $RIP$, etc) to restore them later.
*   **Memory Recon**: Parses `/proc/[pid]/maps` to locate an executable *Code Cave* (memory marked `r-xp`) to host the payload.
*   **Payload Splicing**: Manually writes the string payload and the `0x050f` (syscall) opcode into the process' memory space.
*   **Instruction Pointer Hijacking**: Redirects the Instruction Pointer ($RIP$) to the injected code and populates registers to craft a specific syscall frame.
*   **Zero-Footprint Restore**: Restores the original register state after execution, allowing the process to resume its original task without stability errors.

---

## 🚀 Walkthrough

### Payload Preparation (`so-gen`)
The library is compiled as a `cdylib` and contains a constructor that triggers upon being mapped by the OS.

*   **Implement the Constructor**
    ```rust
    #[unsafe(link_section = ".init_array")]
    pub static INITIALIZE: extern "C" fn() = {
        extern "C" fn init() {
            let _ = std::fs::write("/tmp/success.txt", b"so injection successful.");
        }
        init
    };
    ```
*   **Compile**: `cargo build --release` to generate the `.so` file.

### Hijack
- **Establish a Victim** (for this lab, we use the `cat` process but you can use any)
    
```bash
    cat &
    export VIC_PID=$!
```
- **Run sharedtears**

    Force the victim to open a file handle to your library using its **absolute path**.
    ```bash
    ./target/debug/sharedtears $VIC_PID 3
    ```

### Analyze the Fingerprint
Even before the code executes, acquisition is visible in the victim's resource table.
*   **Command**: `ls -l /proc/$VIC_PID/fd/`
*   **Visible Result**: `lr-x------ ... 4 -> /home/user/sharedtears/so-gen/target/release/libso_gen.so`
*   **PoC**: The presence of file descriptor **4** proves the victim has been subverted into holding a malicious resource.

---

## 🎯 Attack Profile & Impact

*   **Target**: Any running user-space process with the same or lower privilege level (unless running as root).
*   **Conditions Required**
    *   **Ptrace Permissions**: `sys_ptrace` capabilities or matching User ID.
    *   **Absolute Pathing**: Kernel-level syscalls require full literal paths (e.g. `/home/aradhya/...` instead of `~/`).
*   **Impact**
    *   **Stealth**: No new processes are created. Malicious actions occur inside a trusted PID, often bypassing EDR tools that monitor for new process starts.
    *   **Resource Hijacking**: Forcing processes to maintain handles to malicious files for later exploitation or persistence.
    *   **Stability**: The process remains active and functional, reducing the likelihood of detection by system crashes.

---

## 🛡️ Use Cases

### Production Scenario
*   **Red Teaming**: Demonstrating how a compromise in one user-space application can be used to silently subvert other running services.
*   **Privilege Escalation**: Targeting a root-owned process (like a system daemon) to perform actions with elevated permissions.
*   **Lateral Movement**: Using a hijacked process to establish a hidden channel for data exfiltration or scanning.

---

## 📊 MITRE

| ID | Technique | Application |
| :--- | :--- | :--- |
| **T1055.008** | **Process Injection: Ptrace** | Manipulating a process using the `ptrace` system call to execute arbitrary code or syscalls. |
| **T1574.002** | **Hijack Execution Flow: SO Injection** | Forcing a process to load and maintain a handle to a malicious Shared Object. |
| **T1027** | **Obfuscation** | Executing actions in-memory within a process to avoid writing new binaries to disk. |

---
