pub fn harden_process() {
    #[cfg(target_os = "linux")]
    unsafe {
        if libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) != 0 {
            log::warn!(
                "GhostFS: mlockall() failed ({}) — process memory (including encryption keys) \
                 may be swapped to disk under memory pressure. To fix: increase RLIMIT_MEMLOCK \
                 ('ulimit -l unlimited' or systemd 'LimitMEMLOCK=infinity'), or grant \
                 CAP_IPC_LOCK if running in a container/restricted environment.",
                std::io::Error::last_os_error()
            );
        } else {
            log::info!("GhostFS: process memory locked (mlockall) — keys will not be swapped to disk");
        }

        // PR_SET_DUMPABLE = 4 (libc crate exposes it as a constant).
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            log::warn!(
                "GhostFS: prctl(PR_SET_DUMPABLE, 0) failed ({}) — core dumps and ptrace \
                 attachment are NOT disabled for this process.",
                std::io::Error::last_os_error()
            );
        } else {
            log::info!("GhostFS: core dumps and ptrace attachment disabled for this process (PR_SET_DUMPABLE=0)");
        }

        warn_on_unencrypted_swap();
    }

    #[cfg(not(target_os = "linux"))]
    {
        log::warn!(
            "GhostFS: memory-lock / anti-ptrace hardening (harden_process) is only implemented \
             for Linux — running without this protection on this platform."
        );
    }
}

/// `mlockall` chroni tylko pamięć TEGO procesu — nie robi nic dla innych
/// procesów, ani dla stron, które z jakiegoś powodu i tak trafiły na swap
/// ZANIM `mlockall` zdążyło zadziałać (np. bardzo krótkie okno startowe).
/// To czysto informacyjne ostrzeżenie: jeśli `/proc/swaps` pokazuje aktywny
/// obszar wymiany, który sam nie jest zaszyfrowany (LUKS/dm-crypt na
/// urządzeniu swap), to defense-in-depth tej instalacji ma lukę niezależną
/// od GhostFS — administrator powinien albo wyłączyć swap, albo
/// zaszyfrować go osobno.
#[cfg(target_os = "linux")]
fn warn_on_unencrypted_swap() {
    let swaps = match std::fs::read_to_string("/proc/swaps") {
        Ok(s) => s,
        Err(_) => return, // brak /proc/swaps (np. kontener) — nic do zgłoszenia
    };
    let active: Vec<&str> = swaps.lines().skip(1).filter(|l| !l.trim().is_empty()).collect();
    if active.is_empty() {
        return; // brak aktywnego swap — nie ma czego ostrzegać
    }
    // Heurystyka: urządzenia dm-crypt/LUKS zwykle mają w ścieżce "/dev/mapper/"
    // z nazwą sugerującą crypt (np. "cryptswap", "swap_crypt"). To
    // niedoskonałe (fałszywe negatywy możliwe), stąd tylko WARN, nie błąd.
    let looks_encrypted = active.iter().any(|l| {
        let path = l.split_whitespace().next().unwrap_or("");
        path.contains("mapper") || path.to_lowercase().contains("crypt")
    });
    if !looks_encrypted {
        log::warn!(
            "GhostFS: active swap space detected that does NOT appear to be encrypted \
             (checked /proc/swaps). mlockall() only protects THIS process's memory from \
             being swapped — it does not affect other processes, and offers no protection \
             during the brief window before mlockall() runs. For full defense-in-depth, \
             encrypt swap itself (e.g. LUKS-backed swap) or disable it entirely."
        );
    }
}
