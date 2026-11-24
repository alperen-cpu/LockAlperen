/*
 * Preloaded (LD_PRELOAD) into the processes LockAlperen starts on Linux.
 * In WebKitGTK's helper processes (WebKitWebProcess, WebKitNetworkProcess,
 * ...) it turns off "dumpable", as the app does for itself: other processes
 * of the same user can then no longer read their memory (ptrace,
 * /proc/<pid>/mem) and no core dump is written. The web process holds what
 * the page shows: a revealed password, the entry being edited.
 *
 * The flag cannot be inherited: the kernel sets it again on every exec, so
 * it has to be set from inside the new process. Every other program is left
 * alone. See src/linux/hardening.rs.
 */
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

__attribute__((constructor)) static void lav_nodump(void) {
    char exe[4096];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (n <= 0)
        return;
    exe[n] = '\0';
    const char *base = strrchr(exe, '/');
    base = base ? base + 1 : exe;
    if (strncmp(base, "WebKit", 6) == 0)
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}
