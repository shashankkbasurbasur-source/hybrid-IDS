import re
from datetime import datetime

SYSCALL_NUMBER_TO_NAME = {
    0: "read", 1: "write", 2: "open", 3: "close", 9: "mmap",
    10: "mprotect", 11: "munmap", 12: "brk", 21: "access",
    22: "pipe", 32: "dup", 33: "dup2", 39: "getpid", 41: "socket",
    42: "connect", 43: "accept", 44: "sendto", 45: "recvfrom",
    49: "bind", 50: "listen", 56: "clone", 57: "fork", 58: "vfork",
    59: "execve", 60: "exit", 61: "wait4", 62: "kill", 79: "getcwd",
    82: "rename", 83: "mkdir", 84: "rmdir", 85: "creat", 86: "link",
    87: "unlink", 88: "symlink", 89: "readlink", 90: "chmod",
    91: "fchmod", 92: "chown", 93: "fchown", 94: "lchown",
    101: "ptrace", 102: "getuid", 104: "getgid", 105: "setuid",
    106: "setgid", 107: "geteuid", 108: "getegid", 112: "setsid",
    117: "setresuid", 119: "setresgid", 157: "prctl", 165: "mount",
    166: "umount2", 257: "openat", 322: "execveat",
}


def resolve_syscall_name(num: int) -> str:
    return SYSCALL_NUMBER_TO_NAME.get(num, f"syscall_{num}")


AUDIT_LINE_REGEX = re.compile(
    r'type=SYSCALL msg=audit\((?P<epoch>\d+)\.\d+:\d+\):.*?'
    r'syscall=(?P<syscall>\d+).*?'
    r'success=(?P<success>yes|no)'
    r'(?:.*?pid=(?P<pid>\d+))?'
    r'(?:.*?ppid=(?P<ppid>\d+))?'
    r'(?:.*?uid=(?P<uid>\d+))?'
    r'(?:.*?comm="(?P<comm>[^"]*)")?'
    r'(?:.*?exe="(?P<exe>[^"]*)")?'
)


class SyscallLogParser:
    def parse_line(self, line: str):
        line = line.strip()
        m = AUDIT_LINE_REGEX.search(line)
        if not m:
            return None
        syscall_num = int(m.group("syscall"))
        return {
            "timestamp": datetime.utcfromtimestamp(int(m.group("epoch"))).isoformat(),
            "source": "auditd",
            "syscall_num": syscall_num,
            "syscall_name": resolve_syscall_name(syscall_num),
            "success": m.group("success") == "yes",
            "pid": int(m.group("pid")) if m.group("pid") else None,
            "ppid": int(m.group("ppid")) if m.group("ppid") else None,
            "uid": int(m.group("uid")) if m.group("uid") else None,
            "comm": m.group("comm"),
            "exe": m.group("exe"),
            "raw": line,
        }

    def parse_lines(self, lines):
        return [e for e in (self.parse_line(l) for l in lines) if e]