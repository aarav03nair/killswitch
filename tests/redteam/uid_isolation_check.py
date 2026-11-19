import os, subprocess, sys, ctypes, signal, time, pwd
libc = ctypes.CDLL(None, use_errno=True)
PR_SET_DUMPABLE, PTRACE_ATTACH, PTRACE_DETACH = 4, 16, 17
for u in (60001, 60002):
    try: pwd.getpwuid(u); print("passwd entry exists for", u)
    except KeyError: pass
# 1) subprocess user=int, no passwd entry
for i in range(2):
    out = subprocess.run([sys.executable, "-c", "import os;print(os.getuid(),os.geteuid(),os.getgid())"],
                         user=60001+i, group=60001+i, extra_groups=[], capture_output=True, text=True)
    print("user=", 60001+i, "->", out.stdout.strip(), out.stderr.strip()[:80])
# 2) preexec_fn os.setuid
def pre():
    os.setgroups([]); os.setgid(60003); os.setuid(60003)
out = subprocess.run([sys.executable, "-c", "import os;print(os.getuid())"], preexec_fn=pre, capture_output=True, text=True)
print("preexec setuid 60003 ->", out.stdout.strip(), out.stderr.strip()[:80])
# 3) cross-uid ptrace from 60002 against a 60001 victim (dumpable and non-dumpable), plus same-uid control
victim_src = "import ctypes,sys,time;l=ctypes.CDLL(None);l.prctl(4,int(sys.argv[1]),0,0,0);print('ready',flush=True);time.sleep(30)"
attack_src = r'''
import ctypes,os,sys
l=ctypes.CDLL(None,use_errno=True); pid=int(sys.argv[1])
r=l.ptrace(16,pid,0,0); e=ctypes.get_errno()
print("ptrace", r, os.strerror(e) if r else "OK")
if r==0: l.ptrace(17,pid,0,0)
SYS_pidfd_open, SYS_pidfd_getfd = 434, 438
fd=l.syscall(SYS_pidfd_open,pid,0); e=ctypes.get_errno()
if fd<0: print("pidfd_open",os.strerror(e))
else:
    g=l.syscall(SYS_pidfd_getfd,fd,0,0); e=ctypes.get_errno()
    print("pidfd_getfd", g, os.strerror(e) if g<0 else "OK")
'''
def trial(vu, au, dumpable):
    v = subprocess.Popen([sys.executable, "-c", victim_src, str(dumpable)], user=vu, group=vu, extra_groups=[], stdout=subprocess.PIPE, text=True)
    v.stdout.readline()
    a = subprocess.run([sys.executable, "-c", attack_src, str(v.pid)], user=au, group=au, extra_groups=[], capture_output=True, text=True)
    v.kill(); v.wait()
    print(f"victim uid {vu} dumpable={dumpable} attacker uid {au}:", a.stdout.strip().replace("\n"," | "), a.stderr.strip()[:100])
trial(60001, 60002, 1)
trial(60001, 60002, 0)
trial(60001, 60001, 1)
trial(60001, 60001, 0)
print("yama:", os.path.exists("/proc/sys/kernel/yama/ptrace_scope"))
