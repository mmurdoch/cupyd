from ctypes import *
from ctypes.util import find_library
from errno import *
from sys import stdout

traced_process = 2421

PTRACE_ATTACH = 16
PTRACE_GETREGS = 12
PTRACE_PEEKTEXT = 1
PTRACE_PEEKUSER = 3
PTRACE_DETACH = 17
PTRACE_SYSCALL = 24

class user_regs_struct(Structure):
    _fields_ = [
        ('r15', c_ulong),
        ('r14', c_ulong),
        ('r13', c_ulong),
        ('r12', c_ulong),
        ('rbp', c_ulong),
        ('rbx', c_ulong),
        ('r11', c_ulong),
        ('r10', c_ulong),
        ('r9', c_ulong),
        ('r8', c_ulong),
        ('rax', c_ulong),
        ('rcx', c_ulong),
        ('rdx', c_ulong),
        ('rsi', c_ulong),
        ('rdi', c_ulong),
        ('orig_rax', c_ulong),
        ('rip', c_ulong),
        ('cs', c_ulong),
        ('eflags', c_ulong),
        ('rsp', c_ulong),
        ('ss', c_ulong),
        ('fs_base', c_ulong),
        ('gs_base', c_ulong),
        ('ds', c_ulong),
        ('es', c_ulong),
        ('fs', c_ulong),
        ('gs', c_ulong)]

# Need to check return values. Will be 0 on success, -1 on failure
# and then check errno. For _PEEK* operations need to set errno to 0
# before the call and then check it afterwards (the return value is
# used for returning the peeked value.
def handle_ptrace_error(request_name, status):
    if status == -1:
        error_number = get_errno()
        if error_number == EPERM:
            print(request_name + ': tracing not allowed. ' +
                'Try running with \'sudo\'?')
        else:
            print(request_name + ': error: ' + errorcode[error_number]) 

        exit(error_number)


libc = CDLL(find_library('c'), use_errno=True)
ptrace = libc.ptrace
ptrace.argtypes = (c_ulong, c_ulong, c_void_p, c_void_p)
ptrace.restype = c_long

status = ptrace(PTRACE_ATTACH, traced_process, 0, 0)
handle_ptrace_error('ATTACH', status)

in_syscall = False
while True:
    libc.wait(None)
    regs = user_regs_struct()
    status = ptrace(PTRACE_GETREGS, traced_process, 0, byref(regs))
    handle_ptrace_error('GETREGS', status)

    orig_rax = regs.orig_rax
    if orig_rax == 1: # write()
        if not in_syscall:
            in_syscall = True

# On 64-bit Linux, system calls are passed arguments in registers
# RDI, RSI, RDX, R10, R8, R9
# See http://stackoverflow.com/a/2538212/4023 for calling conventions
            params = [regs.rdi, regs.rsi, 
                      regs.rdx, regs.r10,
                      regs.r8, regs.r9]
            print('write(' + str(params[2]) + 
                ' bytes from buffer ' + str(params[1]) +
                ' to file ' + str(params[0]))
            stdout.flush()
        else:
            rax = regs.rax
            print('write() wrote ' + str(rax) + ' bytes')
            stdout.flush()
            in_syscall = False

    status = ptrace(PTRACE_SYSCALL, traced_process, 0, 0)
    handle_ptrace_error('SYSCALL', status)

status = ptrace(PTRACE_DETACH, traced_process, 0, 0)
handle_ptrace_error('DETACH', status)

