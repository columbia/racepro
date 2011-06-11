import scribe
from racepro import *

###############################################################################
def parse_syscall(session, i):
    """Parse a syscall event"""

    s_ev = session.events[i]
    args = session.events[s_ev.regind].event.args
    event = s_ev.event
    ret = unistd.syscall_ret(event.ret)

    for j in xrange(s_ev.pindex + 1, len(s_ev.proc.events)):
        e_data = s_ev.proc.events[j].event
        if isinstance(e_data, scribe.EventDataExtra): break

    out = sys.stdout
    if event.nr == unistd.Syscalls.NR_open:
        out.write('open("%s", %#x, %#3o)' %
                  (e_data.data, args[1], args[2]))
    elif event.nr == unistd.Syscalls.NR_close:
        out.write('close(%d)' %
                  (args[0]))
    elif event.nr == unistd.Syscalls.NR_access:
        out.write('access("%s", %#3o)' %
                  (e_data.data, args[1]))
    elif event.nr == unistd.Syscalls.NR_execve:
        out.write('execve("%s", %#x, %#x)' %
                  (e_data.data, args[1], args[2]))
    elif event.nr == unistd.Syscalls.NR_stat:
        out.write('stat("%s", %#x)' %
                  (e_data.data, args[1]))
    elif event.nr == unistd.Syscalls.NR_stat64:
        out.write('stat64("%s", %#x, %#x)' %
                  (e_data.data, args[1], args[2]))
    elif event.nr == unistd.Syscalls.NR_unlink:
        out.write('unlink("%s")' %
                  (e_data.data))
    else:
        out.write('%s(%#x, %#x, %#x)' %
                  (unistd.syscall_str(event.nr),
                   args[0], args[1], args[2]))
    out.write(' = %ld\n' % (ret))

###############################################################################
def save_modify_log(graph, output, bookmarks, injects, cutoff, replace):
    """Generate and save a modified scribe log for a race"""
    event_iter = mutate_events(graph, bookmarks, injects, cutoff, replace)
    save_session(output, event_iter)

