from nose.tools import *
from racepro.execution_graph import *
from racepro.unistd import *

def test_fork_wait_dep():
    def gen_test_fork_process_edge(nr_fork, nr_wait, nr_exit):
        events = [
                   scribe.EventPid(pid=1),                       # 0
                   scribe.EventRegs(),                           # 1
                   scribe.EventSyscallExtra(nr=nr_fork, ret=-1), # 2
                   scribe.EventSyscallExtra(nr=nr_fork, ret=2),  # 3
                   scribe.EventSyscallExtra(nr=nr_fork, ret=3),  # 4
                   scribe.EventSyscallExtra(nr=nr_wait, ret=-1), # 5
                   scribe.EventSyscallExtra(nr=nr_wait, ret=3),  # 6
                   scribe.EventSyscallExtra(nr=nr_wait, ret=2),  # 7
                   scribe.EventSyscallExtra(nr=nr_wait, ret=4),  # 8
                   scribe.EventSyscallExtra(nr=nr_exit, ret=0),  # 9
                   scribe.EventPid(pid=2),                       # 10
                   scribe.EventSyscallExtra(nr=nr_fork, ret=4),  # 11
                   # pid 2 gets killed: doesn't call exit.
                   # pid 4 gets reparented to 1
                   scribe.EventPid(pid=3),                       # 12
                   scribe.EventSyscallExtra(nr=nr_exit, ret=0),  # 13
                   scribe.EventPid(pid=4),                       # 14
                   scribe.EventSyscallExtra(nr=nr_exit, ret=0)   # 15
                 ]

        g = ExecutionGraph(events)
        e = list(g.events)
        procs = g.processes

        assert_equal(set(g.edges()), set([
            # natural edges
            (procs[1].anchor, e[3]),
            (e[3], e[4]),
            (e[4], e[6]),
            (e[6], e[7]),
            (e[7], e[8]),
            (e[8], e[9]),
            (procs[2].anchor, e[11]),
            (procs[3].anchor, e[13]),
            (procs[4].anchor, e[15]),
            # forks
            (e[3],  procs[2].anchor),
            (e[4],  procs[3].anchor),
            (e[11], procs[4].anchor),
            # waits
            (e[11], e[7]),
            (e[13], e[6]),
            (e[15], e[8])]))

    for nr_fork in [NR_fork, NR_clone, NR_vfork]:
        yield gen_test_fork_process_edge, nr_fork, NR_waitpid, NR_exit
    for nr_wait in [NR_waitpid, NR_wait4, NR_waitid]:
        yield gen_test_fork_process_edge, NR_fork, nr_wait, NR_exit
    for nr_exit in [NR_exit, NR_exit_group]:
        yield gen_test_fork_process_edge, NR_fork, NR_waitpid, nr_exit

def test_fifo_dep():
    def pipe_syscall(nr, pipe, ret, res_id, serial):
        return [
                scribe.EventSyscallExtra(nr = nr, ret = ret),
                scribe.EventResourceLockExtra(
                        id = res_id, desc='pipe:[%d]' % pipe,
                        serial = serial, type = scribe.SCRIBE_RES_TYPE_FILE),
                scribe.EventSyscallEnd()]
    events = [
          [scribe.EventPid(pid=1)],
          pipe_syscall(nr=NR_read,  pipe=1, ret=2,  res_id=1, serial=1), # i=0
          pipe_syscall(nr=NR_read,  pipe=1, ret=1,  res_id=1, serial=2), # i=1
          pipe_syscall(nr=NR_read,  pipe=1, ret=3,  res_id=1, serial=3), # i=2
          pipe_syscall(nr=NR_read,  pipe=1, ret=1,  res_id=1, serial=4), # i=3
          [scribe.EventPid(pid=2)],
          pipe_syscall(nr=NR_write, pipe=1, ret=3,  res_id=2, serial=1), # i=4
          pipe_syscall(nr=NR_write, pipe=1, ret=2,  res_id=2, serial=2), # i=5
          pipe_syscall(nr=NR_write, pipe=1, ret=5,  res_id=2, serial=3), # i=6
          pipe_syscall(nr=NR_write, pipe=1, ret=5,  res_id=2, serial=4)  # i=7
             ]

    g = ExecutionGraph(e for el in events for e in el)
    sys = [e for e in g.events if e.is_a(scribe.EventSyscallExtra)]
    procs = g.processes

    assert_equal(set(g.edges()) ^ set([
        # natural edges
        (procs[1].anchor, sys[0]),
        (sys[0], sys[1]),
        (sys[1], sys[2]),
        (sys[2], sys[3]),
        # shouldn't we include the natural deps of pid=2 ?
        # pipe deps
        (sys[4], sys[0]),
        (sys[4], sys[1]),
        (sys[4], sys[1]),
        (sys[5], sys[2]),
        (sys[6], sys[2]),
        (sys[6], sys[3])]), set())
