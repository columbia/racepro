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
                   scribe.EventSyscallExtra(nr=NR_read, ret=0),  # 13
                   scribe.EventSyscallExtra(nr=nr_exit, ret=0),  # 14
                   scribe.EventPid(pid=4),                       # 15
                   scribe.EventSyscallExtra(nr=nr_exit, ret=0)   # 16
                 ]
        # p1: p1f e2 e3 e4 e5              e6     e7         e8 e9 p1l
        #             \  \                 /      /          /
        # p2:         p2f \               / e11 p2l         /
        #                  \             /    \            /
        # p3:              p3f e13 e14 p3l     \          /
        #                                       \        /
        # p4:                                   p4f e16 p4l

        g = ExecutionGraph(events)
        e = list(g.events)
        p = g.processes

        assert_equal(set(g.edges_labeled('fork')), set([
            (e[3],  p[2].first_anchor),
            (e[4],  p[3].first_anchor),
            (e[11], p[4].first_anchor)]))

        assert_equal(set(g.edges_labeled('exit')), set([
            (p[2].last_anchor, e[7]),
            (p[3].last_anchor, e[6]),
            (p[4].last_anchor, e[8])]))

    for nr_fork in [NR_fork, NR_clone, NR_vfork]:
        yield gen_test_fork_process_edge, nr_fork, NR_waitpid, NR_exit
    for nr_wait in [NR_waitpid, NR_wait4, NR_waitid]:
        yield gen_test_fork_process_edge, NR_fork, nr_wait, NR_exit
    for nr_exit in [NR_exit, NR_exit_group]:
        yield gen_test_fork_process_edge, NR_fork, NR_waitpid, nr_exit

def pipe_syscall(nr, pipe, ret, res_id, serial):
    return [
            scribe.EventSyscallExtra(nr = nr, ret = ret),
            scribe.EventResourceLockExtra(
                    id = res_id, desc='pipe:[%d]' % pipe,
                    serial = serial, type = scribe.SCRIBE_RES_TYPE_FILE),
            scribe.EventSyscallEnd()]

def test_fifo_dep():
    events = [
          [scribe.EventPid(pid=1)],
          [scribe.EventSyscallExtra(nr=NR_fork, ret=2)],                 # i=0
          pipe_syscall(nr=NR_read,  pipe=1, ret=2,  res_id=1, serial=1), # i=1
          pipe_syscall(nr=NR_read,  pipe=1, ret=-1, res_id=1, serial=2), # i=2
          pipe_syscall(nr=NR_read,  pipe=1, ret=1,  res_id=1, serial=3), # i=3
          pipe_syscall(nr=NR_read,  pipe=1, ret=3,  res_id=1, serial=4), # i=4
          pipe_syscall(nr=NR_read,  pipe=1, ret=1,  res_id=1, serial=5), # i=5
          [scribe.EventPid(pid=2)],
          pipe_syscall(nr=NR_write, pipe=1, ret=3,  res_id=2, serial=1), # i=6
          pipe_syscall(nr=NR_write, pipe=1, ret=-1, res_id=2, serial=2), # i=7
          pipe_syscall(nr=NR_write, pipe=1, ret=2,  res_id=2, serial=3), # i=8
          pipe_syscall(nr=NR_write, pipe=1, ret=5,  res_id=2, serial=4), # i=9
          pipe_syscall(nr=NR_write, pipe=1, ret=5,  res_id=2, serial=5)  # i=10
             ]
    # p1: p1f s0         s1 s2 s3          s4  s5     p1l
    #          \         /     /        .--/   /
    #           \       +-----+        /  +---+
    #            \     /              /  /
    # p2:        p2f  s6         s7 s8  s9        s10 p2l

    g = ExecutionGraph(e for el in events for e in el)
    sys = [e for e in g.events if e.is_a(scribe.EventSyscallExtra)]

    assert_equal(set(g.edges_labeled('fifo')), set([
        (sys[6], sys[1]),
        (sys[6], sys[3]),
        (sys[8], sys[4]),
        (sys[9], sys[4]),
        (sys[9], sys[5])]))

def test_signal_dep():
    events = [
               scribe.EventPid(pid=1),                      # 0
               scribe.EventSyscallExtra(nr=NR_fork, ret=2), # 1
               scribe.EventFence(),                         # 2
               scribe.EventSyscallExtra(),                  # 3
               scribe.EventFence(),                         # 4
               scribe.EventSigSendCookie(cookie=1),         # 5
               scribe.EventSyscallEnd(),                    # 6
               scribe.EventSyscallExtra(),                  # 7
               scribe.EventFence(),                         # 8
               scribe.EventSigRecvCookie(cookie=2),         # 9
               scribe.EventSyscallEnd(),                    # 10
               scribe.EventPid(pid=2),                      # 11
               scribe.EventSyscallExtra(),                  # 12
               scribe.EventFence(),                         # 13
               scribe.EventSigRecvCookie(cookie=1),         # 14
               scribe.EventSyscallEnd(),                    # 15
               scribe.EventFence(),                         # 16
               scribe.EventSyscallExtra(),                  # 17
               scribe.EventFence(),                         # 18
               scribe.EventSigSendCookie(cookie=2),         # 19
               scribe.EventSyscallEnd(),                    # 20
               scribe.EventSigHandledCookie(cookie=1),      # 21
             ]

    g = ExecutionGraph(events)
    e = list(g.events)

    assert_equal(set(g.edges_labeled('signal')), set([
        (e[3],  e[12]),
        (e[17], e[7])]))

def test_vclocks():
    events = [
               scribe.EventPid(pid=1),                        # 0
               scribe.EventSyscallExtra(nr=NR_fork,  ret=-1), # 1
               scribe.EventSyscallExtra(nr=NR_fork,  ret=2),  # 2
               scribe.EventSyscallExtra(nr=NR_fork,  ret=3),  # 3
               scribe.EventSyscallExtra(nr=NR_wait4, ret=-1), # 4
               scribe.EventSyscallExtra(nr=NR_wait4, ret=3),  # 5
               scribe.EventSyscallExtra(nr=NR_wait4, ret=2),  # 6
               scribe.EventSyscallExtra(nr=NR_wait4, ret=4),  # 7
               scribe.EventSyscallExtra(nr=NR_exit,  ret=0),  # 8
               scribe.EventPid(pid=2),                        # 9
               scribe.EventSyscallExtra(nr=NR_fork,  ret=4),  # 10
               scribe.EventPid(pid=3),                        # 11
               scribe.EventSyscallExtra(nr=NR_read,  ret=0),  # 12
               scribe.EventSyscallExtra(nr=NR_exit,  ret=0),  # 13
               scribe.EventPid(pid=4),                        # 14
               scribe.EventSyscallExtra(nr=NR_exit,  ret=0)   # 15
             ]
    # p1: p1f e1 e2 e3 e4              e5     e6         e7 e8 p1l
    #             \  \                 /      /          /
    # p2:         p2f \               / e10 p2l         /
    #                  \             /    \            /
    # p3:              p3f e12 e13 p3l     \          /
    #                                       \        /
    # p4:                                   p4f e15 p4l


    g = ExecutionGraph(events)
    e = list(g.events)
    p = g.processes

    def vc(*l):
        procs = sorted(p.values(), key=lambda p: p.pid)
        return VectorClock(dict(zip(procs, l)))

    # Following standard vclock behavior as
    # defined at http://en.wikipedia.org/wiki/Vector_clock
    assert_equal(p[ 1].first_anchor.vclock, vc(1, 0, 0, 0))
    assert_equal(e[ 1].vclock,              vc(2, 0, 0, 0))
    assert_equal(e[ 2].vclock,              vc(3, 0, 0, 0))
    assert_equal(p[ 2].first_anchor.vclock, vc(3, 1, 0, 0))
    assert_equal(e[ 3].vclock,              vc(4, 0, 0, 0))
    assert_equal(p[ 3].first_anchor.vclock, vc(4, 0, 1, 0))
    assert_equal(e[ 4].vclock,              vc(5, 0, 0, 0))
    assert_equal(e[12].vclock,              vc(4, 0, 2, 0))
    assert_equal(e[13].vclock,              vc(4, 0, 3, 0))
    assert_equal(p[ 3].last_anchor.vclock,  vc(4, 0, 4, 0))
    assert_equal(e[ 5].vclock,              vc(6, 0, 4, 0))
    assert_equal(e[10].vclock,              vc(3, 2, 0, 0))
    assert_equal(p[ 4].first_anchor.vclock, vc(3, 2, 0, 1))
    assert_equal(p[ 2].last_anchor.vclock,  vc(3, 3, 0, 0))
    assert_equal(e[ 6].vclock,              vc(7, 3, 4, 0))
    assert_equal(e[15].vclock,              vc(3, 2, 0, 2))
    assert_equal(p[ 4].last_anchor.vclock,  vc(3, 2, 0, 3))
    assert_equal(e[ 7].vclock,              vc(8, 3, 4, 3))
    assert_equal(e[ 8].vclock,              vc(9, 3, 4, 3))
    assert_equal(p[ 1].last_anchor.vclock,  vc(10, 3, 4, 3))

def test_vclocks_multiple():
    events = [
          [scribe.EventPid(pid=1)],
          [scribe.EventSyscallExtra(nr=NR_fork, ret=2)],                 # i=0
          pipe_syscall(nr=NR_read,  pipe=1, ret=2,  res_id=1, serial=1), # i=1
          pipe_syscall(nr=NR_read,  pipe=1, ret=1,  res_id=1, serial=2), # i=2
          pipe_syscall(nr=NR_read,  pipe=1, ret=3,  res_id=1, serial=3), # i=3
          pipe_syscall(nr=NR_read,  pipe=1, ret=1,  res_id=1, serial=4), # i=4
          [scribe.EventPid(pid=2)],
          pipe_syscall(nr=NR_write, pipe=1, ret=3,  res_id=2, serial=1), # i=5
          pipe_syscall(nr=NR_write, pipe=1, ret=2,  res_id=2, serial=2), # i=6
          pipe_syscall(nr=NR_write, pipe=1, ret=5,  res_id=2, serial=3), # i=7
          pipe_syscall(nr=NR_write, pipe=1, ret=5,  res_id=2, serial=4)  # i=8
             ]
    # p1: p1f s0         s1 s2        s3  s4    p1l
    #          \         /  /      .--/   /
    #           \       +--+      /  +---+
    #            \     /         /  /
    # p2:        p2f  s5       s6  s7        s8 p2l

    g = ExecutionGraph(e for el in events for e in el)
    s = [e for e in g.events if e.is_a(scribe.EventSyscallExtra)]
    p = g.processes

    def vc(*l):
        procs = sorted(p.values(), key=lambda p: p.pid)
        return VectorClock(dict(zip(procs, l)))

    assert_equal(p[1].first_anchor.vclock, vc(1, 0))
    assert_equal(s[0].vclock,              vc(2, 0))
    assert_equal(p[2].first_anchor.vclock, vc(2, 1))
    assert_equal(s[5].vclock,              vc(2, 2))
    assert_equal(s[1].vclock,              vc(3, 2))
    assert_equal(s[2].vclock,              vc(4, 2))
    assert_equal(s[6].vclock,              vc(2, 3))
    assert_equal(s[7].vclock,              vc(2, 4))
    assert_equal(s[3].vclock,              vc(5, 4))
    assert_equal(s[4].vclock,              vc(6, 4))
    assert_equal(s[8].vclock,              vc(2, 5))
    assert_equal(p[1].last_anchor.vclock,  vc(7, 4))
    assert_equal(p[2].last_anchor.vclock,  vc(2, 6))

def test_crosscut():
    events = [
               scribe.EventPid(pid=1),                        # 0
               scribe.EventRegs(),                            # 1
               scribe.EventSyscallExtra(nr=NR_fork,  ret=-1), # 2
               scribe.EventSyscallExtra(nr=NR_fork,  ret=2),  # 3
               scribe.EventSyscallExtra(nr=NR_fork,  ret=3),  # 4
               scribe.EventSyscallExtra(nr=NR_wait4, ret=-1), # 5
               scribe.EventSyscallExtra(nr=NR_wait4, ret=3),  # 6
               scribe.EventSyscallExtra(nr=NR_wait4, ret=2),  # 7
               scribe.EventSyscallExtra(nr=NR_wait4, ret=4),  # 8
               scribe.EventSyscallExtra(nr=NR_exit,  ret=0),  # 9
               scribe.EventPid(pid=2),                        # 10
               scribe.EventSyscallExtra(nr=NR_fork,  ret=4),  # 11
               scribe.EventPid(pid=3),                        # 12
               scribe.EventSyscallExtra(nr=NR_read,  ret=0),  # 13
               scribe.EventSyscallExtra(nr=NR_exit,  ret=0),  # 14
               scribe.EventPid(pid=4),                        # 15
               scribe.EventSyscallExtra(nr=NR_exit,  ret=0)   # 16
             ]
    # p1: p1f e2 e3 e4 e5              e6     e7         e8 e9 p1l
    #             \  \                 /      /          /
    # p2:         p2f \               / e11 p2l         /
    #                  \             /    \            /
    # p3:              p3f e13 e14 p3l     \          /
    #                                       \        /
    # p4:                                   p4f e16 p4l

    g = ExecutionGraph(events)
    e = list(g.events)
    p = g.processes

    assert_raises(ValueError, g.crosscut, [])

    assert_equal(set(g.crosscut([NodeLoc(e[14], 'before')])),
                 set([NodeLoc(e[4],              'after'),
                      NodeLoc(p[2].first_anchor, 'after'),
                      NodeLoc(e[14],             'before'),
                      NodeLoc(p[4].first_anchor, 'before')]))

    assert_equal(set(g.crosscut([e[14], e[11]])),
                 set([NodeLoc(e[4],              'after'),
                      NodeLoc(e[11],             'before'),
                      NodeLoc(e[14],             'before'),
                      NodeLoc(p[4].first_anchor, 'before')]))

    assert_equal(set(g.crosscut([p[2].last_anchor])),
                 set([NodeLoc(e[3],              'after'),
                      NodeLoc(p[2].last_anchor,  'before'),
                      NodeLoc(p[3].first_anchor, 'before'),
                      NodeLoc(p[4].first_anchor, 'after')]))

    assert_raises(ValueError, g.crosscut, [e[14], e[2]])

    for node in g.nodes():
        nl = NodeLoc(node, 'before')
        assert_true(nl in g.crosscut([nl]))
        assert_equal(g.crosscut([nl]), g.crosscut([node]))
        nl = NodeLoc(node, 'after')
        assert_true(nl in g.crosscut([nl]))
