from nose.tools import *
from racepro.session import *
from racepro.unistd import *

def test_event_str():
    e = Event(scribe.EventRegs())
    assert_equal(repr(e), repr(scribe.EventRegs()))
    assert_equal(str(e), str(scribe.EventRegs()))

def test_event_encode():
    e = Event(scribe.EventRegs())
    assert_equal(e.encode(), scribe.EventRegs().encode())

def test_event_attr():
    e = Event(scribe.EventSyscallExtra(nr = 3))
    assert_equal(e.nr, 3)
    e = Event(scribe.EventResourceLockExtra(id = 3))
    assert_equal(e.id, 3)

def test_event_is():
    e = Event(scribe.EventSyscallExtra(nr = 3))
    assert_true(e.is_a(scribe.EventSyscallExtra))
    assert_false(e.is_a(scribe.EventResourceLockExtra))

def test_event_list():
    e1 = Event(scribe.EventRegs())
    e2 = Event(scribe.EventRegs())
    e3 = Event(scribe.EventRegs())

    el1 = EventList()
    el1.append(e1)
    el1.append(e2)
    el1.append(e3)

    el2 = EventList()
    el2.append(e2)
    el2.append(e3)

    el3 = EventList()
    el3.append(e2)

    assert_equal(list(el1), [e1, e2, e3])
    assert_equal(list(el2), [e2, e3])
    assert_equal(list(el3), [e2])

    assert_equal(list(el1.after(e1)), [e2, e3])
    assert_equal(list(el3.after(e2)), [])

    assert_equal(list(el1.before(e2)), [e1])
    assert_equal(list(el1.before(e3)), [e2, e1])
    assert_equal(list(el2.before(e2)), [])

    assert_equal(el1.index(e2), 1)
    assert_equal(el2.index(e2), 0)
    assert_equal(el3.index(e2), 0)
    assert_raises(ValueError, el3.index, e3)

    assert_equal(el1[0], e1)
    assert_equal(el1[-1], e3)

    assert_raises(ValueError, el3.after, e1)

    el1.extend(el2)
    assert_equal(list(el1), [e1, e2, e3, e2, e3])


def test_event_doesnt_belong_to_proc_by_default():
    e = Event(scribe.EventRegs())
    assert_equal(e.proc, None)

def test_add_proc_events_sets_event_proc():
    proc = Process(pid=1)
    e = Event(scribe.EventRegs())
    proc.add_event(e)
    assert_equal(e.proc, proc)

def test_event_no_proc():
    e = Event(scribe.EventSyscallExtra(1))
    def get_children(e):
        return e.children
    assert_raises(AttributeError, get_children, e)

def test_process_syscall():
    events = [ scribe.EventFence(),             # 0
               scribe.EventSyscallExtra(1),     # 1
               scribe.EventRegs(),              # 2
               scribe.EventSyscallEnd(),        # 3
               scribe.EventRdtsc(),             # 4
               scribe.EventSyscallExtra(2),     # 5
               scribe.EventData('hello'),       # 6
               scribe.EventData('world'),       # 7
               scribe.EventSyscallEnd(),        # 8
               scribe.EventSyscallExtra(3),     # 9
               scribe.EventSyscallEnd() ]       # 10
    events = map(lambda se: Event(se), events)

    proc = Process(pid=1)
    for event in events:
        proc.add_event(event)

    proc_events = list(proc.events)
    assert_equal(len(proc_events), 11)

    assert_equal(list(proc_events[1].children), [events[2]])
    assert_equal(list(proc_events[5].children), [events[6], events[7]])
    assert_equal(list(proc_events[9].children), [])

    assert_equal(list(proc_events[6].children), [])

    def get_syscall(e):
        return e.syscall
    assert_raises(AttributeError, get_syscall, events[0])
    assert_raises(AttributeError, get_syscall, events[4])

    assert_equal(events[1].syscall, events[1])
    assert_equal(events[2].syscall, events[1])
    assert_equal(events[6].syscall, events[5])
    assert_equal(events[7].syscall, events[5])

    def get_syscall_index(e):
        return e.syscall_index
    assert_raises(AttributeError, get_syscall_index, events[0])
    assert_raises(AttributeError, get_syscall_index, events[6])

    assert_equal(events[1].syscall_index, 0)
    assert_equal(events[5].syscall_index, 1)
    assert_equal(events[9].syscall_index, 2)

    assert_equal(list(proc.syscalls), [events[1], events[5], events[9]])


def test_process_name():
    events = [ scribe.EventSyscallExtra(nr=unistd.NR_execve, ret=0),
               scribe.EventFence(),
               scribe.EventDataExtra(data_type = scribe.SCRIBE_DATA_INPUT,
                                     data = 'bad'),
               scribe.EventDataExtra(data_type = scribe.SCRIBE_DATA_INPUT |
                                                 scribe.SCRIBE_DATA_STRING,
                                     data = 'cmd1'),
               scribe.EventFence(),
               scribe.EventSyscallEnd(),

               scribe.EventSyscallExtra(nr=unistd.NR_execve, ret=0),
               scribe.EventDataExtra(data_type = scribe.SCRIBE_DATA_INPUT |
                                                 scribe.SCRIBE_DATA_STRING,
                                     data = 'cmd2'),
               scribe.EventFence(),
               scribe.EventDataExtra(data_type = scribe.SCRIBE_DATA_INPUT |
                                                 scribe.SCRIBE_DATA_STRING,
                                     data = 'bad'),
               scribe.EventFence(),
               scribe.EventSyscallEnd() ]

    proc = Process(pid=1)
    assert_equal(proc.name, None)

    for event in events:
        proc.add_event(Event(event))
    assert_equal(proc.name, 'cmd2')

    events[6].ret = -1 # if execve() < 0, it should not process the name
    proc = Process(pid=1)
    for event in events:
        proc.add_event(Event(event))
    assert_equal(proc.name, 'cmd1')

def test_process_str():
    proc = Process(pid=1, name='cmd')
    assert_equal(str(proc), 'pid=1 (cmd)')

    proc = Process(pid=1)
    assert_equal(str(proc), 'pid=1 (??)')

def test_process_repr():
    proc = Process(pid=1, name='cmd')
    proc.add_event(Event(scribe.EventFence()))
    proc.add_event(Event(scribe.EventSyscallExtra()))

    assert_equal(repr(proc), "<Process pid=1 name='cmd' events=2>")

def test_session_events():
    events = [ scribe.EventFence(), scribe.EventRegs() ]

    session = Session(events)
    assert_equal(len(session.events), 2)
    assert_true(isinstance(session.events[0], Event))

    session = Session(map(lambda se: Event(se), events))
    assert_equal(len(session.events), 2)
    assert_true(isinstance(session.events[0], Event))

def test_process_pid():
    events = [ scribe.EventFence(),             # 0
               scribe.EventPid(pid=1),          # 1
               scribe.EventRdtsc(),             # 2
               scribe.EventSyscallExtra(2),     # 3
               scribe.EventPid(pid=2),          # 4
               scribe.EventRdtsc(),             # 5
               scribe.EventPid(pid=1),          # 6
               scribe.EventPid(pid=2),          # 7
               scribe.EventPid(pid=1),          # 8
               scribe.EventData('hello'),       # 9
               scribe.EventSyscallEnd() ]       # 10

    session = Session(events)
    events = list(session.events)

    assert_equal(len(events), 11)
    assert_equal(len(session.processes), 2)
    assert_equal(session.processes[1].pid, 1)
    assert_equal(session.processes[2].pid, 2)
    assert_equal(list(session.processes[1].events), [events[2], events[3],
                                                     events[9], events[10]])
    assert_equal(list(session.processes[2].events), [events[5]])

    assert_equal(session.processes[1], session.init_proc)

def test_resource_init():
    res = Resource()
    res.add_event(Event(scribe.EventResourceLockExtra(id=2, type=3, desc='hello')))
    assert_equal(res.id, 2)
    assert_equal(res.type, 3)
    assert_equal(res.desc, 'hello')

def test_resource_repr():
    res = Resource()
    assert_equal(repr(res), "<Resource not initialized>")
    res.add_event(Event(scribe.EventResourceLockExtra(id=2, type=2, desc='hello')))
    res.add_event(Event(scribe.EventResourceLockExtra(id=2, type=2, desc='hello')))
    assert_equal(repr(res), "<Resource id=2 type=2 desc='hello' events=2>")

def test_session_resource():
    events = [ scribe.EventResourceLockExtra(id=1, serial=3),  # 0
               scribe.EventFence(),                            # 1
               scribe.EventResourceLockExtra(id=2, serial=8),  # 2
               scribe.EventResourceLockExtra(id=1, serial=2),  # 3
               scribe.EventPid(pid=1),                         # 4
               scribe.EventResourceLockExtra(id=1, serial=1),  # 5
               scribe.EventResourceLockExtra(id=2, serial=3),  # 6
               scribe.EventFence(),                            # 7
               scribe.EventResourceLockExtra(id=1, serial=4) ] # 8

    session = Session(events)
    events = list(session.events)

    assert_equal(len(session.resources), 2)
    assert_equal(session.resources[1].id, 1)
    assert_equal(session.resources[2].id, 2)
    assert_equal(list(session.resources[1].events), [events[5], events[3],
                                                     events[0], events[8]])
    assert_equal(list(session.resources[2].events), [events[6], events[2]])

    def get_resource(e):
        return e.resource
    assert_raises(AttributeError, get_resource, events[1])
    assert_equal(events[3].resource, session.resources[1])
    assert_equal(events[6].resource, session.resources[2])

def test_pipe():
    def gen_test_pipe(read_nr, write_nr):
        def pipe_syscall(nr, pipe, ret, res_id, serial):
            return [
                    scribe.EventSyscallExtra(nr = nr, ret = ret),
                    scribe.EventFence(),
                    scribe.EventResourceLockExtra(
                            id = res_id, desc='pipe:[%d]' % pipe,
                            serial = serial, type = scribe.SCRIBE_RES_TYPE_FILE),
                    scribe.EventFence(),
                    scribe.EventSyscallEnd()]

        events = [
          [scribe.EventPid(pid=1)],
          pipe_syscall(nr=unistd.NR_fstat64, pipe=1, ret=5,  res_id=1, serial=1), # buf=0 i=0
          pipe_syscall(nr=read_nr,  pipe=1, ret=3,  res_id=1, serial=2), # buf=2 i=1
          pipe_syscall(nr=read_nr,  pipe=1, ret=-1, res_id=1, serial=3), # buf=2 i=2
          pipe_syscall(nr=read_nr,  pipe=3, ret=1,  res_id=3, serial=2), # buf=4 i=3
          pipe_syscall(nr=read_nr,  pipe=1, ret=1,  res_id=1, serial=4), # buf=1 i=4
          [scribe.EventPid(pid=2)],
          pipe_syscall(nr=write_nr, pipe=1, ret=3,  res_id=2, serial=1), # buf=3 i=5
          pipe_syscall(nr=write_nr, pipe=1, ret=2,  res_id=2, serial=2), # buf=5 i=6
          [scribe.EventPid(pid=3)],
          pipe_syscall(nr=write_nr, pipe=1, ret=-1, res_id=2, serial=3), # buf=0 i=7
          pipe_syscall(nr=write_nr, pipe=1, ret=5,  res_id=2, serial=4), # buf=5 i=8
          pipe_syscall(nr=write_nr, pipe=3, ret=5,  res_id=4, serial=1), # buf=5 i=9
          pipe_syscall(nr=read_nr,  pipe=3, ret=3,  res_id=3, serial=1), # buf=1 i=10
        ]
        session = Session(e for el in events for e in el)
        syscalls = [e for e in session.events
                    if e.is_a(scribe.EventSyscallExtra)]

        assert_equal(len(session.fifos), 2)
        assert_equal(list(session.fifos[0].reads), [syscalls[1], syscalls[2], syscalls[4]])
        assert_equal(list(session.fifos[0].writes), [syscalls[5], syscalls[6], syscalls[7], syscalls[8]])
        assert_equal(list(session.fifos[1].reads),  [syscalls[10], syscalls[3]])
        assert_equal(list(session.fifos[1].writes), [syscalls[9]])

    for read_nr in [unistd.NR_read, unistd.NR_readv,
                    unistd.NR_pread64, unistd.NR_preadv]:
        for write_nr in [unistd.NR_write, unistd.NR_writev,
                         unistd.NR_pwrite64, unistd.NR_pwritev]:
            yield gen_test_pipe, read_nr, write_nr

def test_socket():
    def gen_test_socket(read_nr, write_nr):
        def socket_syscall(nr, sock1, sock2, ret, res_id, serial):
            desc = 'socket:[%d]' % sock1
            if sock2:
                desc += ' socket:[%d]' % sock2
            return [
                    scribe.EventSyscallExtra(nr = nr, ret = ret),
                    scribe.EventFence(),
                    scribe.EventResourceLockExtra(
                            id = res_id, desc = desc, serial = serial,
                            type = scribe.SCRIBE_RES_TYPE_FILE),
                    scribe.EventFence(),
                    scribe.EventSyscallEnd()]

        events = [
          [scribe.EventPid(pid=1)],
          socket_syscall(nr=unistd.NR_fstat64, sock1=1, sock2=None, ret=5, res_id=1, serial=1), # i=0
          socket_syscall(nr=write_nr, sock1=1, sock2=None, ret=-1,  res_id=1, serial=2), # i=1
          socket_syscall(nr=write_nr, sock1=1, sock2=2,    ret=3,   res_id=1, serial=3), # i=2
          socket_syscall(nr=read_nr,  sock1=1, sock2=2,    ret=10,  res_id=1, serial=4), # i=3
          socket_syscall(nr=read_nr,  sock1=1, sock2=None, ret=5,   res_id=1, serial=5), # i=4
          [scribe.EventPid(pid=2)],
          socket_syscall(nr=read_nr,  sock1=2, sock2=1,    ret=1,   res_id=2, serial=1), # i=5
          socket_syscall(nr=write_nr, sock1=2, sock2=1,    ret=15,  res_id=2, serial=2), # i=6
          socket_syscall(nr=read_nr,  sock1=2, sock2=None, ret=2,   res_id=2, serial=3), # i=7
        ]
        session = Session(e for el in events for e in el)
        syscalls = [e for e in session.events
                    if e.is_a(scribe.EventSyscallExtra)]

        assert_equal(len(session.fifos), 2)
        assert_equal(list(session.fifos[0].reads), [syscalls[5], syscalls[7]])
        assert_equal(list(session.fifos[0].writes), [syscalls[1], syscalls[2]])
        assert_equal(list(session.fifos[1].reads),  [syscalls[3], syscalls[4]])
        assert_equal(list(session.fifos[1].writes), [syscalls[6]])

    for read_nr in [unistd.NR_read, unistd.NR_readv,
                    unistd.NR_pread64, unistd.NR_preadv]:
        for write_nr in [unistd.NR_write, unistd.NR_writev,
                         unistd.NR_pwrite64, unistd.NR_pwritev]:
            yield gen_test_socket, read_nr, write_nr
    # not in the same loop to limit the number of tests generated
    for read_nr in [NR_recv, NR_recvfrom, NR_recvmsg]:
        for write_nr in [NR_send, NR_sendto, NR_sendmsg]:
            yield gen_test_socket, read_nr, write_nr


def test_signal():
    events = [
               scribe.EventPid(pid=1),                 # 0
               scribe.EventFence(),                    # 1
               scribe.EventSyscallExtra(),             # 2
               scribe.EventFence(),                    # 3
               scribe.EventSigSendCookie(cookie=1),    # 4
               scribe.EventSyscallEnd(),               # 5
               scribe.EventSyscallExtra(),             # 6
               scribe.EventFence(),                    # 7
               scribe.EventSigRecvCookie(cookie=2),    # 8
               scribe.EventSyscallEnd(),               # 9
               scribe.EventPid(pid=2),                 # 10
               scribe.EventSyscallExtra(),             # 11
               scribe.EventFence(),                    # 12
               scribe.EventSigRecvCookie(cookie=1),    # 13
               scribe.EventSyscallEnd(),               # 14
               scribe.EventFence(),                    # 15
               scribe.EventSyscallExtra(),             # 16
               scribe.EventFence(),                    # 17
               scribe.EventSigSendCookie(cookie=2),    # 18
               scribe.EventSyscallEnd(),               # 19
               scribe.EventSigHandledCookie(cookie=1), # 20
             ]

    session = Session(events)
    events = list(session.events)

    assert_equal(len(session.signals), 2)
    assert_equal(session.signals[0].send,    events[4])
    assert_equal(session.signals[0].recv,    events[13])
    assert_equal(session.signals[0].handled, events[20])

    assert_equal(session.signals[1].send,    events[18])
    assert_equal(session.signals[1].recv,    events[8])
    assert_equal(session.signals[1].handled, None)

@raises(ValueError)
def test_signal_no_recv():
    events = [
               scribe.EventPid(pid=1),
               scribe.EventSyscallExtra(),
               scribe.EventSigSendCookie(cookie=1),
               scribe.EventSyscallEnd(),
             ]

    session = Session(events)

@raises(ValueError)
def test_signal_no_send():
    events = [
               scribe.EventPid(pid=1),
               scribe.EventSyscallExtra(),
               scribe.EventSigRecvCookie(cookie=1),
               scribe.EventSyscallEnd(),
             ]

    session = Session(events)

def test_creators():
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


    g = Session(events)
    e = list(g.events)
    p = g.processes

    assert_equal(p[1].creator, None)
    assert_equal(p[2].creator, p[1])
    assert_equal(p[3].creator, p[1])
    assert_equal(p[4].creator, p[2])
