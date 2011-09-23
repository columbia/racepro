from nose.tools import *
from racepro.mutator import *
from racepro.session import *
from racepro.unistd import *
from racepro.execgraph import *

class ToStr(Mutator):
    def process_events(self, events, options={}):
        for event in events:
            yield str(event)

class ToRaw(Mutator):
    def process_events(self, events, options={}):
        for event in events:
            yield event._scribe_event

class Nop(Mutator):
    def process_events(self, events, options={}):
        for event in events:
            yield event

class RemoveEventPid(Mutator):
    def process_events(self, events, options={}):
        for event in events:
            if not event.is_a(scribe.EventPid):
                yield event

def test_base_class():
    out = ToStr().process_events([1,2,3])
    assert_equal(list(out), ['1','2','3'])

def test_replace():
    out = Replace({1:5, 3:8}).process_events([1,2,3])
    assert_equal(list(out), [5,2,8])

def test_pipe():
    out = [1,2,3] | Replace({1:3}) | Replace({3:5}) | ToStr()
    assert_equal(list(out), ['5','2','5'])

def test_adjust_resources():
    # The tests were written at some point. Where are they ?
    pass

def test_insert_pid_events():
    events = [
               scribe.EventPid(pid=1),
               scribe.EventFence(),
               scribe.EventFence(),
               scribe.EventPid(pid=3),
               scribe.EventPid(pid=2),
               scribe.EventPid(pid=2),
               scribe.EventFence(),
               scribe.EventPid(pid=3),
               scribe.EventFence(),
             ]
    out = Session(events).events | InsertPidEvents() | ToRaw()
    should_be = [
               scribe.EventPid(pid=1),
               scribe.EventFence(),
               scribe.EventFence(),
               scribe.EventPid(pid=2),
               scribe.EventFence(),
               scribe.EventPid(pid=3),
               scribe.EventFence(),
             ]

    assert_equal(list(out), should_be)

def test_insert_eoq_events():
    events = [
               scribe.EventPid(pid=1),
               scribe.EventFence(),
               scribe.EventPid(pid=2),
               scribe.EventFence(),
               scribe.EventQueueEof(),
               scribe.EventPid(pid=3),
               scribe.EventFence(),
             ]
    out = Session(events).events | InsertEoqEvents() | \
                                   InsertPidEvents() | ToRaw()
    should_be = [
               scribe.EventPid(pid=1),
               scribe.EventFence(),
               scribe.EventPid(pid=2),
               scribe.EventFence(),
               scribe.EventQueueEof(),
               scribe.EventPid(pid=3),
               scribe.EventFence(),
               scribe.EventPid(pid=1),
               scribe.EventQueueEof(),
               scribe.EventPid(pid=3),
               scribe.EventQueueEof(),
             ]

    assert_equal(list(out), should_be)

def test_cat_graph():
    events = [
               scribe.EventInit(),                            # 0
               scribe.EventPid(pid=1),                        # 1
               scribe.EventSyscallExtra(nr=NR_fork,  ret=2),  # 2
               scribe.EventSyscallExtra(nr=NR_wait4, ret=2),  # 3
               scribe.EventSyscallExtra(nr=NR_exit,  ret=0),  # 4
               scribe.EventPid(pid=2),                        # 5
               scribe.EventSyscallExtra(nr=NR_read,  ret=0),  # 6
               scribe.EventFence(),                           # 7
               scribe.EventSyscallEnd(),                      # 8
               scribe.EventFence(),                           # 9
               scribe.EventSyscallExtra(nr=NR_exit,  ret=0),  # 10
             ]

    # p1: p1f e2                     e3 e4 p1l
    #          \                    /
    # p2:      p2f e6 e7 e8 e9 e10 p2l

    g = ExecutionGraph(events)
    e = list(g.events)
    p = g.processes

    out = CatGraph(g)

    should_be = [
                  e[0],
                  p[1].first_anchor,
                  e[2],
                  p[2].first_anchor,
                  e[6],
                  e[7],
                  e[8],
                  e[9],
                  e[10],
                  p[2].last_anchor,
                  e[3],
                  e[4],
                  p[1].last_anchor,
               ]

    assert_equal(list(out), should_be)

    out = g | Nop() # Piping a graph directly should work too
    assert_equal(list(out), should_be)

def test_insert():
    out = [1,5,10] | Insert({ NodeLoc(1, 'after'): 2,
                              NodeLoc(5, 'before'): 3,
                              NodeLoc(10, 'after'): 20,
                              NodeLoc(99, 'before'): -1 })

    assert_equal(list(out), [1,2,3,5,10,20])

def test_truncate_queue():
    events = [
               scribe.EventPid(pid=1),   # 0
               scribe.EventFence(),      # 1
               scribe.EventFence(),      # 2
               scribe.EventPid(pid=2),   # 3
               scribe.EventFence(),      # 4
               scribe.EventPid(pid=3),   # 5
               scribe.EventFence(),      # 6
               scribe.EventFence(),      # 7
               scribe.EventPid(pid=1),   # 8
               scribe.EventFence(),      # 9
               scribe.EventFence(),      # 10
               scribe.EventPid(pid=2),   # 11
               scribe.EventFence(),      # 12
             ]
    s = Session(events)
    e = list(s.events)
    out = e | TruncateQueue([ NodeLoc(e[1], 'after'),
                              NodeLoc(e[2], 'after'),
                              NodeLoc(e[12], 'before') ])
    out |= RemoveEventPid()

    should_be = [
                  e[1],
                  e[4],
                  e[6],
                  e[7],
               ]

    assert_equal(list(out), should_be)

def test_truncate_queue_atom():
    events = [
               scribe.EventPid(pid=1),   # 0
               scribe.EventFence(),      # 1
               scribe.EventFence(),      # 2
               scribe.EventPid(pid=2),   # 3
               scribe.EventFence(),      # 4
             ]

    s = Session(events)
    e = list(s.events)
    out = e | TruncateQueue( NodeLoc(e[1], 'after') )
    out |= RemoveEventPid()

    assert_equal(list(out), [e[1],e[4]])
