import logging

import scribe
from racepro import *

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
    else:
        out.write('%s(%#x, %#x, %#x)' %
                  (unistd.syscall_str(event.nr),
                   args[0], args[1], args[2]))
    out.write(' = %ld\n' % (ret))

def syscalls_process(session, pid, vclocks=None):
    """Print all the syscalls of a process"""
    try:
        proc = session.process_map[pid]
    except KeyError:
        logging.error('No such process with pid %d' % (pid))
        return

    for p_ev in proc.events:
        if isinstance(p_ev.event, scribe.EventSyscallExtra):
            sys.stdout.write('pid=%3d:cnt=%3d:' % (proc.pid, p_ev.syscnt))
            sys.stdout.write('ind=%4d:' % (session.events[p_ev.index].pindex))
            if vclocks is not None:
                sys.stdout.write('vc=%s:' % vclocks[(proc, p_ev.syscnt)])
            session.parse_syscall(p_ev.index)

def profile_process(session, pid):
    """Print profile of all the events of a process"""
    proc = session.process_map[pid]
    for p_ev in proc.events:
        print("[%02d][%d] %s%s%s" %
              (proc.pid, p_ev.syscnt,
               ("", "    ")[p_ev.info.in_syscall],
               "  " * p_ev.info.res_depth,
               p_ev.event))

################################################################################


def save_events(graph,
                bookmarks = None,
                injects = None,
                cutoff = None,
                replace = None):
    """Iterator that returns the (perhaps modified) scribe log.

    Write out the scribe log while potentially modifying it. Two
    types of modifications exist: "inject", to inject new events
    (per process) into the log , and "cutoff", which specifies
    locations (per process) to cut remaining log.

    @bookmarks: array of bookmarks [{ proc:nodeloc }]
    @injects: actions to inject { procf : {nodeloc:act1},{nodeloc:act2}, ...] }
    @cutoff: where to cutoff queues { proc : nodeloc }
    @replace: (ordered) events to substitutee [(old1,new1),(old2,new2)..]
    """

    def check_bookmarks(bookmarks, nl):
        proc = nl.node.proc
        for n, bmark in enumerate(bookmarks):
            try:
                print('NL %s (bmark[proc] % s' % (nl, bmark[proc]))
                if bmark[proc] == nl:
                    event = scribe.EventBookmark()
                    event.id = n
                    event.npr = len([b for b in bmark.values() if b != 0])
                    logging.debug('[%d] bookmark at syscall %s' %
                                  (proc.pid, nl.node))
                    yield event
            except KeyError:
                pass

    def check_inject(injects, nl):
        proc = nl.node.proc
        try:
            for a in injects[proc][nl]:
                event = scribe.EventInjectAction()
                event.action = a.action
                event.arg1 = a.arg1
                event.arg2 = a.arg2
                logging.debug('[%d] inject at syscall %s' % (proc.pid, node))
                yield event
        except KeyError:
            pass

    def check_cutoff(cutoff, nl):
        try:
            if cutoff[proc] == nl:
                logging.debug('[%d] cutoff at syscall %s' % (proc.pid, node))
                return True
        except KeyError:
            pass

    def consider_event(node, when):
        # pid bookmark ?
        for event in check_bookmarks(bookmarks, NodeLoc(node, when)):
            yield event

        # pid inject ?
        for event in check_inject(injects, NodeLoc(node, when)):
            if event.action == scribe.SCRIBE_INJECT_ACTION_PSFLAGS:
                if event.arg2 & scribe.SCRIBE_PS_ENABLE_RESOURCE:
                    relaxed[proc]['resource'] = True
                if event.arg2 & scribe.SCRIBE_PS_ENABLE_DATA:
                    relaxed[proc]['data'] = True
            yield event

        # pid cutoff ?
        if check_cutoff(cutoff, NodeLoc(node, when)):
            inactive[proc] = True

    def replace_event():
        event = event_new
        try:
            event_old, event_new = replace.pop(0)
        except IndexError:
            event_old, event_new = None, None
        return event

    def is_resource_event(node):
        return node.is_a(scribe.EventResourceLockExtra) or \
            node.is_a(scribe.EventResourceLockIntr) or \
            node.is_a(scribe.EventResourceUnlock)

    def is_data_event(node):
        return node.is_a(scribe.EventData) or \
            node.is_a(scribe.EventDataExtra)

    def events_for_node(node, sys):
        proc = node.proc

        # not strictly needed here, but can expedite things
        if proc in inactive:
            return

        # ignore old bookmarks
        if node.is_a(scribe.EventBookmark):
            return

        # actions before a syscall
        if node.is_a(scribe.EventSyscallExtra):
            print('syscall start: %s' % node)
            for event in consider_event(sys, 'before'):
                yield event

        if proc in relaxed:
            # skip 'resource' events ?
            if relaxed[proc]['resource'] and is_resource_event(node):
                return
            # skip 'data' events ?
            if relaxed[proc]['data'] and is_data_event(node):
                return

        # replace this event ?
        if node == event_old:
            node = replace_event()

        if node != proc.first_anchor and node != proc.last_anchor:
            yield node

        # actions after a syscall
        if node.is_a(scribe.EventSyscallEnd):
            print('syscall end %s' % node)
            for event in consider_event(sys, 'after'):
                yield event

        if node.is_a(scribe.EventQueueEof):
            endofq[proc] = True
            inactive[proc] = True

    if not bookmarks: bookmarks = dict()
    if not injects: injects = dict()
    if not cutoff: cutoff = dict()
    if not replace: replace = list()

    try:
        event_old, event_new = replace.pop(0)
    except IndexError:
        event_old, event_new = None, None

    inactive = dict()
    endofq = dict()
    relaxed = dict()

    for proc in graph.processes.itervalues():
        relaxed[proc] = dict({'resource':False, 'data':False})

    current = None

    yield graph.events[0]

    for node in networkx.algorithms.dag.topological_sort(graph):
        proc = node.proc

        def node_and_after(node):
            if node == proc.first_anchor:
                return proc.events
            elif node == proc.last_anchor:
                return list()
            else:
                return itertools.chain([node], proc.events.after(node))

        for nd in itertools.takewhile(lambda e: e != node.next_node(),
                                      node_and_after(node)):
            for event in events_for_node(nd, node):
                if not event:
                    continue
                if proc in inactive:
                    continue
                if proc != current:
                    e = scribe.EventPid()
                    e.pid = proc.pid
                    current = proc
                    yield e
                yield event

    # indicate go-live where needed
    for proc in graph.processes.itervalues():
        if proc not in endofq:
            e = scribe.EventPid()
            e.pid = proc.pid
            yield e
            e = scribe.EventQueueEof()
            yield e
