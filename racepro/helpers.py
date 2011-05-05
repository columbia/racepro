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
    @replace: events to substitutee [{ old1:new1 },{ old2,new2 }..]
    """

    event_new = None

    def check_bookmarks(bookmarks, nl):

        def live_processes(bmark):
            live_procs = filter(lambda p: bmark[p].node != p.last_anchor, bmark)
            return live_procs

        proc = nl.node.proc
        for n, bmark in enumerate(bookmarks):
            try:
                if bmark[proc] == nl:
                    event = scribe.EventBookmark()
                    if nl.after:
                        event.type = scribe.SCRIBE_BOOKMARK_POST_SYSCALL
                    else:
                        event.type = scribe.SCRIBE_BOOKMARK_PRE_SYSCALL
                    event.id = n
                    event.npr = len(live_processes(bmark))
                    logging.debug('[%d] bookmark at syscall %s' %
                                  (proc.pid, nl.node))
                    yield session.Event(event)
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
                yield session.Event(event)
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
        if node in replace:
            node = replace[node]

        if node != proc.first_anchor and node != proc.last_anchor:
            yield node

        # actions after a syscall
        if node.is_a(scribe.EventSyscallEnd):
            for event in consider_event(sys, 'after'):
                yield event

        if node.is_a(scribe.EventQueueEof):
            endofq[proc] = True
            inactive[proc] = True

    if not bookmarks: bookmarks = dict()
    if not injects: injects = dict()
    if not cutoff: cutoff = dict()
    if not replace: replace = dict()

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
                    yield session.Event(scribe.EventPid(proc.pid))
                    current = proc
                yield event

    # indicate go-live where needed
    for proc in graph.processes.itervalues():
        if proc not in endofq:
            yield session.Event(scribe.EventPid(proc.pid))
            yield session.Event(scribe.EventQueueEof())
