import mmap
import logging
import networkx
import itertools

import scribe
import session
from execgraph import NodeLoc

def load_events(logfile):
    """Load a scribe log from logfile"""
    try:
        f = open(logfile, 'r')
    except:
        print('Cannot open log file %s' % logfile)
        exit(1)

    m = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
    events = list(scribe.EventsFromBuffer(m))
    m.close()
    f.close()

    return events

def mutate_events(graph,
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

    def check_bookmarks(nl):

        def live_processes(bmark):
            def proc_is_alive(p):
                nl = bmark[p]
                if nl.node == p.last_anchor:
                    return False
                if nl.node == p.first_anchor and nl.before:
                    return False
                return True

            return filter(proc_is_alive, bmark)

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
                    logging.debug('[%d] bookmark at syscall %s npr %d' %
                                  (proc.pid, nl.node, event.npr))
                    yield session.Event(event)
            except KeyError:
                pass

    def check_inject(nl):
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

    def check_cutoff(nl):
        try:
            if cutoff[proc] == nl:
                logging.debug('[%d] cutoff at syscall %s' % (proc.pid, node))
                return True
        except KeyError:
            pass

    def consider_event(nl):
        # pid bookmark ?
        for event in check_bookmarks(nl):
            yield event

        # pid inject ?
        for event in check_inject(nl):
            if event.action == scribe.SCRIBE_INJECT_ACTION_PSFLAGS:
                if event.arg2 & scribe.SCRIBE_PS_ENABLE_RESOURCE:
                    relaxed[proc]['resource'] = True
                if event.arg2 & scribe.SCRIBE_PS_ENABLE_DATA:
                    relaxed[proc]['data'] = True
            yield event

        # pid cutoff ?
        if check_cutoff(nl):
            inactive[proc] = True

    def is_resource_event(node):
        return node.is_a(scribe.EventResourceLockExtra) or \
            node.is_a(scribe.EventResourceLockIntr) or \
            node.is_a(scribe.EventResourceUnlock)

    def is_data_event(node):
        return node.is_a(scribe.EventData) or \
            node.is_a(scribe.EventDataExtra)

    def new_events_of_event(event):
        proc = event.proc

        # not strictly needed here, but can expedite things
        if proc in inactive:
            return

        # ignore old bookmarks
        if event.is_a(scribe.EventBookmark):
            return

        # actions before a syscall
        if event.is_a(scribe.EventSyscallExtra):
            for new_event in consider_event(NodeLoc(event.syscall, 'before')):
                yield new_event

        if proc in relaxed:
            # skip 'resource' events ?
            if relaxed[proc]['resource'] and is_resource_event(event):
                return
            # skip 'data' events ?
            if relaxed[proc]['data'] and is_data_event(event):
                return

        # replace this event ?
        if event in replace:
            event = replace[event]

        if event not in [proc.first_anchor, proc.last_anchor]:
            yield event

        # actions after a syscall
        if event.is_a(scribe.EventSyscallEnd):
            for new_event in consider_event(NodeLoc(event.syscall, 'after')):
                yield new_event

        if event == proc.first_anchor:
            for new_event in consider_event(NodeLoc(event, 'after')):
                yield new_event

        if event.is_a(scribe.EventQueueEof):
            endofq[proc] = True
            inactive[proc] = True

    def new_events_of_node(node):
        def node_and_after(node):
            if node == proc.first_anchor:
                return itertools.chain([node], proc.events)
            elif node == proc.last_anchor:
                return [node]
            else:
                return itertools.chain([node], proc.events.after(node))

        def events_of_node(node):
            return itertools.takewhile(lambda e: e != node.next_node(),
                                       node_and_after(node))

        for event in events_of_node(node):
            for new_event in new_events_of_event(event):
                yield new_event


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
        for new_event in new_events_of_node(node):
            if not new_event:
                continue
            if proc in inactive:
                continue
            if proc != current:
                yield session.Event(scribe.EventPid(proc.pid))
                current = proc
            yield new_event

    # indicate go-live where needed
    for proc in graph.processes.itervalues():
        if proc not in endofq:
            yield session.Event(scribe.EventPid(proc.pid))
            yield session.Event(scribe.EventQueueEof())

def condense_events(events):
    """Remove holes in serial number sequence"""

    # map from resource id to the previou event's (serial, seq, write_access)
    # serial: serial number
    # seq: sequence number ignoring access type
    # write_access: non zero if the event is a write

    events = list(events)

    serials = dict()
    for e in events:
        if e.is_a(scribe.EventResourceLockExtra):
            if e.id not in serials:
                serials[e.id] = dict()
            if e.serial not in serials[e.id]:
                serials[e.id][e.serial] = 1
            else:
                serials[e.id][e.serial] += 1

    for id_serials in serials.values():
        last_i = None
        for i in sorted(id_serials.keys()):
            if last_i == None:
                last_i = i
                last_serial = id_serials[i]
                id_serials[i] = 0
                continue
            deficit = i - last_serial
            last_serial += id_serials[i]
            id_serials[i] = i - deficit
            last_i = i

    for e in events:
        if e.is_a(scribe.EventResourceLockExtra):
            if e.serial != serials[e.id][e.serial]:
                ee = e.copy()
                ee.serial = serials[e.id][e.serial]
                e = session.Event(ee)
        yield e

def load_session(logfile):
    events = load_events(logfile)
    return Session(events)

def save_session(logfile, events):
    """Save modified scribe log to logfile"""
    try:
        f = open(logfile, 'w')
    except:
        print('Cannot open log file %s' % logfile)
        exit(1)

    for e in condense_events(events):
        f.write(e.encode())

    f.close()
