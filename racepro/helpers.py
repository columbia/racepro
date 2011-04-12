import scribe
import logging

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


def save_events(session, bookmarks = None, injects = None, cutoff = None,
                replace = None):
    """Iterator that returns the (perhaps modified) scribe log.

    Write out the scribe log while potentially modifying it. Two
    types of modifications exist: "inject", to inject new events
    (per process) into the log , and "cutoff", which specifies
    locations (per process) to cut remaining log.

    @bookmarks: array of bookmarks [{ pid: cnt1 }]
    @injects: actions to inject { pid : {cnt1:act1},{cnt2:act2}, ...] }
    @cutoff: where to cutoff queues { pid : cnt }
    @replace: (ordered) events to substitutee [(old1,new1),(old2,new2)..]

    The 'cnt' value above specifies a system call:
    cnt > 0: effect occurs post-syscall (before return to userspace)
    cnt < 0: effect occufs pre-syscall
    cnt == 0: no effect because process exited so leave log as is
    else (if pid not a key) then process not started, ignore the log
    """

    def check_bookmarks(pid, syscall, bookmarks):
        for n, bmark in enumerate(bookmarks):
            if pid in bmark and syscall == bmark[pid]:
                e = scribe.EventBookmark()
                e.id = n
                e.npr = len([b for b in bmark.values() if b != 0])
                logging.debug('[%d] bookmark at syscall %d' % (pid, syscall))
                yield e

    def check_inject(pid, syscall, injects):
        if syscall in injects[pid]:
            for a in injects[pid].itervalues():
                e = scribe.EventInjectAction()
                e.action = a.action
                e.arg1 = a.arg1
                e.arg2 = a.arg2
                logging.debug('[%d] inject at syscall %d' % (pid, syscall))
                yield e

    def check_cutoff(pid, syscall, cutoff):
        if syscall == cutoff[pid]:
            logging.debug('[%d] cutoff at syscall %d' % (pid, cutoff[pid]))
            return True
        else:
            return False


    active = dict()
    syscall = dict()
    relaxed = dict()
    endofq = dict({0:False})

    # include all pids that belong to any bookmark; pid's not here
     # should not yet be created, and their logs will be skipped
    if not bookmarks is None:
        include = reduce(lambda d1, d2: dict(d1, **d2), bookmarks)
        drop_old_bookmarks = True
    else:
        include = dict([(k, k) for k in session.process_map.keys()])
        drop_old_bookmarks = False

    logging.debug('pids included in the log: %s' % include.keys())

    if bookmarks is None: bookmarks = dict()
    if injects is None: injects = dict()
    if cutoff is None: cutoff = dict()
    if replace is None: replace = list()

    try:
        event_old, event_new = replace.pop(0)
    except IndexError:
        event_old, event_new = None, None

    for s_ev in session.events:
        info = s_ev.info
        event = s_ev.event
        pid = info.pid

        # pid==0 is a special event
        if pid == 0:
            yield event
            continue

        # pid's not in @include are ignored (not created yet)
        if pid not in include:
            continue

        # first time we see this pid ?
        # note: setting cutoff[pid] ensures no cutoff
        if pid not in active:
            active[pid] = True
            syscall[pid] = 0
            endofq[pid] = False
            relaxed[pid] = dict({'resource':False, 'data':False})
            if pid not in cutoff:
                cutoff[pid] = 0
            if pid not in injects:
                injects[pid] = dict()

        assert not endofq[pid] or pid == 0, \
            'Event for pid %d after eoq' % (pid)

        # pid inactive ?
        if not active[pid]:
            continue

        # ignore original bookmarks
        if drop_old_bookmarks and isinstance(event, scribe.EventBookmark):
            continue

        #
        # I would expect to remove the EventRegs already, but nico said
        # it should stay, and remove from EventSyscallExtra nad on
        #    if isinstance(event, scribe.EventRegs):
        #
        if isinstance(event, scribe.EventSyscallExtra):
            syscall[pid] += 1

            # pid bookmark ?
            for e in check_bookmarks(pid, -syscall[pid], bookmarks):
                yield e
            # pid inject ?
            for e in check_inject(pid, -syscall[pid], injects):
                if e.action == scribe.SCRIBE_INJECT_ACTION_PSFLAGS:
                    if e.arg2 & scribe.SCRIBE_PS_ENABLE_RESOURCE:
                        relaxed[pid]['resource'] = True
                    if e.arg2 & scribe.SCRIBE_PS_ENABLE_DATA:
                        relaxed[pid]['data'] = True
                yield e
            # pid cutoff ?
            if check_cutoff(pid, -syscall[pid], cutoff):
                active[pid] = False
                continue

        # skip 'restource' events ?
        if relaxed[pid]['resource'] and \
                (isinstance(event, scribe.EventResourceLockExtra) or \
                 isinstance(event, scribe.EventResourceLockIntr) or \
                 isinstance(event, scribe.EventResourceUnlock)):
            continue
        # skip 'data' events ?
        if relaxed[pid]['data'] and \
                (isinstance(event, scribe.EventData) or \
                 isinstance(event, scribe.EventDataExtra)):
            continue

        if isinstance(event, scribe.EventQueueEof):
            endofq[pid] = True
            active[pid] = False

        # substitute for this event ?
        if event == event_old:
            event = event_new
            try:
                event_old, event_new = replace.pop(0)
            except IndexError:
                event_old, event_new = None, None
            if not event:
                continue

        yield event

        if isinstance(event, scribe.EventSyscallEnd):
            # pid bookmark ?
            for e in check_bookmarks(pid, syscall[pid], bookmarks):
                yield e
            # pid inject ?
            for e in check_inject(pid, syscall[pid], injects):
                if e.action == scribe.SCRIBE_INJECT_ACTION_PSFLAGS:
                    relaxed[pid] = True
                yield e
            # pid cutoff ?
            if check_cutoff(pid, syscall[pid], cutoff):
                active[pid] = False
                continue

    # indicate go-live where needed
    for pid in active:
        if not endofq[pid]:
            e = scribe.EventPid()
            e.pid = pid
            yield e
            e = scribe.EventQueueEof()
            yield e


############################################################################



def score_race(graph, race):
    # TODO: priority may change?
    # file data > path > exit > signal > file metadata > stdout
    # basescores = {'file':400, 'path':300, 'exit-exit':200, 'signal':100}

    session = graph.session

    def syscall_events(proc, pindex):
        assert isinstance(proc.events[pindex].event, scribe.EventSyscallExtra)

        events = list()
        while True:
            p_ev = proc.events[pindex]
            if isinstance(p_ev.event, scribe.EventSyscallEnd):
                break
            elif isinstance(p_ev.event, scribe.EventResourceLockExtra):
                events.append(session.events[p_ev.index])
            pindex += 1

        return events

    score = 0

    # events closer in one of the resource access lists > farther
    n1, n2 = race
    i1 = int(graph.node[n1]['index'])
    evl1 = syscall_events(session.events[i1].proc, session.events[i1].pindex)
    i2 = int(graph.node[n2]['index'])
    evl2 = syscall_events(session.events[i2].proc, session.events[i2].pindex)

    # average distance of resource accesses
    distance = 0
    nresource = 0
    for e1 in evl1:
        for e2 in evl2:
            if e1.resource == e2.resource:
                assert e1 != e2
                if(e1.event.write_access == 0 and
                   e2.event.write_access == 0):
                    continue
                distance += abs(e1.event.serial-e2.event.serial)
                nresource += 1
    if nresource != 0:
        distance = float(distance) / nresource
    else:
        distance = 5 # why no common resources?
    logging.debug('race %s,%s avg distance=%d' % (n1, n2, distance))
    return score - distance;
