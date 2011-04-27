import logging
import scribe
from itertools import *
from racepro import *

def rank_races_of_resources(graph, race):
    # TODO: priority may change?
    # file data > path > exit > signal > file metadata > stdout
    # basescores = {'file':400, 'path':300, 'exit-exit':200, 'signal':100}

    def event_is_resource(event):
        return \
            event.is_a(scribe.EventResourceLockExtra) or \
            event.is_a(scribe.EventResourceLockIntr)

    # events closer in one of the resource access lists > farther
    node1, node2 = race
    index1 = node1.syscall_index
    index2 = node2.syscall_index

    # average distance of resource accesses
    distance = 0
    nresource = 0
    for event1 in node1.children:
        if not event_is_resource(event1):
            continue
        for event2 in node2.children:
            if not event_is_resource(event2):
                continue

            if event1.resource == event2.resource:
                assert event1 != event2
                if event1.write_access == 0 and event2.write_access == 0:
                    continue
                distance += abs(event1.serial - event2.serial)
                nresource += 1
    if nresource != 0:
        distance = float(distance) / nresource
    else:
        distance = 5 # why no common resources?
    logging.debug('race %s,%s avg distance=%d' % (node1, node2, distance))
    return distance;

def find_races_of_resource(resource):
    """Given a mapping proc:events for a resource, find racing events"""
    races = list()

    events_of_proc = dict()
    for node in resource.events:
        if node.proc not in events_of_proc:
            events_of_proc[node.proc] = list()
        events_of_proc[node.proc].append(node)

    for proc1, proc2 in combinations(events_of_proc, 2):
        for node1 in events_of_proc[proc1]:
            for node2 in events_of_proc[proc2]:
                if node1.syscall.vclock.before(node2.syscall.vclock):
                    break
                if node2.syscall.vclock.before(node1.syscall.vclock):
                    continue
                if node1.write_access == 0 and node2.write_access == 0:
                    continue
                races.append((node1, node2))
    return races

def races_of_resources(graph):
    """Find resources races: for each resource, separate the events
    per process, and find list of racing events (nodes).
    """
    races = list()

    resource_ignore = [ scribe.SCRIBE_RES_TYPE_FUTEX ]

    for resource in graph.resources.itervalues():

        # ignore some resources
        if resource.type in resource_ignore:
            continue

        # (FIXME) ignore resource with too many events
        thresh = 100
        if len(resource.events) > thresh:
            logging.info('resource %d has too many (%d) events; skip'
                         % (resource.id, len(resource.events)))
            continue

        races_of_resource = find_races_of_resource(resource)
        races.extend(races_of_resource)

    return races

def races_signals(graph):
    """Given vclocks of all syscalls, find signal races for both
    'internal' and 'external' signals (i.e. send by a process in
    or out of the recorded session, respectively).

    Initially, we just change the way the signals affects (or not)
    the syscall. If the signal interrupted the syscall, we will
    now allow the syscall to complete and then deliver the signal;
    if the signal did not interrupt the syscall, we will force it
    to interrupt the syscall.

    TODO: attempt to deliver the signal to syscalls that occured
    before the affected syscall and that are "racy" with the
    sending syscall (for each syscall, once pre-, once post-).
    """

    return graph.session.signals

def races_of_exitwait(graph):
    """Find exit-wait races: for each exit() successfully waited for,
    find all the other exit() calls that may be concurrent to this one
    and thus could be waited for instead.
    """

    # step one: divide the exits() into per-parent lists, each
    # list ordered by vclocks: loop on waits to determine where
    # each exit (by pid) belongss and then add exits.

    exit_events = dict()
    exit_to_wait = dict()

    # create mapping:  pid --> reaper
    for i in session.wait_e:
        s_ev = session.events[i]
        proc, event = s_ev.proc, s_ev.event

        if event.ret > 0:
            exit_to_wait[event.ret] = (proc, s_ev.pindex)

    # collect exit calls per reaper
    for i in session.exit_e:
        s_ev = session.events[i]
        proc = s_ev.proc
        try:
            reaper, z = exit_to_wait[proc.pid]
        except:
            pass
        else:
            exit_events[reaper.pid].append((proc, s_ev.pindex))

    def vclock_cmp(exit_e1, exit_e2):
        p1, i1 = exit_e1
        p2, i2 = exit_e2
        vc1 = vclocks[(p1, p1.events[i1].syscnt)]
        vc2 = vclocks[(p2, p2.events[i2].syscnt)]
        if vc1.before(vc2):
            return -1
        elif vc2.before(vc1):
            return 1
        else:
            return 0

    # sort the exit calls by their vclocks
    for exit_l in exit_events.values():
        exit_l.sort(cmp=vclock_cmp)

    exitwait = list()

    # find potential races: for each exit event, search ahead for
    # races with other races that are concurrent with this exit
    for pid in exit_events.keys():
        exit_l = exit_events[pid]
        for n, (ep1, ei1) in enumerate(exit_l):
            vc1 = vclocks[ep1, ep1.events[ei1].syscnt]
            for ep2, ei2 in exit_l[n + 1:]:
                vc2 = vclocks[ep2, ep2.events[ei2].syscnt]
                if vc1.race(vc2):
                    wp1, wi1 = exit_to_wait[ep1.pid]
                    wp2, wi2 = exit_to_wait[ep2.pid]

                    w_vc1 = vclocks[wp1, wp1.events[wi1].syscnt]
                    w_vc2 = vclocks[wp2, wp2.events[wi2].syscnt]

                    if w_vc1.before(w_vc2):
                        exitwait.append(((ep2, ei2),
                                        (ep1, ei1),
                                        (wp1, wi1)))
                    else:
                        exitwait.append(((ep1, ei1),
                                        (ep2, ei2),
                                        (wp2, wi2)))

    return exitwait
