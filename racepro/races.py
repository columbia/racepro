import logging
import scribe
from itertools import *

#def __races_accesses(session, access):
#    """Given vclocks of a resource per process (non-decreasing
#    order), find resources races:
#
#    For each two processes, iterate in parallel over accesses and
#    find those that are neither before nor after each other. Each
#    such race is reported as (vclock1, r_ev1, vclock2, r_ev2).
#
#    This works because, given two process A[1..n] and B[1..m]:
#    - for i < j:  Ai < Aj,  Bi < Bj
#    - for i, j:   Ai < Bj  or  Ai > Bj  or  Ai || Bj
#    - the relation '<' is transitive
#    """
#    races = list()
#
#    for k1, k2 in combinations(access, 2):
#        q1, q2 = access[k1], access[k2]
#
#        n, m = 0, 0
#        while n < len(q1) and m < len(q2):
#            vc1, r_ev1 = q1[n]
#            vc2, r_ev2 = q2[m]
#
#            aa,ab = session.r_ev_to_proc(r_ev1)
#            ba,bb = session.r_ev_to_proc(r_ev2)
#
#            if vc1.before(vc2):
#                n += 1
#            elif vc2.before(vc1):
#                m += 1
#            else:
#                for vc3, r_ev3 in q2[m:]:
#                    # going too far ?
#                    if vc1.before(vc3):
#                        break
#                    # read-read case ?
#                    if (r_ev1.event.write_access == 0 and
#                        r_ev2.event.write_access == 0):
#                        continue
#                    races.append((vc1, r_ev1, vc3, r_ev3))
#                n += 1
#
#    return races

# YJF: dumb version of race detection; but seems to detect more races
# than the optimized version, such as the mv race
def __races_accesses_yjf(access):
    races = list()

    for k1, k2 in combinations(access, 2):
        q1, q2 = access[k1], access[k2]
        for (vc1, r_ev1) in q1:
            for (vc2, r_ev2) in q2:
                if vc1.before(vc2):
                    break
                if vc2.before(vc1):
                    continue
                if (r_ev1.event.write_access == 0 and
                    r_ev2.event.write_access == 0):
                    continue
                races.append((vc1, r_ev1, vc2, r_ev2))
    return races

def races_resources(graph):
    """Given vclocks of all syscalls, find resources races:
    For each resource, iterate through its events and accumulate
    them in a per-process list - stored in @access dictionary,
    such that access[pid] is a list of (vclock, index) tuples of
    the events and their vector-clocks belonging to that process.
    This is passsed to __races_accesses() which returns a list of
    actual races: (vclock1, index1, vclock2, index2)
    """
    session = graph.session
    vclocks = graph.vclocks

    races = list()
    resource_ignore = [ scribe.SCRIBE_RES_TYPE_FUTEX ]

    for resource in session.resource_list:
        if resource.subtype in resource_ignore:
            continue

        # YJF: FIXME: switch to random sampling if there are too many events
        events = resource.events
        thresh = 100  # threshold to switch to random
        if len(resource.events) > thresh:
            # just drop such resources
            logging.info('resource %d has too many (%d) events; skip'
                         % (resource.id, len(resource.events)))
            continue

        access = dict(map(lambda k: (k, list()), session.process_map.keys()))

        # track accesses per process
        for r_ev in events:
            proc, event = session.r_ev_to_proc(r_ev, sysind=True)
            p_ev = proc.events[index]
            node = graph.make_node(proc.pid, p_ev.syscnt)
            vc = vclocks[(proc, p_ev.syscnt)]
            access[proc.pid].append((vc, r_ev))

        # YJF: exlude empty lists
        for k in access.keys():
            if len(access[k]) == 0:
                del access[k]

        races.extend(__races_accesses_yjf(access))

    return [(vc1, r_ev1.index, vc2, r_ev2.index) for
            vc1, r_ev1, vc2, r_ev2 in races]

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

def races_exitwait(graph):
    """Given vclocks of all syscalls, find exit-wait races:
    For each exit() successfully waited for, find all the other
    exit() calls that may be concurrent to this one and thus
    could be waited for instead.
    """

    session = graph.session
    vclocks = graph.vclocks

    # step one: divide the exits() into per-parent lists, each
    # list ordered by vclocks: loop on waits to determine where
    # each exit (by pid) belongss and then add exits.
    exit_events = dict([ (k, list()) for k in session.process_map ])
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
