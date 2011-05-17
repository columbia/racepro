import logging
import pdb

import scribe
from itertools import *
from racepro import *
import toctou

def _split_events_per_proc(resource, in_syscall=False):
    per_proc = dict()

    def filter_belong_to_syscalls(events):
        return ifilter(lambda e: hasattr(e, 'syscall'), events)

    def filter_belong_to_proc(events, proc):
        return ifilter(lambda n: n.proc == proc, events)

    for proc in set(e.proc for e in resource.events):
        if not in_syscall:
            events = resource.events
        else:
            events = filter_belong_to_syscalls(resource.events)
        per_proc[proc] = filter_belong_to_proc(events, proc)

    return per_proc

def dict_values_to_lists(d):
    return dict((k, list(v)) for k,v in d.iteritems())

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

    ievents_per_proc = _split_events_per_proc(resource, in_syscall=True)
    events_per_proc = dict_values_to_lists(ievents_per_proc)

    for proc1, proc2 in combinations(events_per_proc, 2):
        for node1 in events_per_proc[proc1]:
            for node2 in events_per_proc[proc2]:
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

def races_of_signals(graph):
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

    return graph.signals

def races_of_exitwait(graph):
    """Find exit-wait races: for each exit() successfully waited for,
    find all the other exit() calls that may be concurrent to this one
    and thus could be waited for instead.
    """

    # step one: divide the exits() into per-parent lists, each
    # list ordered by vclocks: loop on waits to determine where
    # each exit (by pid) belongss and then add exits.

    reaper_wait_of = dict()
    exits_by_reaper = dict()

    # create mapping:  pid --> reaper
    for node in graph.nodes_typed('wait'):
        child = graph.processes[node.ret]
        reaper_wait_of[child] = node

    # collect exit calls per reaper
    for node in graph.nodes_typed('exit'):
        if node.proc not in reaper_wait_of:    # not yet reaped
            continue
        wait_node = reaper_wait_of[node.proc]
        if wait_node.proc not in exits_by_reaper:
            exits_by_reaper[wait_node.proc] = [node]
        else:
            exits_by_reaper[wait_node.proc].append(node)

    for exits in exits_by_reaper.values():
        exits.sort(key=lambda node: node.vclock)

    races = list()

    # find potential races: for each exit event, search ahead for
    # races with other exits that are concurrent with this exit (and
    # under the same reaper)

    for proc in exits_by_reaper:
        for n, exit1 in enumerate(exits_by_reaper[proc]):
            for exit2 in exits_by_reaper[proc][n + 1:]:
                if exit1.vclock.race(exit2.vclock):
                    wait1 = reaper_wait_of[exit1.proc]
                    wait2 = reaper_wait_of[exit2.proc]
                    if wait1.vclock.before(wait2.vclock):
                        races.append((exit2, exit1, wait1))
                    else:
                        races.append((exit1, exit2, wait2))

    return races

def races_of_toctou(graph):
    races = dict()

    for pattern in toctou.patterns:
        races[pattern] = list()

    for resource in graph.resources.itervalues():
        syscalls_hists = dict()
        for pattern in toctou.patterns:
            syscalls_hists[pattern.sys1] = list()

        events_per_proc = _split_events_per_proc(resource, in_syscall=True)

        for proc in events_per_proc:
            for node in events_per_proc[proc]:
                sys_cur = node.syscall
                for pattern in toctou.patterns:
                    if pattern.sys2.has(sys_cur.nr):
                        for sys_old in syscalls_hists[pattern.sys1]:
                            israce, s1, s2 = pattern.check(sys_old, sys_cur)
                            if not israce:
                                continue
                            at_cmd = pattern.generate(s1, s2)
                            pair_exists = False
                            for sys1, sys2, cmd in races[pattern]:
                                if sys1 == sys_old and sys2 == sys_cur:
                                    pair_exists = True
                                    break

                            if not pair_exists:
                                races[pattern].append((sys_old, sys_cur, at_cmd))

                    if pattern.sys1.has(sys_cur.nr):
                        if sys_cur not in syscalls_hists[pattern.sys1]:
                            syscalls_hists[pattern.sys1].append(sys_cur)

    return races

def attack_toctou (pattern_name, args):
    for pattern in toctou.patterns:
        if pattern.desc == pattern_name:
            print >> sys.stderr, "perform %s attack..." % pattern.desc
            pattern.attack(args)
            break

def test_toctou (pattern_name, args):
    for pattern in toctou.patterns:
        if pattern.desc == pattern_name:
            print >> sys.stderr, "perform %s test..." % pattern.desc
            pattern.test(args)

def explain_toctou (pattern_name):
    for pattern in toctou.patterns:
        if pattern.desc == pattern_name:
            return pattern.detail
    return 'Unknown pattern'
