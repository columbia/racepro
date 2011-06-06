import logging
import pdb

from itertools import *

import scribe
import toctou
from racepro import *

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

def crosscut_to_bookmark(crosscut):
    bookmark = dict(map(lambda nl: (nl.node.proc, nl), crosscut))
    return bookmark

##############################################################################
# races of RESOURCES

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

def find_resource_races(graph):
    """Find all pairwise races and return in a list"""
    all_races = races_of_resources(graph)
    logging.debug('total resource races %d' % (len(all_races)))

    sys_races = set()

    for node1, node2 in all_races:
        assert node1.serial != node2.serial, \
            'Race between %s and %s with same serial' % (node1, node2)

        if node1.serial < node2.serial:
            node1, node2 = node2, node1

        sys_races.add((node1.syscall, node2.syscall))
        logging.info('\tadding %s --> %s to races' % (node1, node2))

    print('RACES %s', sys_races)
    return all_races, sys_races

def prep_resource_race(graph, node1, node2, n_race):
    """prepare a race by computing bookmarks, injects, and cutoff"""
    crosscut = graph.crosscut([node1, node2])
    bookmark1 = crosscut_to_bookmark(crosscut)

    if not bookmark1:
        print('No consistent cut: node %s --> node %s' % (node1, node2))
        return None

    bookmark2 = dict(bookmark1)
    bookmark2[node1.proc] = NodeLoc(node1, 'after')
    bookmarks = [bookmark1, bookmark2]

    mask = (scribe.SCRIBE_PS_ENABLE_RESOURCE |
            scribe.SCRIBE_PS_ENABLE_RET_CHECK)

    if node1.nr not in unistd.SYS_wait:
        mask |= scribe.SCRIBE_PS_ENABLE_DATA

    action = Action(scribe.SCRIBE_INJECT_ACTION_PSFLAGS, 0, mask)

    injects = dict()
    actions = list([action])
    injects[node1.proc] = dict({NodeLoc(node1, 'before') : actions})

    cutoff = dict(bookmark2)

    print('RACE %2d:  ' % (n_race + 1) +
          'pid %d syscnt %d [sys(%d)=%d]' %
          (node1.proc.pid, node1.syscall_index, node1.nr, node1.ret) +
          '  -->   pid %d syscnt %d [sys(%d)=%d]' %
          (node2.proc.pid, node2.syscall_index, node2.nr, node2.ret))
    print('          cut:  %s' % bookmark1.values())

    logging.debug('   boobkmark1: %s' % (bookmark1))
    logging.debug('   boobkmark2: %s' % (bookmark2))
    logging.debug('      injects: %s' % (injects))
    logging.debug('       cutoff: %s' % (cutoff))

    return bookmarks, injects, cutoff, None

##############################################################################
# races of SIGNALS

def races_of_signals(graph):
    """Find signal races for both 'internal' and 'external' signals
    (i.e. send by a process in or out of the recorded session,
    respectively).

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

def find_signal_races(graph):
    """Find all signal races and return in a list"""
    signal_races = races_of_signals(graph)
    logging.debug('total signal races %d' % (len(signal_races)))
    return signal_races

def prep_signal_race(graph, signal, n_race):
    """prepare a race by computing bookmarks, injects, and cutoff
    If the signal interrupted the syscall, then make it not interrupt.
    If the signal did not interrupt the syscall, then make it interrupt.
    """
    node = signal.handled

    crosscut = graph.crosscut([node])
    bookmark1 = crosscut_to_bookmark(crosscut)

    if not bookmark1:
        print('No consistent cut: pid %d syscnt %d' % proc.pid, cnt)
        return None

    bookmark2 = dict(bookmark1)
    bookmark2[node.proc] = NodeLoc(node, 'after')
    bookmarks = [bookmark1, bookmark2]

    # we reverse the signal's effect by "reversing" the syscall return
    # value (from interrupted to non-interrupted or vice versa)

    injects = dict()

    action = Action(scribe.SCRIBE_INJECT_ACTION_PSFLAGS,
                    0, scribe.SCRIBE_PS_ENABLE_RESOURCE |
                    scribe.SCRIBE_PS_ENABLE_RET_CHECK)
    injects[node.proc] = dict({NodeLoc(node, 'before') : action})

    cutoff = dict(bookmark2)

    print('%s syscnt %d' % (node, node.syscall_index))

    sys_old = node
    sys.new = Session.Event(node)

    if sys_old.ret in unistd.EINTERRUPTED:
        sys_new.ret = 0
    else:
        # FIXME: choice of ERESTARTSYS is arbitrary and probably
        # incorrect. specific error value should be syscall specific
        logging.warn('"reverse" signal race may be incorrect...')
        sys_new.ret = unistd.ERESTARTSYS

    replace = dict({sys_old:sys_new})

    print('RACE %2d:  ' % (n_race + 1) +
          'pid %d syscnt %d [sys(%d)=%d/%d]' %
          (node.proc.pid, node.syscall_index,
           sys_old.nr, sys_old.ret, sys_new.ret))
    print('          cut:  %s' % bookmark1.values())

    logging.info('   boobkmark1: %s' % (bookmark1))
    logging.info('   boobkmark2: %s' % (bookmark2))
    logging.info('      injects: %s' % (injects))
    logging.info('       cutoff: %s' % (cutoff))
    logging.info('      replace: %s' % (replace))

    return bookmarks, injects, cutoff, replace

##############################################################################
# races of EXIT-WAIT

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

def find_exitwait_races(graph):
    """Find all exit-wait races and return in a list"""
    exit_races = races_of_exitwait(graph)
    logging.debug('total exit-races %d' % (len(exit_races)))
    return exit_races

def prep_exitwait_race(graph, exit1, exit2, wait, n_race):
    """prepare a race by computing bookmarks, injects, and cutoff"""

    crosscut = graph.crosscut([exit1, exit2, wait])
    bookmark1 = crosscut_to_bookmark(crosscut)

    if not bookmark1:
        print('No consistent cut: exit %s, exit %s, wait %s' %
              (exit1, exit2, wait))
        return None

    bookmark2 = dict(bookmark1)
    bookmark2[exit1.proc] = NodeLoc(exit1, 'after')

    bookmark3 = dict(bookmark2)
    bookmark3[wait.proc] = NodeLoc(wait, 'after')
    del bookmark3[exit1.proc]
    
    bookmarks = [bookmark1, bookmark2, bookmark3]

    injects = dict()

    # we don't need scribe.SCRIBE_PS_ENABLE_DATA, because we know
    # our syscalls are wait() and exit()
    action1 = Action(scribe.SCRIBE_INJECT_ACTION_PSFLAGS,
                    0, scribe.SCRIBE_PS_ENABLE_RESOURCE |
                       scribe.SCRIBE_PS_ENABLE_RET_CHECK)
    injects[exit1.proc] = dict({NodeLoc(exit1.proc, 'before') : [action1]})
    action2 = Action(scribe.SCRIBE_INJECT_ACTION_PSFLAGS,
                    0, scribe.SCRIBE_PS_ENABLE_RESOURCE |
                       scribe.SCRIBE_PS_ENABLE_RET_CHECK)
    injects[wait.proc] = dict({NodeLoc(wait, 'before') : [action2]})

    cutoff = dict(bookmark3)

    # get data (internal) event described wait() during replay
    sys_old = wait
    event = sys_old.copy()
    event.ret = exit1.proc.pid
    sys_new = session.Event(event)
    print('sys_old: %s   sys_new: %s' % (sys_old, sys_new))

    datas = filter(lambda node: node.is_a(scribe.EventDataExtra), wait.children)

    data_old = datas.pop()
    event = data_old.copy()
    event.data_type = scribe.SCRIBE_DATA_INTERNAL
    event.data = struct.pack('i', exit1.proc.pid)
    event.user_ptr = 0
    data_new = session.Event(event)

#    event = scribe.EventDataExtra(user_ptr = 0,
#                                  data_type = scribe.SCRIBE_DATA_INTERNAL,
#                                  data = struct.pack('i', exit1.proc.pid))

    replace = dict({sys_old:sys_new, data_old:data_new})

    # consider a exit-exit-wait race: C exited first, A collected and
    # then B exited. To reorder B and C, we will (1) bookmark everyone
    # prior to the respective syscall, (2) let C execute exit and then
    # bookmark, (3) let A collect C and then another bookmark, and
    # they all resume normal exeution.
    #
    # this is more complicated if the task that waits (A) is init. if
    # we allow task A to attempt wait for C, then A may wait forever
    # because C may remain a child of B (so cannot be reaped by A)...
    # therefore A never reaches the third bookmark and the execution
    # as a whole reaches a deadlock.
    #
    # to address this case, we change the details: we make B and C
    # both run their respective exit calls before hitting, both, the
    # second bookmark. and then let A collect C first, and all go live.

    if wait.proc.pid == 1 and exit1.proc.creator != 1:
        if exit1.proc.creator in cutoff and \
                cutoff[exit1.proc.creator] == NodeLoc(exit1, 'after') or \
                exit1.proc.creator == exit2.proc:

            # discard the 3rd bookmark, allow proc2 to also exit, and
            # finally extend the cut to occur after proc3's wait

            bookmark2[exit2.proc] = NodeLoc(exit2, 'after')
            bookmarks = [bookmark1, bookmark2]

            cutoff = dict(bookmark2)
            cutoff[wait.proc] = NodeLoc(wait, 'after')
        else:
            print('exit-exit-wait race would deadlock .... ' +
                  '%s - %s - %s' % (exit1, exit2, wait))
            return None

    print('RACE %2d:  ' % (n_race + 1) +
          'pid %s syscnt %d [sys(%d)=%d]' %
          (exit1.proc.pid, exit1.syscall_index, exit1.nr, exit1.ret) +
          '  -->   pid %d syscnt %d [sys(%d)=%d]' %
          (wait.proc.pid, wait.syscall_index, wait.nr, wait.ret) +
          '  -->   pid %d syscnt %d [sys(%d)=%d]' %
          (exit2.proc.pid, exit2.syscall_index, exit2.nr, exit2.ret))
    print('          cut:  %s' % bookmark1.values())

    logging.info('   bookmark1: %s' % (bookmark1))
    logging.info('   bookmark2: %s' % (bookmark2))
    logging.info('   bookmark3: %s' % (bookmark3))
    logging.info('     injects: %s' % (injects))
    logging.info('      cutoff: %s' % (cutoff))
    logging.info('     replace: %s' % (replace))

    return bookmarks, injects, cutoff, replace

##############################################################################
# races of TOCTOU

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

def prep_toctou_race(graph, sys1, sys2, attack, n_toctou):
    """prepare a toctou by computing bookmarks, injects, and cutoff"""
    crosscut = graph.crosscut([sys2])
    bookmark1 = crosscut_to_bookmark(crosscut)

    if not bookmark1:
        print('No consistent cut: node %s --> node %s' % (sys1, sys2))
        return None

    bookmarks = [bookmark1]

    cutoff = dict(bookmark1)

    print('TOCTOU %2d:  ' % (n_toctou + 1) +
          'pid %d syscnt %d [sys(%d)=%d]' %
          (sys1.proc.pid, sys1.syscall_index, sys1.nr, sys1.ret) +
          '  -->   pid %d syscnt %d [sys(%d)=%d]' %
          (sys2.proc.pid, sys2.syscall_index, sys2.nr, sys2.ret) +
          ' (%s)' % attack)
    print('          cut:  %s' % bookmark1.values())

    logging.debug('   boobkmark1: %s' % (bookmark1))
    logging.debug('       cutoff: %s' % (cutoff))

    return bookmarks, None, cutoff, None

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
