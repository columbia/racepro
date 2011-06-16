import networkx
import logging
import struct
import pdb

from itertools import *

import unistd
import scribe
import scribewrap
import toctou
from execgraph import NodeLoc
from helpers import *

##############################################################################

class Race:
    def __init__(self):
        self._prepared = False
        self.bookmarks = None
        self.injects = None
        self.cutoff = None
        self.replace = None

    def __str__(self):
        raise NotImplementedError('Subclasses should implement this')

    def prepare(self, graph):
        raise NotImplementedError('Subclasses should implement this')

    def rank(self):
        return 0

    def output(self, graph, output):
        save_modify_log(graph, output + '.log',
                        self.bookmarks,
                        self.injects,
                        self.cutoff,
                        self.replace)

class RaceList:
    def __init__(self, graph, find_races):
        self.graph = graph
        self._races = find_races(graph)

    def __iter__(self):
        return iter(self._races)

    def __len__(self):
        return len(self._races)

    def __getitem__(self, index):
        return self._races[index]

    def extend(self, race_list):
        self._races.extend(race_list._races)

##############################################################################

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

class RaceResource(Race):
    def __init__(self, node1, node2):
        Race.__init__(self)
        self.node1 = node1
        self.node2 = node2

    def __str__(self):
        node1 = self.node1
        node2 = self.node2
        s = 'pid %d #%d [sys(%d)=%d]' % \
            (node1.proc.pid, node1.syscall_index, node1.nr, node1.ret) + \
            ' -> pid %d #%d [sys(%d)=%d]' % \
            (node2.proc.pid, node2.syscall_index, node2.nr, node2.ret)

        if self._prepared:
            for n, bookmark in enumerate(self.bookmarks):
                logging.debug('   bookmark%d: %s' % (n, bookmark))
            logging.debug('      injects: %s' % (self.injects))
            logging.debug('       cutoff: %s' % (self.cutoff))

        return s

    def rank(self):
        """Rank race importance by calcaulating the average distance
        between accesses to resources in the corresponding nodes"""

        def event_is_resource(event):
            return \
                event.is_a(scribe.EventResourceLockExtra) or \
                event.is_a(scribe.EventResourceLockIntr)

        count = 0

        resources1 = ifilter(event_is_resource, self.node1.children)
        resources2 = ifilter(event_is_resource, self.node2.children)

        for event1, event2 in product(resources1, resources2):
            if event1.resource == event2.resource:
                assert event1 != event2
                if event1.write_access != 0 or event2.write_access != 0:
                    distance += abs(event1.serial - event2.serial)
                    count += 1

        distance = float(distance) / count

        logging.debug('race %s,%s avg distance=%d'
                      % (self.node1, self.node2, distance))

        return distance

    def prepare(self, graph):
        node1 = self.node1
        node2 = self.node2
        crosscut = graph.crosscut([node1, node2])

        # bookmarks
        bookmark1 = crosscut_to_bookmark(crosscut)
        assert bookmark1, 'no crosscut %s -> %s' % (node1, node2)

        bookmark2 = dict(bookmark1)
        bookmark2[node1.proc] = NodeLoc(node1, 'after')

        bookmarks = [bookmark1, bookmark2]

        # injects
        mask = (scribe.SCRIBE_PS_ENABLE_RESOURCE |
                scribe.SCRIBE_PS_ENABLE_RET_CHECK)

        if node1.nr not in unistd.SYS_wait:
            mask |= scribe.SCRIBE_PS_ENABLE_DATA

        action = Action(scribe.SCRIBE_INJECT_ACTION_PSFLAGS, 0, mask)
        actions = list([action])

        injects = dict()
        injects[node1.proc] = dict({NodeLoc(node1, 'before') : actions})

        # cutoff
        cutoff = dict(bookmark2)

        self.bookmarks = bookmarks
        self.injects = injects
        self.cutoff = cutoff

        self._prepared = True

        return True

    @staticmethod
    def find_races(graph):
        """Return list of all resource races in @graph"""

        # for each resource, separate the events of that reosurce per
        # process, and find racing events.

        total = 0
        nodes = set()

        ignore_type = [ scribe.SCRIBE_RES_TYPE_FUTEX ]
        ignore_thresh = 100

        def find_races_resource(resource):
            pairs = list()
            ievents_per_proc = \
                _split_events_per_proc(resource, in_syscall=True)
            events_per_proc = \
                dict_values_to_lists(ievents_per_proc)
            for proc1, proc2 in combinations(events_per_proc, 2):
                for node1 in events_per_proc[proc1]:
                    for node2 in events_per_proc[proc2]:
                        if node1.syscall.vclock.before(node2.syscall.vclock):
                            break
                        if node2.syscall.vclock.before(node1.syscall.vclock):
                            continue
                        if node1.write_access == 0 and node2.write_access == 0:
                            continue
                        assert node1.serial != node2.serial, \
                            'race %s vs. %s with same serial' % (node1, node2)
                        if node1.serial < node2.serial:
                            node1, node2 = node2, node1
                        pairs.append((node1, node2))
            return pairs

        for resource in graph.resources.itervalues():
            # ignore some resources
            if resource.type in ignore_type:
                continue
            # ignore resource with too many events (FIXME)
            if len(resource.events) > ignore_thresh:
                logging.info('resource %d has too many events (%d); skip'
                             % (resource.id, len(resource.events)))
                continue

            pairs = find_races_resource(resource)
            total += len(pairs)

            for node1, node2 in pairs:
                nodes.add((node1.syscall, node2.syscall))
                logging.debug('\tadding %s -> %s to races' % (node1, node2))

        return [RaceResource(n1, n2) for n1, n2 in nodes]

##############################################################################
# races of SIGNALS

class RaceSignal(Race):
    def __init__(self, node):
        Race.__init__(self)
        self.signal = signal

    def __str__(self):
        node = self.node
        s = 'pid %d #%d [sys(%d)= %d->%d]' % \
            (node.proc.pid, node.syscall_index,
             node.syscall.nr, self.old_ret, self.new_ret)

        if self._prepared:
            for n, bookmark in enumerate(self.bookmarks):
                logging.debug('   bookmark%d: %s' % (n, bookmark))
            logging.debug('      injects: %s' % (self.injects))
            logging.debug('       cutoff: %s' % (self.cutoff))
            logging.debug('      replace: %s' % (self.replace))

        return s

    def prepare(self, graph):
        node = self.signal.handled
        crosscut = graph.crosscut([node])

        # bookmarks
        bookmark1 = crosscut_to_bookmark(crosscut)
        assert bookmark1, 'no crosscut pid %d syscall %d' \
            % (node.proc.pid, node.syscall_index)

        bookmark2 = dict(bookmark1)
        bookmark2[node.proc] = NodeLoc(node, 'after')

        bookmarks = [bookmark1, bookmark2]

        # injects
        action = Action(scribe.SCRIBE_INJECT_ACTION_PSFLAGS,
                        0, scribe.SCRIBE_PS_ENABLE_RESOURCE |
                        scribe.SCRIBE_PS_ENABLE_RET_CHECK)

        injects = dict()
        injects[node.proc] = dict({NodeLoc(node, 'before') : action})

        # cutoff
        cutoff = dict(bookmark2)

        # replace
        sys_old = node
        sys.new = Session.Event(node)

        # If signal interrupted the syscall -> make it not interrupt
        # If signal did not interrupt the syscall -> make it interrupt
        # We reverse the signal's effect by "reversing" the syscall
        # retval (from interrupted to non-interrupted or vice versa)

        if sys_old.ret in unistd.EINTERRUPTED:
            sys_new.ret = 0
        else:
            # FIXME: choice of ERESTARTSYS is arbitrary and probably
            # incorrect. specific error value should be syscall specific
            logging.warn('"reverse" signal race may be incorrect...')
            sys_new.ret = unistd.ERESTARTSYS

        replace = dict({sys_old:sys_new})

        self.old_ret = sys_old.ret
        self.new_ret = sys_new.ret

        self.bookmarks = bookmarks
        self.injects = injects
        self.cutoff = cutoff
        self.replace = replace

        self._prepared = True

        return True

    @staticmethod
    def find_races(graph):
        """Return list of all signal races in @graph"""

        return [RaceSignal(s) for s in graph.signals]

##############################################################################
# races of EXIT-WAIT

class RaceExitWait(Race):
    def __init__(self, exit1, exit2, wait):
        Race.__init__(self)
        self.exit1 = exit1
        self.exit2 = exit2
        self.wait = wait

    def __str__(self):
        exit1 = self.exit1
        exit2 = self.exit2
        wait = self.wait
        s = 'pid %s #%d [sys(%d)=%d]' % \
            (exit1.proc.pid, exit1.syscall_index, exit1.nr, exit1.ret) + \
            ' -> pid %d #%d [sys(%d)=%d]' % \
            (wait.proc.pid, wait.syscall_index, wait.nr, wait.ret) + \
            ' -> pid %d #%d [sys(%d)=%d]' % \
            (exit2.proc.pid, exit2.syscall_index, exit2.nr, exit2.ret)

        if self._prepared:
            for n, bookmark in enumerate(self.bookmarks):
                logging.debug('   bookmark%d: %s' % (n, bookmark))
            logging.debug('     injects: %s' % (self.injects))
            logging.debug('      cutoff: %s' % (self.cutoff))
            logging.debug('     replace: %s' % (self.replace))

        return s

    def prepare(self, graph):
        exit1 = self.exit1
        exit2 = self.exit2
        wait = self.wait
        crosscut = graph.crosscut([exit1, exit2, wait])

        # bookmarks
        bookmark1 = crosscut_to_bookmark(crosscut)
        assert bookmark1, 'no crosscut exit %s exit %s wait %s' \
            % (exit1, exit2, wait)

        bookmark2 = dict(bookmark1)
        bookmark2[exit1.proc] = NodeLoc(exit1, 'after')

        bookmark3 = dict(bookmark2)
        bookmark3[wait.proc] = NodeLoc(wait, 'after')
        del bookmark3[exit1.proc]

        bookmarks = [bookmark1, bookmark2, bookmark3]

        # injects
        # we don't need scribe.SCRIBE_PS_ENABLE_DATA, because we know
        # our syscalls are wait() and exit()
        action1 = Action(scribe.SCRIBE_INJECT_ACTION_PSFLAGS,
                        0, scribe.SCRIBE_PS_ENABLE_RESOURCE |
                           scribe.SCRIBE_PS_ENABLE_RET_CHECK)
        action2 = Action(scribe.SCRIBE_INJECT_ACTION_PSFLAGS,
                        0, scribe.SCRIBE_PS_ENABLE_RESOURCE |
                           scribe.SCRIBE_PS_ENABLE_RET_CHECK)

        injects = dict()
        injects[exit1.proc] = dict({NodeLoc(exit1.proc, 'before') : [action1]})
        injects[wait.proc] = dict({NodeLoc(wait, 'before') : [action2]})

        # cutoff
        cutoff = dict(bookmark3)

        # replace
        # get data (internal) event described wait() during replay
        sys_old = wait
        event = sys_old.copy()
        event.ret = exit1.proc.pid
        sys_new = session.Event(event)

        datas = filter(lambda node: node.is_a(scribe.EventDataExtra),
                       wait.children)

        data_old = datas.pop()
        event = data_old.copy()
        event.data_type = scribe.SCRIBE_DATA_INTERNAL
        event.data = struct.pack('i', exit1.proc.pid)
        event.user_ptr = 0
        data_new = session.Event(event)

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

                # bookmarks (new)
                bookmark2[exit2.proc] = NodeLoc(exit2, 'after')
                bookmarks = [bookmark1, bookmark2]

                # cutoff (new)
                cutoff = dict(bookmark2)
                cutoff[wait.proc] = NodeLoc(wait, 'after')
            else:
                logging.info('exit-exit-wait race would deadlock ... ')
                logging.info('  syscalls: %s, %s, %s' % (exit1, exit2, wait))
                return False

        self.bookmarks = bookmarks
        self.injects = injects
        self.cutoff = cutoff
        self.replace = replace

        self._prepared = True

        return True

    @staticmethod
    def find_races(graph):
        """Return list of all exit-wait races in @graph"""

        # divide the exits() into per-parent lists, each list ordered
        # by vclocks: loop on waits to determine where each exit (by
        # pid) belongss and then add exits.

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

        races = list()

        # find potential races: for each exit event, search ahead for
        # races with other exits that are concurrent with this exit (and
        # under the same reaper)

        for proc in exits_by_reaper:
            for exit1, exit2, in combinations(exits_by_reaper[proc], 2):
                if exit1.vclock.race(exit2.vclock):
                    wait1 = reaper_wait_of[exit1.proc]
                    wait2 = reaper_wait_of[exit2.proc]
                    assert not wait1.vclock.race(wait2.vclock)
                    if wait1.vclock.before(wait2.vclock):
                        races.append((exit2, exit1, wait1))
                    else:
                        races.append((exit1, exit2, wait2))

        return [RaceExitWait(e1, e2, w) for e1, e2, w in races]

##############################################################################
# races of TOCTOU

class RaceToctou(Race):
    def __init__(self, sys1, sys2, pattern, attack):
        Race.__init__(self)
        self.sys1 = sys1
        self.sys2 = sys2
        self.pattern = pattern
        self.attack = attack

    def __str__(self):
        sys1 = self.sys1
        sys2 = self.sys2
        attack = self.attack

        s = 'pattern: %s ' % self.pattern.desc + \
            ', pid %d #%d [sys(%d)=%d]' % \
            (sys1.proc.pid, sys1.syscall_index, sys1.nr, sys1.ret) + \
            ' -> pid %d #%d [sys(%d)=%d]' % \
            (sys2.proc.pid, sys2.syscall_index, sys2.nr, sys2.ret) + \
            ' (%s)' % attack

        if self._prepared:
            logging.debug('   boobkmark1: %s' % (self.bookmarks[0]))
            logging.debug('       cutoff: %s' % (self.cutoff))

        return s

    def output(self, graph, output):
        Race.output(self, graph, output)
        with open(output + '.toctou', 'w') as out:
            out.write('%s\n' % self.attack)

    def prepare(self, graph):
        sys1 = self.sys1
        sys2 = self.sys2
        crosscut = graph.crosscut([sys2])

        # bookmarks
        bookmark1 = crosscut_to_bookmark(crosscut)
        assert bookmark1, 'no crosscut sys %s sys %s' % (sys1, sys2)

        bookmarks = [bookmark1]

        # cutoff
        cutoff = dict(bookmark1)

        self.bookmarks = bookmarks
        self.cutoff = cutoff

        self._prepared = True

        return True

    @staticmethod
    def find_races(graph):
        """Return list of all toctou races in @graph"""

        nodes = set()

        def find_races_resource(resource):
            events_per_proc = _split_events_per_proc(resource, in_syscall=True)

            for proc in events_per_proc:
                syscalls = dict()

                for pattern in toctou.patterns:
                    syscalls[pattern.syscallset1] = list()

                def check_pattern(racing_syscalls, sys_cur):
                    for pattern in toctou.patterns:
                        if sys_cur.nr not in pattern.syscallset2:
                            continue
                        for sys_old in syscalls[pattern.syscallset1]:
                            if sys_cur.vclock.before(sys_old.vclock):
                                continue
                            if pattern.check(sys_old, sys_cur):
                                nodes.add((sys_old, sys_cur, pattern,
                                           pattern.generate(sys_old, sys_cur)))

                for node in events_per_proc[proc]:
                    check_pattern(syscalls, node.syscall)
                    for pattern in toctou.patterns:
                        if node.syscall.nr in pattern.syscallset1:
                            syscalls[pattern.syscallset1].append(node.syscall)

                for other in filter(lambda p: p != proc, events_per_proc):
                    for node in events_per_proc[other]:
                        check_pattern(syscalls, node.syscall)

        candidate_resources = [
            scribe.SCRIBE_RES_TYPE_FILE,
            scribe.SCRIBE_RES_TYPE_FILES_STRUCT,
            scribe.SCRIBE_RES_TYPE_INODE,
            ]

        for resource in graph.resources.itervalues():
            if resource.type in candidate_resources:
                find_races_resource(resource)

        return [RaceToctou(s1, s2, p, a) for s1, s2, p, a in nodes]

##############################################################################

def output_races(race_list, path, desc, count, limit):
    print('-' * 79)
    print('%s' % desc)
    print('  found %d potential races' % len(race_list))
    print('-' * 79)

    logging.debug('Race list %s' % race_list)

    for race in race_list:
        if count >= limit:
            break;
        if race.prepare(race_list.graph):
            count += 1
            print('RACE %2d: %s' % (count, race))
            race.output(race_list.graph, path + '.' + str(count))

    return count

def find_show_races(graph, args):
    total = 0
    count = 0

    # step 1: find resource races
    race_list = RaceList(graph, RaceResource.find_races)
    race_list._races.sort(reverse=True, key=lambda race: race.rank)
    total += len(race_list)
    count = output_races(race_list, args.path, 'RESOURCE', count, args.count)
    races = race_list

    # step 2: find exit-exit-wait races
    if args.no_exit_races:
        race_list = list()
    else:
        race_list = RaceList(graph, RaceExitWait.find_races)
    total += len(race_list)
    count = output_races(race_list, args.path, 'EXIT-WAIT', count, args.count)
    races.extend(race_list)

    # step 3: find signal races
    if args.no_signal_races:
        race_list = list()
    else:
        race_list = RaceList(graph, RaceSignal.find_races)
    total += len(race_list)
    count = output_races(race_list, args.path, 'SIGNAL', count, args.count)
    races.extend(race_list)

    # step 4: statistics
    print('Generated %d logs for races out of %d candidates' % (count, total))
    print('-' * 79)

    return races

def replay_for_toctou(graph, args):

    bookmarks = list()

    for node in networkx.algorithms.dag.topological_sort(graph):
        if not node.is_a(scribe.EventSyscallExtra):
            continue

        node.queriers = list()

        for querier in toctou.queriers:
            if querier.need_bookmark(node, before=True):
                node.queriers.append(querier)
                bookmarks.append(dict({node.proc: NodeLoc(node, 'before')}))
            if querier.need_bookmark(node, after=True):
                node.queriers.append(querier)
                bookmarks.append(dict({node.proc: NodeLoc(node, 'after')}))

    out = args.path + '.toctou.log'
    save_modify_log(graph, out, bookmarks, None, None, None)

    def toctou_bookmark_cb(**kargs):
        bookmarks = kargs['bookmarks']
        exe = kargs['exe']
        id = kargs['id']

        for nl in bookmarks[id].values():
            node = nl.node
            for querier in node.queriers:
                querier.upon_bookmark(nl.node, exe,
                                      before=nl.before,
                                      after=nl.after)

        return True

    bookmark_cb = scribewrap.Callback(toctou_bookmark_cb, bookmarks=bookmarks)

    print('ABOUT TO REPLAY TOCTOU')
    ret = scribewrap.scribe_replay(args, logfile=out, bookmark_cb=bookmark_cb)
    if not ret:
        raise execute.ExecuteError('toctou replay', ret)

    for bookmark in bookmarks:
        for nl in bookmark.values():
            for querier in nl.node.queriers:
                querier.debug(nl.node)

def find_show_toctou(graph, args):
    total = 0
    count = 0

    # step 0: controlled replay to get extra info on special syscalls
    replay_for_toctou(graph, args)

    # step 1: find toctou races
    race_list = RaceList(graph, RaceToctou.find_races)
    total += len(race_list)
    count = output_races(race_list, args.path, 'TOCTOU', count, args.count)

    # step 2: statistics
    print('Generated %d logs for races of of %d candidates' % (count, total))
    print('-' * 79)

    return race_list