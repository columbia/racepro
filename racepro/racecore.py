import networkx
import logging
import struct
import pdb
import fnmatch
import datetime

from itertools import *

import unistd
import syscalls
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

def syscall_name(nr):
    if nr in syscalls.Syscalls:
        return syscalls.Syscalls[nr].name
    else:
        return '???(nr=%d)' % nr

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
        s = 'pid %d #%d [%s()=%d]' % \
            (node1.proc.pid, node1.syscall_index, syscall_name(node1.nr), node1.ret) + \
            ' -> pid %d #%d [%s()=%d]' % \
            (node2.proc.pid, node2.syscall_index, syscall_name(node2.nr), node2.ret)

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

        nodes_original = set()
        nodes = set()

        dt_original = datetime.timedelta(0)
        dt_detect = datetime.timedelta(0)

        ignore_type = [ scribe.SCRIBE_RES_TYPE_FUTEX ]

        def skip_parent_dir_race(resource, node1, node2):
            if resource.type not in [scribe.SCRIBE_RES_TYPE_INODE,
                                     scribe.SCRIBE_RES_TYPE_FILES_STRUCT]:
                return False

            for node in [node1, node2]:
                if not node:
                    return False
                if not hasattr(node, 'path'):
                    syscall = syscalls.event_to_syscall(node)
                    node.path = syscalls.get_resource_path(syscall)
                if not node.path or not os.path.isabs(node.path):
                    return False

            path1 = os.path.normpath(node1.path) + '/'
            path2 = os.path.normpath(node2.path) + '/'
            return not (path1.startswith(path2) or path2.startswith(path1))

        def find_races_resource(resource):
            pairs = list()
            ievents_per_proc = \
                _split_events_per_proc(resource, in_syscall=True)
            events_per_proc = \
                dict_values_to_lists(ievents_per_proc)
            for proc1, proc2 in combinations(events_per_proc, 2):
                for node1 in events_per_proc[proc1]:
                    for node2 in events_per_proc[proc2]:
                        if node2.syscall.vclock.before(node1.syscall.vclock):
                            continue
                        if node1.syscall.vclock.before(node2.syscall.vclock):
                            break
                        if node1.write_access == 0 and node2.write_access == 0:
                            continue
                        # SKIP: skip access to same dir but different paths
                        if skip_parent_dir_race(resource,
                                                node1.syscall,
                                                node2.syscall):
                            logging.debug('false positive due to path: %s=>%s' %
                                          (node1, node2))
                            continue
                        assert node1.serial != node2.serial, \
                            'race %s vs. %s with same serial' % (node1, node2)
                        if node1.serial < node2.serial:
                            pairs.append((node2, node2))
                        else:
                            pairs.append((node1, node2))
            return pairs

        def find_races_resource_optimized(resource):
            pairs = list()
            ievents_per_proc = \
                _split_events_per_proc(resource, in_syscall=True)
            events_per_proc = \
                dict_values_to_lists(ievents_per_proc)

            for proc1, proc2 in combinations(events_per_proc, 2):
                # OPTIMIZE: two processes have happens-before
                if not events_per_proc[proc1] or not events_per_proc[proc2] or \
                   events_per_proc[proc1][-1].syscall.vclock.before(
                        events_per_proc[proc2][0].syscall.vclock) or \
                   events_per_proc[proc2][-1].syscall.vclock.before(
                        events_per_proc[proc1][0].syscall.vclock):
                    continue

                vc_index1 = vc_index2 = 0
                for node1 in events_per_proc[proc1]:

                    # OPTIMIZE: proc2 nodes that happen BEFORE proc1.node1
                    for node2 in events_per_proc[proc2][vc_index1:]:
                        if not node2.syscall.vclock.before(node1.syscall.vclock):
                            break
                        vc_index1 += 1
                    if vc_index1 >= len(events_per_proc[proc2]):
                        break
                    if vc_index2 < vc_index1:
                        vc_index2 = vc_index1

                    # OPTIMIZE: proc2 nodes that don't happen AFTER proc1.node1
                    for node2 in events_per_proc[proc2][vc_index2:]:
                        if node1.syscall.vclock.before(node2.syscall.vclock):
                            break
                        vc_index2 += 1

                    for node2 in events_per_proc[proc2][vc_index1:vc_index2]:
                        if node1.write_access == 0 and node2.write_access == 0:
                            continue
                        # SKIP: skip access to same dir but different paths
                        if skip_parent_dir_race(resource,
                                                node1.syscall,
                                                node2.syscall):
                            logging.debug('false positive due to path: %s=>%s' %
                                          (node1, node2))
                            continue
                        assert node1.serial != node2.serial, \
                            'race %s vs. %s with same serial' % (node1, node2)
                        if node1.serial < node2.serial:
                            pairs.append((node2, node1))
                        else:
                            pairs.append((node1, node2))
            return pairs

        ignore_path = []
        if hasattr(graph.processes[1], 'fd'):
            ignore_path += graph.processes[1].fd.values()

        if RaceResource.ignore_path:
            ignore_path += RaceResource.ignore_path
        for path in ignore_path:
            logging.debug('ignore this path: %s' % path)

        for resource in graph.resources.itervalues():
            # ignore resources with no WRITE access
            if not next(ifilter(lambda e: e.write_access > 0, resource.events), None):
                logging.debug('resource %d: skip no write access' % resource.id)
                continue
            # ignore some resources
            if resource.type in ignore_type:
                logging.debug('resource %d: skip type ignored' % resource.id)
                continue

            # SKIP: given file path pattern
            ismatch = False
            if resource.type == scribe.SCRIBE_RES_TYPE_FILE:
                for pattern in ignore_path:
                    if fnmatch.fnmatch(resource.desc, pattern):
                        ismatch = True
                        break
            if ismatch:
                continue

            t_start_original = datetime.datetime.now()
            pairs_original = find_races_resource(resource)
            t_start = datetime.datetime.now()
            pairs = find_races_resource_optimized(resource)
            t_end = datetime.datetime.now()

            dt_original += t_start - t_start_original
            dt_detect += t_end - t_start

            for node1, node2 in pairs_original:
                nodes_original.add((node1.syscall, node2.syscall))
                logging.debug('\t(original) adding %s -> %s racing on %s' % \
                              (node1.syscall, node2.syscall, resource))

            for node1, node2 in pairs:
                nodes.add((node1.syscall, node2.syscall))
                logging.debug('\t(optimized) adding %s -> %s racing on %s' % \
                              (node1.syscall, node2.syscall, resource))

        logging.debug("original algorithm: %d found in %.2f sec " % (len(nodes_original),
                      dt_original.seconds + dt_original.microseconds / 1000000.0))
        logging.debug("optimized algorithm: %d found in %.2f sec " % (len(nodes),
                      dt_detect.seconds + dt_detect.microseconds / 1000000.0))
        logging.debug("    intersect: %d" % len(nodes.intersection(nodes_original)))

        return [RaceResource(n1, n2) for n1, n2 in nodes]

##############################################################################
# races of SIGNALS

class RaceSignal(Race):
    def __init__(self, node):
        Race.__init__(self)
        self.signal = node

    def __str__(self):
        node = self.node
        s = 'pid %d #%d [%s()= %d->%d]' % \
            (node.proc.pid, node.syscall_index,
             syscall_name(node.syscall.nr), self.old_ret, self.new_ret)

        if self._prepared:
            for n, bookmark in enumerate(self.bookmarks):
                logging.debug('   bookmark%d: %s' % (n, bookmark))
            logging.debug('      injects: %s' % (self.injects))
            logging.debug('       cutoff: %s' % (self.cutoff))
            logging.debug('      replace: %s' % (self.replace))

        return s

    def prepare(self, graph):
        node = self.signal.handled
        if not node:
            return False

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
        s = 'pid %s #%d [%s()=%d]' % \
            (exit1.proc.pid, exit1.syscall_index, syscall_name(exit1.nr), exit1.ret) + \
            ' -> pid %d #%d [%s()=%d]' % \
            (wait.proc.pid, wait.syscall_index, syscall_name(wait.nr), wait.ret) + \
            ' -> pid %d #%d [%s()=%d]' % \
            (exit2.proc.pid, exit2.syscall_index, syscall_name(exit2.nr), exit2.ret)

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
            ', pid %d #%d [%s()=%d]' % \
            (sys1.proc.pid, sys1.syscall_index, syscall_name(sys1.nr), sys1.ret) + \
            ' -> pid %d #%d [%s()=%d]' % \
            (sys2.proc.pid, sys2.syscall_index, syscall_name(sys2.nr), sys2.ret) + \
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
                                break
                            if pattern.check(sys_old, sys_cur):
                                nodes.add((sys_old, sys_cur, pattern,
                                           pattern.generate(sys_old, sys_cur)))
                                logging.debug('\tadding %s -> %s to pattern %s' % 
                                              (sys_old, sys_cur, pattern.desc))

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

def output_races(race_list, path, desc, count):
    print('-' * 79)
    print('%s' % desc)
    print('  found %d potential races' % len(race_list))
    print('-' * 79)

    logging.debug('Race list %s' % race_list)

    for race in race_list:
        if race.prepare(race_list.graph):
            count += 1
            print('RACE %2d: %s' % (count, race))
            race.output(race_list.graph, path + '.' + str(count))

    return count

def find_show_races(graph, args):
    total = 0
    count = 0
    dt_outputrace = datetime.timedelta(0)

    # step 1: find resource races
    RaceResource.max_races = args.max_races
    RaceResource.ignore_path = args.ignore_path
    race_list = RaceList(graph, RaceResource.find_races)
    race_list._races.sort(reverse=True, key=lambda race: race.rank)
    if args.max_races and total + len(race_list) > args.max_races:
        logging.info('too many races: %d' % len(race_list))
        race_list._races = race_list._races[:args.max_races - total]
    total += len(race_list)
    t_start = datetime.datetime.now()
    count = output_races(race_list, args.path, 'RESOURCE', count)
    t_end = datetime.datetime.now() 
    dt_outputrace += t_end - t_start
    races = race_list
    # step 2: find exit-exit-wait races
    if args.no_exit_races:
        race_list = list()
    else:
        race_list = RaceList(graph, RaceExitWait.find_races)
        if args.max_races and total + len(race_list) > args.max_races:
            logging.info('too many races: %d' % len(race_list))
            race_list._races = race_list._races[:args.max_races - total]
        races.extend(race_list)
    t_start = datetime.datetime.now()
    count = output_races(race_list, args.path, 'EXIT-WAIT', count)
    t_end = datetime.datetime.now()
    dt_outputrace += t_end - t_start
    total += len(race_list)

    # step 3: find signal races
    if args.no_signal_races:
        race_list = list()
    else:
        race_list = RaceList(graph, RaceSignal.find_races)
        if args.max_races and total + len(race_list) > args.max_races:
            logging.info('too many races: %d' % len(race_list))
            race_list._races = race_list._races[:args.max_races - total]
        races.extend(race_list)
    count = output_races(race_list, args.path, 'SIGNAL', count)
    total += len(race_list)

    # step 4: statistics
    print('Generated %d logs for races out of %d candidates' % (count, total))
    print('-' * 79)

    return races

def instrumented_replay(graph, args, queriers):
    bookmarks = list()
    events = networkx.algorithms.dag.topological_sort(graph)

    for node in events:
        if not node.is_a(scribe.EventSyscallExtra):
            continue

        node.queriers = list()
        bookmark_before_node = bookmark_after_node = None

        for querier in queriers:
            if querier.need_bookmark(node, graph, before=True):
                node.queriers.append(querier)
                bookmark_before_node = NodeLoc(node, 'before')
            if querier.need_bookmark(node, graph, after=True):
                node.queriers.append(querier)
                bookmark_after_node = NodeLoc(node, 'after')

        for bmark in [bookmark_before_node, bookmark_after_node]:
            if bmark:
                bookmarks.append(dict({node.proc: bmark}))

    out = args.path + '.pre.log'
    save_modify_log(graph, out, bookmarks, None, None, None)

    def predetect_bookmark_cb(**kargs):
        bookmarks = kargs['bookmarks']
        exe = kargs['exe']
        id = kargs['id']

        for nl in bookmarks[id].values():
            logging.debug('reach bookmark %s' % nl)
            for querier in nl.node.queriers:
                logging.debug('    querier: %s' % querier)
                querier.upon_bookmark(nl.node, exe,
                                      before=nl.before,
                                      after=nl.after)
        return True

    bookmark_cb = scribewrap.Callback(predetect_bookmark_cb, bookmarks=bookmarks)

    ret = scribewrap.scribe_replay(args, logfile=out, bookmark_cb=bookmark_cb)
    if not ret:
        #raise execute.ExecuteError(
        logging.debug('failure: %s (ret = %d)' %
                ('pre-detect replay failed: try with --skip-predetect', ret))

    for node in events:
        if not node.is_a(scribe.EventSyscallExtra):
            continue

        for querier in queriers:
            querier.after_replay(graph, node)

def find_show_toctou(graph, args):
    total = 0
    count = 0

    # step 1: find toctou races
    race_list = RaceList(graph, RaceToctou.find_races)
    total += len(race_list)
    count = output_races(race_list, args.path, 'TOCTOU', count)

    # step 2: statistics
    print('Generated %d logs for races of of %d candidates' % (count, total))
    print('-' * 79)

    return race_list

class PredetectBookmarks:
    def need_bookmark(self, event, graph, before=False, after=False):
        return False

    def upon_bookmark(self, event, exe, before=False, after=False):
        assert False

    def after_replay(self, graph, event):
        pass

    def __init__(self):
        pass

syscalls.declare_syscall_sets({
        "ChangePath" : ["chroot", "chdir", "fchdir"],
        })

class BookmarksForPaths(PredetectBookmarks):
    def need_bookmark(self, event, graph, before=False, after=False):
        if after: return False

        if not hasattr(event.proc, 'paths') or event.proc.paths is None:
           event.paths = event.proc.paths = dict()
           return True

        event.paths = event.proc.paths

        if event.nr in unistd.SYS_fork and event.ret > 0:
            graph.processes[event.ret].paths = event.proc.paths
            
        if event.nr in SYS_ChangePath:
            event.proc.paths = None

        return False

    def upon_bookmark(self, event, exe, before=False, after=False):
        pid = exe.pids[event.proc.pid]
        proc = exe.chroot + '/proc'
        cwd = os.readlink('%s/%d/cwd' % (proc, pid))
        root = os.readlink('%s/%d/root' % (proc, pid))
        event.proc.paths['cwd'] = \
            os.path.normpath('/' + os.path.relpath(cwd, root))
        event.proc.paths['root'] = \
            os.path.normpath('/' + os.path.relpath(root, exe.chroot))

    def after_replay(self, graph, event):
        syscall = syscalls.event_to_syscall(event)
        path = syscalls.get_resource_path(syscall)
        if path and 'cwd' in event.paths:
            event.path = os.path.join(event.paths['cwd'], path)
 
class BookmarksForFirstProc(PredetectBookmarks):
    def need_bookmark(self, event, graph, before=False, after=False):
        return before and event.proc.pid == 1 and \
               event == event.proc.syscalls[0]

    def upon_bookmark(self, event, exe, before=False, after=False):
        event.proc.fd = dict()
        pid = exe.pids[event.proc.pid]
        proc = exe.chroot + '/proc'
        for fd in os.listdir('%s/%d/fd' % (proc, pid)):
            fd = int(fd)
            path = os.readlink('%s/%d/fd/%d' % (proc, pid, fd))
            if path.startswith('/'):
                event.proc.fd[fd] = \
                    os.path.normpath('/' + os.path.relpath(path, exe.chroot))
            else:
                event.proc.fd[fd] = path

class BookmarksForStats(PredetectBookmarks):
    def need_bookmark(self, event, graph, before=False, after=False):
        if before:
            syscall = syscalls.event_to_syscall(event)
            path = syscalls.get_resource_path(syscall)
            if path is not None:
                event.path = path
                return True
        return False

    def upon_bookmark(self, event, exe, before=False, after=False):
        def _query_event_file_stat(event, exe, path, keys=None):
            if not hasattr(event, 'stat'):
                event.stat = dict()

            def set_event_stat(path):
                path = os.path.normpath(path)
                if path in event.stat:
                    return
                event.stat[path] = dict()
                if os.path.exists(exe.chroot + path):
                    file_stat = os.stat(exe.chroot + path)
                    for attr in dir(file_stat):
                        if attr.startswith('st_') and (keys and attr in keys):
                            event.stat[path][attr] = getattr(file_stat, attr)

            set_event_stat(path)
            while path != '/':
                path = os.path.dirname(path)
                set_event_stat(path)

        event.path = os.path.join(event.proc.paths['cwd'], event.path)
        _query_event_file_stat(event, exe, event.path, self._keys)

    def __init__(self, keys=None):
        self._keys = keys


BookmarksForResources = [BookmarksForPaths(), BookmarksForFirstProc()]
BookmarksForToctou = [BookmarksForPaths(), BookmarksForStats()]
