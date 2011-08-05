import networkx
import logging
import struct
import pdb

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

        total = 0
        nodes = set()

        ignore_type = [ scribe.SCRIBE_RES_TYPE_FUTEX ]

        def skip_parent_dir_race(resource, node1, node2):
            for node in [node1, node2]:
                if not node: continue
                if hasattr(node, 'path_info'):
                    node.proc.path_info = node.path_info

            if resource.type not in [scribe.SCRIBE_RES_TYPE_FILE,
                                     scribe.SCRIBE_RES_TYPE_FILES_STRUCT,
                                     scribe.SCRIBE_RES_TYPE_INODE]:
                return False

            for node in [node1, node2]:
                if not node: continue
                if not hasattr(node, 'path'):
                    node.path = syscalls.get_resource_path(
                                syscalls.event_to_syscall(node))
                    if node.path and not os.path.isabs(node.path):
                        if hasattr(node.proc, 'path_info'):
                            node.path = os.path.join(node.proc.path_info['cwd'],
                                                     node.path)
                        else:
                            node.path = None
                if not node.path:
                    return False
            return node1 and node2 and \
                   os.path.commonprefix([node1.path, node2.path]) not in \
                   [node1.path, node2.path]

        def skip_false_positive(resource, node1, node2):
            if node1: node1 = node1.syscall
            if node2: node2 = node2.syscall
            if skip_parent_dir_race(resource, node1, node2): 
                return True
            return False

        def find_races_resource(resource):
            pairs = list()
            ievents_per_proc = \
                _split_events_per_proc(resource, in_syscall=True)
            events_per_proc = \
                dict_values_to_lists(ievents_per_proc)
            for proc1, proc2 in combinations(events_per_proc, 2):
                #ignore resource with too many events
                if RaceResource.resource_thres and \
                    len(events_per_proc[proc1])*len(events_per_proc[proc2]) \
                    > RaceResource.resource_thres:
                        logging.info('resource %d has too many events: %s=>%d, %s=>%d; skip' %
                                     (resource.id, 
                                     proc1, len(events_per_proc[proc1]),
                                     proc2, len(events_per_proc[proc2])))
                        continue

                for node1 in events_per_proc[proc1]:
                    if skip_false_positive(resource, node1, None):
                        continue
                    for node2 in events_per_proc[proc2]:
                        if skip_false_positive(resource, None, node2):
                            continue
                        if node1.syscall.vclock.before(node2.syscall.vclock):
                            break
                        if node2.syscall.vclock.before(node1.syscall.vclock):
                            continue
                        if node1.write_access == 0 and node2.write_access == 0:
                            continue
                        if skip_false_positive(resource, node1, node2):
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

    # step 0: controlled replay to get extra info on special syscalls
    predetect_replay(graph, args, [NodeBookmarkPath()])

    # step 1: find resource races
    RaceResource.resource_thres = args.resource_thres
    RaceResource.max_races = args.max_races
    race_list = RaceList(graph, RaceResource.find_races)
    race_list._races.sort(reverse=True, key=lambda race: race.rank)
    total += len(race_list)
    count = output_races(race_list, args.path, 'RESOURCE', count)
    races = race_list

    # step 2: find exit-exit-wait races
    if not args.no_exit_races:
        race_list = RaceList(graph, RaceExitWait.find_races)
        total += len(race_list)
        count = output_races(race_list, args.path, 'EXIT-WAIT', count)
        races.extend(race_list)

    # step 3: find signal races
    if not args.no_signal_races:
        race_list = RaceList(graph, RaceSignal.find_races)
        total += len(race_list)
        count = output_races(race_list, args.path, 'SIGNAL', count)
        races.extend(race_list)

    # step 4: statistics
    print('Generated %d logs for races out of %d candidates' % (count, total))
    print('-' * 79)

    return races

def find_show_toctou(graph, args):
    total = 0
    count = 0

    # step 0: controlled replay to get extra info on special syscalls
    predetect_replay(graph, args, [NodeBookmarkPath(), NodeBookmarkFile()])

    # step 1: find toctou races
    race_list = RaceList(graph, RaceToctou.find_races)
    total += len(race_list)
    count = output_races(race_list, args.path, 'TOCTOU', count)

    # step 2: statistics
    print('Generated %d logs for races of of %d candidates' % (count, total))
    print('-' * 79)

    return race_list

#############################################################################

class NodeBookmark:
    def need_bookmark(self, event, before=False, after=False):
        return False

    def upon_bookmark(self, event, exe, before=False, after=False):
        assert False

    def debug(self, event):
        pass

    def __init__(self):
        pass

syscalls.declare_syscall_sets({
        "ChangeRoot" : ["chroot"],
        "ChangeDir"  : ["chdir", "fchdir"],
        })

class NodeBookmarkPath(NodeBookmark):
    def need_bookmark(self, event, before=False, after=False):
        assert (before and not after) or (after and not before)

        return (before and event == event.proc.syscalls[0]) or \
               (after and event.nr in set().union(SYS_ChangeRoot, SYS_ChangeDir))

    def upon_bookmark(self, event, exe, before=False, after=False):
        assert (before and not after) or (after and not before)

        def get_real_pid(event, exe):
            return exe.pids[event.proc.pid]

        def get_proc_info(proc, pid, key, callback):
            return callback('%s/%d/%s' % (proc, pid, key))

        pid = get_real_pid(event, exe)
        proc = exe.chroot + '/proc'

        cwd = get_proc_info(proc, pid, 'cwd', os.readlink)
        root = get_proc_info(proc, pid, 'root', os.readlink)
        cwd = os.path.join('/', os.path.relpath(cwd, root))
        root = os.path.join('/', os.path.relpath(root, exe.chroot))

        path_info = dict()
        path_info['cwd'] = os.path.normpath(cwd)
        path_info['root'] = os.path.normpath(root)

        event.path_info = path_info
        event.proc.path_info = path_info

    def debug(self, event):
        if hasattr(event, 'path_info'):
            logging.debug('    %s' % event)
            for key, value in event.path_info.items():
                logging.debug('        %s : %s' % (key, value))

class NodeBookmarkFile(NodeBookmark):
    def need_bookmark(self, event, before=False, after=False):
        assert (before and not after) or (after and not before)

        syscalls_node_file = set().union(
            SYS_Check, SYS_FileCreate, SYS_LinkCreate, SYS_DirCreate,
            SYS_FileRemove, SYS_LinkRemove, SYS_DirRemove, SYS_FileWrite,
            SYS_FileRead, SYS_LinkWrite, SYS_LinkRead, SYS_DirWrite,
            SYS_DirRead
            )

        def consider_path(path):
            bad_prefix = ['/proc', '/dev', '/tmp/isolate']
            for prefix in bad_prefix:
                if path.startswith(prefix):
                    return False
            return True

        if before:
            if event.nr in syscalls_node_file:
                syscall = syscalls.event_to_syscall(event)
                path = syscalls.get_resource_path(syscall)
                return consider_path(path)

        return False

    def upon_bookmark(self, event, exe, before=False, after=False):
        assert (before and not after) or (after and not before)

        syscall = syscalls.event_to_syscall(event)
        if not syscall:
            return

        path = syscalls.get_resource_path(syscall)

        assert path, 'Path expected for syscall %s ?' % syscall
        assert before

        if hasattr(event, 'path_info'):
            file_info = event.path_info
        else:
            file_info = event.proc.path_info

        def set_event_file_info(path, prefix):
            file_info[prefix + 'path'] = os.path.normpath(path)
            if os.path.exists(exe.chroot + path):
                file_stat = os.stat(exe.chroot + path)
                for attr in dir(file_stat):
                    if attr.startswith('st_'):
                        file_info[prefix + attr] = getattr(file_stat, attr)

        path = os.path.join(file_info['cwd'], syscalls.get_resource_path(syscall))
        set_event_file_info(os.path.normpath(path), '')

        path = os.path.dirname(path)
        set_event_file_info(os.path.normpath(path), 'dir_')

        event.file_info = file_info

    def debug(self, event):
        if hasattr(event, 'file_info'):
            logging.debug('    %s' % event)
            for key, value in event.file_info.items():
                logging.debug('        %s : %s' % (key, value))

def predetect_replay(graph, args, queriers):

    bookmarks = list()

    for node in networkx.algorithms.dag.topological_sort(graph):
        if not node.is_a(scribe.EventSyscallExtra):
            continue

        node.queriers = list()

        for querier in queriers:
            if querier.need_bookmark(node, before=True):
                node.queriers.append(querier)
                bookmarks.append(dict({node.proc: NodeLoc(node, 'before')}))
            if querier.need_bookmark(node, after=True):
                node.queriers.append(querier)
                bookmarks.append(dict({node.proc: NodeLoc(node, 'after')}))

    out = args.path + '.pre.log'
    save_modify_log(graph, out, bookmarks, None, None, None)

    def predetect_bookmark_cb(**kargs):
        bookmarks = kargs['bookmarks']
        exe = kargs['exe']
        id = kargs['id']

        for nl in bookmarks[id].values():
            for querier in nl.node.queriers:
                querier.upon_bookmark(nl.node, exe,
                                      before=nl.before,
                                      after=nl.after)

        return True

    bookmark_cb = scribewrap.Callback(predetect_bookmark_cb, bookmarks=bookmarks)

    ret = scribewrap.scribe_replay(args, logfile=out, bookmark_cb=bookmark_cb)
    if not ret:
        raise execute.ExecuteError('predetect replay', ret)

    for bookmark in bookmarks:
        for nl in bookmark.values():
            for querier in nl.node.queriers:
                querier.debug(nl.node)


