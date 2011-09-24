import mmap
import scribe
import mutator

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

    events = graph

    if bookmarks is not None:
        for bmark in bookmarks:
            events |= mutator.Bookmark(bmark.values())

    if injects is not None:
        relax = dict()
        for pdict in injects.values():
            for (nl, actions) in pdict.items():
                flags = relax.get(nl, 0)
                for action in actions:
                    flags |= action.arg2
                relax[nl] = flags

        events |= mutator.Relax(relax)

    if cutoff is not None:
        events |= mutator.TruncateQueue(cutoff.values())

    if replace is not None:
        for (old,new) in replace.items():
            new.proc = old.proc
        events |= mutator.Replace(replace)

    events |= mutator.AdjustResources() \
           |  mutator.InsertEoqEvents() \
           |  mutator.InsertPidEvents() \
           |  mutator.ToRawEvents()

    return events

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

def save_session(logfile, events):
    """Save modified scribe log to logfile"""
    try:
        f = open(logfile, 'w')
    except:
        print('Cannot open log file %s' % logfile)
        exit(1)

    for e in events:
        f.write(e.encode())

    f.close()
