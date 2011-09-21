from mutator import Mutator

class Replace(Mutator):
    def __init__(self, replacements):
        self.replacements = replacements

    def on_event(self, event):
        if self.replacements.has_key(event):
            return self.replacements[event]
        return event
