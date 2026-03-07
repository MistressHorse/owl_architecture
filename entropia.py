from collections import Counter
from math import log

class EntropyResult:
    def __init__(self, skip, entropy):
        self.skip = skip
        self.entropy = entropy

def calculate_entropy(line):
    counts = Counter(line)
    freq = ((i/len(line)) for i in counts.values())
    ent = - sum(f*log(f,2) for f in freq)
    if ent > 4.15:
        return EntropyResult(skip=False, entropy=ent)
    return EntropyResult(skip=True, entropy=ent)