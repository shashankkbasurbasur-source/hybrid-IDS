from collections import Counter


def extract_bigrams(sequence: list) -> list:
    return [(sequence[i], sequence[i + 1]) for i in range(len(sequence) - 1)]


def build_bigram_vocabulary(sequences: list, top_k: int = 100) -> list:
    counter = Counter()
    for seq in sequences:
        counter.update(extract_bigrams(seq))
    return [bg for bg, _ in counter.most_common(top_k)]


def bigram_vector(sequence: list, vocabulary: list) -> list:
    counts = Counter(extract_bigrams(sequence))
    return [counts.get(bg, 0) for bg in vocabulary]