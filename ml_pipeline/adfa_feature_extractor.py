import numpy as np
from collections import Counter


def extract_bigrams(sequence):
    return [(sequence[i], sequence[i+1]) for i in range(len(sequence)-1)]


def build_bigram_vocabulary(sequences, top_k=100):
    """
    Build vocabulary of most common bigrams from normal data.
    """
    bigram_counter = Counter()

    for seq in sequences:
        bigrams = extract_bigrams(seq)
        bigram_counter.update(bigrams)

    most_common = bigram_counter.most_common(top_k)
    vocabulary = [bg for bg, _ in most_common]

    return vocabulary


def extract_bigram_features(sequence, vocabulary):
    """
    Convert sequence into bigram frequency vector.
    """
    bigrams = extract_bigrams(sequence)
    counter = Counter(bigrams)

    feature_vector = []
    for bg in vocabulary:
        feature_vector.append(counter.get(bg, 0))

    return feature_vector


def build_feature_matrix(sequences, vocabulary):
    features = []
    for seq in sequences:
        features.append(extract_bigram_features(seq, vocabulary))

    return np.array(features)


    
