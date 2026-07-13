import os
import sys
import pickle
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# Add project root to Python path
sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))
        )
    )
)

from backend.hids.features.syscall_bigram_feature import (
    build_bigram_vocabulary,
    bigram_vector,
)


def read_sequence(file_path):
    """
    Read one ADFA-LD syscall trace.
    Returns a list of syscall IDs (integers).
    """
    with open(file_path, "r") as f:
        return [int(x) for x in f.read().strip().split()]


def load_adfa_sequences(base_path):
    """
    Load all normal and attack syscall traces.
    """

    training_path = os.path.join(base_path, "Training_Data_Master")
    attack_path = os.path.join(base_path, "Attack_Data_Master")

    normal = []

    for fn in os.listdir(training_path):
        fp = os.path.join(training_path, fn)

        if os.path.isfile(fp):
            normal.append(read_sequence(fp))

    attack = []

    for attack_type in os.listdir(attack_path):

        folder = os.path.join(attack_path, attack_type)

        if not os.path.isdir(folder):
            continue

        for fn in os.listdir(folder):

            fp = os.path.join(folder, fn)

            if os.path.isfile(fp):
                attack.append(read_sequence(fp))

    return normal, attack


def main(adfa_dir):

    print("[*] Loading ADFA-LD dataset...")

    normal_sequences, attack_sequences = load_adfa_sequences(adfa_dir)

    print(f"[*] Normal samples : {len(normal_sequences)}")
    print(f"[*] Attack samples : {len(attack_sequences)}")

    print("[*] Building syscall bigram vocabulary...")

    vocab = build_bigram_vocabulary(
        normal_sequences,
        top_k=100,
    )

    print(f"[*] Vocabulary size : {len(vocab)}")

    X = np.array(
        [
            bigram_vector(seq, vocab)
            for seq in (normal_sequences + attack_sequences)
        ]
    )

    y = np.array(
        [0] * len(normal_sequences)
        +
        [1] * len(attack_sequences)
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.30,
        random_state=42,
        stratify=y,
    )

    print("[*] Training Random Forest...")

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    print("\nClassification Report\n")
    print(classification_report(y_test, predictions))

    os.makedirs("models", exist_ok=True)

    with open("models/hids_syscall_model.pkl", "wb") as f:
        pickle.dump(model, f)

    with open("models/hids_syscall_vocab.pkl", "wb") as f:
        pickle.dump(vocab, f)

    print("\n[✓] Saved:")
    print("models/hids_syscall_model.pkl")
    print("models/hids_syscall_vocab.pkl")


if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage:\n"
            "python3 research/adfa_ld/train_syscall_model.py <adfa_ld_directory>"
        )
        sys.exit(1)

    main(sys.argv[1])