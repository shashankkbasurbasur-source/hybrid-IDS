import os


def read_sequence(file_path):
    with open(file_path, "r") as f:
        sequence = f.read().strip().split()
        return [int(x) for x in sequence]


def load_adfa_sequences(base_path):
    """
    Loads ADFA-LD sequences:
    - Training_Data_Master → normal
    - Attack_Data_Master → attacks (nested folders)
    - Validation_Data_Master → validation
    """

    training_path = os.path.join(base_path, "Training_Data_Master")
    attack_path = os.path.join(base_path, "Attack_Data_Master")
    validation_path = os.path.join(base_path, "Validation_Data_Master")

    normal_sequences = []
    attack_sequences = []
    validation_sequences = []

    # -----------------------
    # Load Training (Normal)
    # -----------------------
    for filename in os.listdir(training_path):
        file_path = os.path.join(training_path, filename)
        if os.path.isfile(file_path):
            normal_sequences.append(read_sequence(file_path))

    # -----------------------
    # Load Attack (Nested)
    # -----------------------
    for attack_folder in os.listdir(attack_path):
        folder_path = os.path.join(attack_path, attack_folder)

        if os.path.isdir(folder_path):
            for filename in os.listdir(folder_path):
                file_path = os.path.join(folder_path, filename)
                if os.path.isfile(file_path):
                    attack_sequences.append(read_sequence(file_path))

    # -----------------------
    # Load Validation
    # -----------------------
    for filename in os.listdir(validation_path):
        file_path = os.path.join(validation_path, filename)
        if os.path.isfile(file_path):
            validation_sequences.append(read_sequence(file_path))

    print(f"[✓] Loaded {len(normal_sequences)} normal sequences")
    print(f"[✓] Loaded {len(attack_sequences)} attack sequences")
    print(f"[✓] Loaded {len(validation_sequences)} validation sequences")

    return normal_sequences, attack_sequences, validation_sequences


if __name__ == "__main__":
    import os

    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    base_path = os.path.join(BASE_DIR, "datasets", "adfa-ld")

    load_adfa_sequences(base_path)
