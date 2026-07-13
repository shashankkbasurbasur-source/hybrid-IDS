import pickle
from pathlib import Path


class SyscallModelRegistry:
    def __init__(self, base_path: str = "models"):
        base_path = Path(base_path)
        try:
            with open(base_path / "hids_syscall_model.pkl", "rb") as f:
                self.model = pickle.load(f)
            with open(base_path / "hids_syscall_vocab.pkl", "rb") as f:
                self.vocab = pickle.load(f)
            print("[✓] HIDS syscall model + vocabulary loaded successfully")
        except Exception as e:
            raise RuntimeError(f"Failed to load HIDS syscall model: {e}")


_registry = None


def get_registry(base_path: str = "models") -> SyscallModelRegistry:
    global _registry
    if _registry is None:
        _registry = SyscallModelRegistry(base_path=base_path)
    return _registry