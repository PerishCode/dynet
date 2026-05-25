from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


RUNTIME_SCRIPT = Path(__file__).resolve().parents[2] / "private_runtime.py"
VM_PATH = RUNTIME_SCRIPT.parent


def load_runtime_script():
    sys.path.insert(0, str(VM_PATH))
    spec = importlib.util.spec_from_file_location("_dynet_vm_private_runtime_script", RUNTIME_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("private_runtime.py module spec could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_script = load_runtime_script()
build_parser = _script.build_parser
