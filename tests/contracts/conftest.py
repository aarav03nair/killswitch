import json
from pathlib import Path

import pytest

GOLDEN_FILE = Path(__file__).with_name("golden.json")


@pytest.fixture(scope="session")
def golden() -> dict[str, str]:
    """Pinned hashes (tests/contracts/golden.json). Regenerate only with a CONTRACTS_VERSION bump."""
    return json.loads(GOLDEN_FILE.read_text())
