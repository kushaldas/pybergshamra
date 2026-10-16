"""Guard the CI and release workflows against test-dependency drift.

``tests/test_pybergshamra.py`` imports ``pyuppsala`` at module level, so every
workflow step that installs pytest to run the suite must install pyuppsala as
well. The release workflow once installed only pytest and failed at collection
with ``ModuleNotFoundError: No module named 'pyuppsala'``; this test fails on
any install line that would repeat that.
"""

import re
from pathlib import Path

import pytest

WORKFLOWS = sorted((Path(__file__).resolve().parents[1] / ".github" / "workflows").glob("*.yml"))
INSTALLS_PYTEST = re.compile(r"\bpip install\b.*\bpytest\b")


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_every_pytest_install_also_installs_pyuppsala(workflow):
    offending = [
        f"{workflow.name}:{number}: {line.strip()}"
        for number, line in enumerate(workflow.read_text().splitlines(), start=1)
        if INSTALLS_PYTEST.search(line) and "pyuppsala" not in line
    ]
    assert offending == [], "pytest installed without pyuppsala:\n" + "\n".join(offending)
