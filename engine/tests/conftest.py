"""Suite hermeticity: restore cwd + environment around every test.

No test may depend on, or mutate, the ambient working directory or
process environment (post-freeze fix item 1: order/shared-state
dependence). File-writing tests additionally use isolated tmp_path
copies, never the source tree.
"""
import os

import pytest


@pytest.fixture(autouse=True)
def _restore_cwd_env():
    cwd = os.getcwd()
    env = dict(os.environ)
    yield
    os.chdir(cwd)
    os.environ.clear()
    os.environ.update(env)
