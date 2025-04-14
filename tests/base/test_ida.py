from pathlib import Path

import repyda
import time
import pytest


class TestRepydaIda(IdbTestSuite):
    IDB = Path(__file__).parent.parent / 'ntdll.dll.i64'

    def test_exception_exec_sync(self):
        throws_exception = lambda: 1 / 0
        with pytest.raises(ZeroDivisionError):
            repyda.IDA.exec_sync(throws_exception)

    def test_exec_sync(self):
        excepcted_ret = time.time()
        returns_value = lambda: excepcted_ret
        assert excepcted_ret == repyda.IDA.exec_sync(returns_value)