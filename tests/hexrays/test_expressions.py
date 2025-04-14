from pathlib import Path

import repyda


class TestExpressions(IdbTestSuite):
    IDB = Path(__file__).parent.parent / 'ntdll.dll.i64'

    def test_assignment(self):
        RtlQueryProcessLockInformation = repyda.DecompiledFunction(name='RtlQueryProcessLockInformation')
        all_matches = list(
            RtlQueryProcessLockInformation.match_all(
                repyda.Assignment(
                    left=repyda.VariableExpression(index=lambda index: index <= 3))))
        assert len(all_matches) == 2

    def test_call(self):
        RtlQueryProcessLockInformation = repyda.DecompiledFunction(name='RtlQueryProcessLockInformation')
        all_matches = list(
            RtlQueryProcessLockInformation.match_all(
                repyda.Call(
                    arguments=repyda.Contains(repyda.VariableExpression(name='a1')))))
        assert len(all_matches) == 3

    def test_object(self):
        RtlQueryProcessLockInformation = repyda.DecompiledFunction(name='RtlQueryProcessLockInformation')
        all_matches = list(RtlQueryProcessLockInformation.match_all(repyda.ObjectAddress(name=lambda name: 'debug' in name.lower())))
        assert len(all_matches) == 3