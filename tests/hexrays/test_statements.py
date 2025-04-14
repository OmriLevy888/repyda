from pathlib import Path

import repyda


class TestStatements(IdbTestSuite):
    IDB = Path(__file__).parent.parent / 'ntdll.dll.i64'

    def test_statement(self):
        pass

    def test_block_statement(self):
        RtlQueryProcessLockInformation = repyda.DecompiledFunction(name='RtlQueryProcessLockInformation')
        assert RtlQueryProcessLockInformation.root.is_bound()
        assert RtlQueryProcessLockInformation.root == RtlQueryProcessLockInformation.match(repyda.BlockStatement())
        all_blocks = list(RtlQueryProcessLockInformation.match_all(repyda.BlockStatement()))
        assert len(all_blocks) == 13
        assert all_blocks[0] == RtlQueryProcessLockInformation.root
        assert all_blocks[-1] == RtlQueryProcessLockInformation.match(all_blocks[-1].clone_unbound())

    def test_expression_statement(self):
        RtlQueryProcessLockInformation = repyda.DecompiledFunction(name='RtlQueryProcessLockInformation')
        all_expression_statements = list(RtlQueryProcessLockInformation.match_all(repyda.ExpressionStatement()))
        assert len(all_expression_statements) == 44

    def test_assembly_block(self):
        pass

    def test_control_flow(self):
        pass

    def test_if(self):
        RtlQueryProcessLockInformation = repyda.DecompiledFunction(name='RtlQueryProcessLockInformation')
        all_if = list(RtlQueryProcessLockInformation.match_all(repyda.If()))
        assert len(all_if) == 8

        else_if = list(RtlQueryProcessLockInformation.match_all(repyda.If(elseif=repyda.If())))
        assert len(else_if) == 1

    def test_switch(self):
        pass

    def test_break(self):
        pass

    def test_continue(self):
        pass

    def test_return(self):
        RtlQueryProcessLockInformation = repyda.DecompiledFunction(name='RtlQueryProcessLockInformation')
        all_returns = list(RtlQueryProcessLockInformation.match_all(repyda.Return()))
        assert len(all_returns) == 2

    def test_goto(self):
        pass

    def test_loop(self):
        CsrCaptureMessageMultiUnicodeStringsInPlace = repyda.DecompiledFunction(name='CsrCaptureMessageMultiUnicodeStringsInPlace')
        all_loops = list(CsrCaptureMessageMultiUnicodeStringsInPlace.match_all(repyda.Loop()))
        assert len(all_loops) == 2

    def test_for_loop(self):
        pass

    def test_while_loop(self):
        RtlQueryProcessLockInformation = repyda.DecompiledFunction(name='RtlQueryProcessLockInformation')
        all_loops = list(RtlQueryProcessLockInformation.match_all(repyda.Loop(condition=repyda.Contains(repyda.VariableExpression(name='v6')))))
        assert len(all_loops) == 1

    def test_do_while_loop(self):
        AlpcFreeCompletionListMessage = repyda.DecompiledFunction(name='AlpcFreeCompletionListMessage')
        all_loops = list(AlpcFreeCompletionListMessage.match_all(repyda.DoWhileLoop()))
        assert len(all_loops) == 1