from pathlib import Path

import repyda


class TestRepydaFunction(IdbTestSuite):
    IDB = Path(__file__).parent.parent / 'ntdll.dll.i64'

    def test_function_from_ea(self):
        function = repyda.Function(ea=0x180021080)
        assert function.name == 'RtlAcquireSRWLockExclusive'
        assert function.size == 0x1a7
        assert function.ordinal == 0xf7

    def test_function_from_name(self):
        function = repyda.Function(name='RtlAcquireSRWLockExclusive')
        assert function.ea == 0x180021080

    def test_function_from_contained_ea(self):
        function = repyda.Function(ea=0x1800210ad)
        assert function.ea == 0x180021080

    def test_iter_functions(self):
        functions = list(repyda.Function.iter())
        assert len(functions) == 0xecd
        assert functions[0].name == 'RtlFindClearBits'

    def test_blocks(self):
        function = repyda.Function(ea=0x180021080)
        assert function.count_blocks == 0x18
        assert function.first_block.ea == 0x180021080

        successive_blocks = list(function.first_block.next)
        assert len(successive_blocks) == 2
        assert successive_blocks[0].ea == 0x180021097
        assert successive_blocks[1].ea == 0x18002109d
        preceding_blocks = list(function.first_block.prev)
        assert len(preceding_blocks) == 0

    def test_instructions(self):
        function = repyda.Function(ea=0x180021080)
        instructions = list(function.iter_instructions())
        assert function.count_instructions == 105
        assert function.count_instructions == len(instructions)

        inst = instructions[5]
        assert str(inst) == 'lock bts qword ptr [rcx], 0'
        assert inst.ea == 0x18002108f
        assert inst.size == 6
        assert inst.mnemonic == 'bts'
        assert inst.count_operands == 2
        operands = list(inst.iter_operands())
        assert str(operands[0]) == 'qword ptr [rcx]'
        assert str(operands[1]) == '0'

        first_op = operands[0]
        last_op = operands[1]
        assert first_op.prev is None
        assert first_op.next == last_op
        assert last_op.next is None
        assert last_op.prev == first_op

        assert str(inst.prev) == 'mov     [rsp+68h+arg_0], eax'
        assert str(inst.next) == 'jb      short loc_18002109D'

    def test_comment(self):
        function = repyda.Function(ea=0x180021080)
        assert not function.has_comment

        function.comment = 'hello there!'
        assert function.has_comment
        assert function.comment == 'hello there!'
        assert len(function.comment) == len('hello there!')
        assert function.repeatable_comment is None

        function.repeatable_comment = 'bye now!'
        assert function.comment != function.repeatable_comment
        assert len(function.repeatable_comment) == len('bye now!')
        assert function.comment != function.repeatable_comment

        function.comment = ''
        assert function.has_comment
        assert function.comment is None

        function.repeatable_comment = None
        assert not function.has_comment

        function.comment = 'foo'
        assert function.has_comment
        del function.comment
        assert not function.has_comment

    def test_rename(self):
        function = repyda.Function(ea=0x180021080)
        assert function.name == 'RtlAcquireSRWLockExclusive'
        assert not function.is_auto_name
        assert function.is_user_defined_name
        assert function.demangle_name == function.name

        function.name = '_Z4funcif'
        assert function.name == '_Z4funcif'
        assert function.demangle_name == 'func(int,float)'

        function.name = '_ZN3Foo3barEi'
        assert function.name == '_ZN3Foo3barEi'
        assert function.demangle_name == 'Foo::bar(int)'

        del function.name
        function.name == 'RtlAcquireSRWLockExclusive'

    def test_sequence(self):
        function = repyda.Function(ea=0x180021080)
        assert function.next.name == 'sub_180021228'
        assert function.prev.name == 'sub_180020DFC'

    def test_color(self):
        pass

    def test_type(self):
        function = repyda.Function(ea=0x18010B8EC)
        assert not function.has_user_defined_type
        guessed_type = '__int64 __fastcall(int, int, int, int, __int64, __int64)'
        assert function.guessed_type == repyda.Type.from_c(guessed_type)

        user_type = '__int64 (int, int, int, int, void *, int (*)(int))'
        function.type = repyda.Type.from_c(user_type)
        assert function.has_user_defined_type
        assert function.type == repyda.Type.from_c(user_type)
        assert function.type != function.guessed_type

        del function.type
        assert not function.has_user_defined_type

    def test_arguments(self):
        function = repyda.Function(ea=0x18010B8EC)
        assert function.count_args != len(list(function.iter_arguments()))
        assert function.count_args is None

        function.type = function.guessed_type
        assert function.count_args == 6
        assert all(True for arg in function.iter_arguments() if arg.name is None)

        del function.type

    def test_variables(self):
        pass

    def test_references(self):
        pass

    def test_referencing(self):
        pass

    def test_callers(self):
        pass

    def test_callees(self):
        pass