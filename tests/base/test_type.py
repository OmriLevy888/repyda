from pathlib import Path

import repyda


class TestRepydaType(IdbTestSuite):
    IDB = Path(__file__).parent.parent / 'ntdll.dll.i64'

    def test_builtin_types(self):
        assert repyda.Void == repyda.Void
        assert repyda.SignedInt8.size == repyda.UnsignedInt8.size
        assert repyda.SignedInt8.size != repyda.SignedInt16.size
        assert repyda.SignedInt8 != repyda.UnsignedInt8
        assert repyda.SizeT.size == repyda.OffT.size
        assert not repyda.SizeT.signed
        assert repyda.OffT.signed

        assert isinstance(repyda.Void, repyda.Type)
        assert not isinstance(repyda.Void, repyda.Scalar)
        # NOTE: this fails because rpyc does not handle this correctly(?)
        # assert isinstance(repyda.Bool, repyda.Type)
        assert isinstance(repyda.Bool, repyda.Scalar)

    def test_type_modifiers(self):
        pass

    def test_pointer_type(self):
        assert repyda.Pointer(repyda.Void) == 'void *'
        assert repyda.Pointer(repyda.Void).size == repyda.Pointer(repyda.Float).size
        # NOTE: there is a known bug where inf functions return bad values when the ida starts
        # assert repyda.Pointer(repyda.Void).size == repyda.SizeT.size

    def test_array_type(self):
        assert repyda.Array(repyda.Bool, 5) == 'bool[5]'
        assert repyda.Array(repyda.Bool, 8).size == repyda.Array(repyda.UnsignedInt32, 2).size
        assert repyda.Array(repyda.Bool, 8).size != repyda.Array(repyda.Float, 1).size
        assert repyda.Array(repyda.Bool, 8).count_elements == 8

    def test_parse_c_definition(self):
        assert repyda.SignedInt32 == 'int'
        assert repyda.SignedInt32 == 'int32_t'
        assert repyda.SignedInt32 == 'signed __int32'
        assert repyda.SignedInt32 == 'signed int32_t'
        assert repyda.Void == 'void'
        assert repyda.Void == 'void;'
        assert repyda.Array(repyda.Bool, 5) == 'bool [5]'
        assert repyda.Array(repyda.Bool, 5) == 'bool[5]'
        assert repyda.Array(repyda.Bool, 5) == 'bool[0x5]'

    def test_function_type(self):
        # test function creation
        # access return type
        # access calling convention
        pass

    def test_function_arguments(self):
        # access arguments info
        pass

    def test_function_modification(self):
        # change arguments
        # change return type
        pass

    def test_struct_access(self):
        # create struct
        # iter struct
        # delete struct
        pass

    def test_struct_from_c(self):
        pass

    def test_struct_members(self):
        # iter members
        pass

    def test_modify_struct(self):
        # add members
        # remove members
        pass

    def test_modify_members(self):
        # change member names
        # change member types
        pass

    def test_struct_modifiers(self):
        # const, volatile...
        pass

    def test_union(self):
        pass

    def test_xref(self):
        pass