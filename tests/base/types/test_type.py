from repyda_test import IDBTestCase
from pathlib import Path

# CompoundTypeMember, CompoundType, Union, Struct
# EnumMember, Enum
# get_handling_class_for_tinfo, TypeMeta, Type, CommentableType, NameableType, DeleteableType, Pointer, Array, Scalar, TypeDefinition
# Argument, FunctionType


class TestRepydaType(IDBTestCase):
    IDB = Path(__file__).parent.parent.parent / 'notepad.exe.i64'
