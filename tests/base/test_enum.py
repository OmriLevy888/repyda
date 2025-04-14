from pathlib import Path

import pytest

import repyda


class TestRepydaType(IdbTestSuite):
    IDB = Path(__file__).parent.parent / 'ntdll.dll.i64'

    @pytest.fixture(scope='function')
    def case_enum(self):
        enum = repyda.Enum.create_empty_enum()
        yield enum
        enum.delete()

    def test_idbiterable(self):
        assert len(list(repyda.Enum.iter())) == 0

        COUNT_ENUMS = 10
        for _ in range(COUNT_ENUMS):
            repyda.Enum.create_empty_enum()

        assert(len(list(repyda.Enum.iter()))) == COUNT_ENUMS

        for enum in repyda.Enum.iter():
            enum.delete()

        assert(len(list(repyda.Enum.iter()))) == 0

    def test_nameable(self, case_enum):
        assert case_enum.name.split('_')[1].isdigit()
        case_enum.name = 'foo'
        assert case_enum.name == 'foo'

    def test_commentable(self, case_enum):
        assert case_enum.comment is None
        case_enum.comment = 'quack'
        assert case_enum.comment == 'quack'
        del case_enum.comment
        assert case_enum.comment is None

        assert case_enum.repeatable_comment is None
        case_enum.repeatable_comment = 'bwak'
        assert case_enum.repeatable_comment == 'bwak'
        del case_enum.repeatable_comment
        assert case_enum.repeatable_comment is None

    def test_member_idbiterable(self):
        assert len(list(repyda.EnumMember.iter())) == 0

        first_enum = repyda.Enum.create_empty_enum()
        for i in range(3):
            first_enum.add_member(f'first_enum_{i}')

        assert len(list(repyda.EnumMember.iter())) == 3

        second_enum = repyda.Enum.create_empty_enum()
        for i in range(2):
            second_enum.add_member(f'second_enum_{i}')

        assert len(list(repyda.EnumMember.iter())) == 5

        first_enum.delete()
        assert len(list(repyda.EnumMember.iter())) == 2
        second_enum.delete()
        assert len(list(repyda.EnumMember.iter())) == 0

    def test_member_nameable(self, case_enum):
        member = case_enum.add_member('enum_member')
        assert member.name == 'enum_member'
        member.name = 'quack'
        assert member.name == 'quack'

    def test_member_commentable(self, case_enum):
        member = case_enum.add_member('enum_member')

        assert member.comment is None
        member.comment = 'test'
        assert member.comment == 'test'
        del member.comment
        assert member.comment is None

        assert member.repeatable_comment is None
        member.repeatable_comment = 'test'
        assert member.repeatable_comment == 'test'
        del member.repeatable_comment
        assert member.repeatable_comment is None

    def test_member_referenceable(self):
        pytest.skip('Reference for enums has not been implemented yet')

    def test_width(self, case_enum):
        assert case_enum.width == 0
        case_enum.width = 8
        assert case_enum.width == 8

        with pytest.raises(ValueError):
            case_enum.width = 6

        with pytest.raises(ValueError):
            case_enum.width = -1

        case_enum.width = 0
        assert case_enum.width == 0

    def test_bitfield(self, case_enum):
        assert not case_enum.is_bitfield
        case_enum.is_bitfield = True
        assert case_enum.is_bitfield
        case_enum.is_bitfield = False
        assert not case_enum.is_bitfield