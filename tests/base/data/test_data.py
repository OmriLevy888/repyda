from repyda_test import IDBTestCase
from pathlib import Path

# Data
# IDBStream


class TestRepydaData(IDBTestCase):
    IDB = Path(__file__).parent.parent.parent / 'notepad.exe.i64'

    def test_get_string_literal(self):
        from repyda import Data
        assert Data.exists_at(0x140032A76)
        assert Data.at(0x140032A76).name == 'word_140032A76'
