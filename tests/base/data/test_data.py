from repyda_test import IDBTestCase
from pathlib import Path

# Data
# IDBStream


class TestRepydaData(IDBTestCase):
    IDB = Path(__file__).parent.parent.parent / 'notepad.exe.i64'
