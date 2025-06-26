from repyda_test import IDBTestCase
from pathlib import Path

import time
import pytest

# ExportedSymbol
# IDA
# Endianness, IDB
# ImportedSymbol
# SegmentClass, SegmentPermissions, Segment


class TestRepydaIda(IDBTestCase):
    IDB = Path(__file__).parent.parent.parent / 'notepad.exe.i64'