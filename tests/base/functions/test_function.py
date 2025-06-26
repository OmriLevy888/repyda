from repyda_test import IDBTestCase
from pathlib import Path


# Block
# Function
# Instruction
# OperandType, Operand


class TestRepydaFunction(IDBTestCase):
    IDB = Path(__file__).parent.parent.parent / 'notepad.exe.i64'
