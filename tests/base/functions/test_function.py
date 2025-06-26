from repyda_test import IDBTestCase
from pathlib import Path


# Block
# Function
# Instruction
# OperandType, Operand


class TestRepydaFunction(IDBTestCase):
    IDB = Path(__file__).parent.parent.parent / 'notepad.exe.i64'
    
    def test_get_function(self):
        from repyda import Function
        function = Function(name='ProtectionPolicyManager_GetEnforcementLevel')
        assert function is not None
        assert function.ea == 0x1400268E0
