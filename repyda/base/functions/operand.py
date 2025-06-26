from __future__ import annotations
from typing import Union, Optional, TYPE_CHECKING

import enum
import sys

import ida_ida
import idc
import ida_ua

from repyda.base.elements import Sequenceable


if TYPE_CHECKING:
    from repyda.base.functions import Instruction
    from repyda.base.elements import Addressable
    from repyda.base.types import Type


if 'sphinx' in sys.modules:
    o_void = 0
    o_reg = 1
    o_mem = 2
    o_phrase = 3
    o_displ = 4
    o_imm = 5
    o_far = 6
    o_near = 7
    o_idpspec0 = 8
    o_idpspec1 = 9
    o_idpspec2 = 10
    o_idpspec3 = 11
    o_idpspec4 = 12
    o_idpspec5 = 13
    _arm_condition_operand = -1
else:
    o_void = ida_ua.o_void
    o_reg = ida_ua.o_reg
    o_mem = ida_ua.o_mem
    o_phrase = ida_ua.o_phrase
    o_displ = ida_ua.o_displ
    o_imm = ida_ua.o_imm
    o_far = ida_ua.o_far
    o_near = ida_ua.o_near
    o_idpspec0 = ida_ua.o_idpspec0
    o_idpspec1 = ida_ua.o_idpspec1
    o_idpspec2 = ida_ua.o_idpspec2
    o_idpspec3 = ida_ua.o_idpspec3
    o_idpspec4 = ida_ua.o_idpspec4
    o_idpspec5 = ida_ua.o_idpspec5
    _arm_condition_operand = ida_ua.o_idpspec5 + 1


class OperandType(enum.Enum):
    NO_OPERAND                                      = o_void
    GENERAL_PURPOSE_REGISTER                        = o_reg
    DIRECT_MEMORY_ACCESS                            = o_mem
    REGISTERS_ADDITION_MEMORY_ACCESS                = o_phrase
    REGISTERS_AND_IMMEDIATE_ADDITION_MEMORY_ACCESS  = o_displ
    IMMEDIATE                                       = o_imm
    FAR_CODE_ACCESS                                 = o_far
    NEAR_CODE_ACCESS                                = o_near

    X86_TRACE_REGISTER              = o_idpspec0
    X86_DEBUG_REGISTER              = o_idpspec1
    X86_CONTROL_REGISTER            = o_idpspec2
    X86_FLOATING_POINT_REGISTER     = o_idpspec3
    X86_MMX_REGISTER                = o_idpspec4
    X86_XMM_REGISTER                = o_idpspec5

    ARM_REGISTER_LIST                   = o_idpspec1
    ARM_COPROCESSOR_REGISTER_LIST       = o_idpspec2
    ARM_COPROCESSOR_REGISTER            = o_idpspec3
    ARM_FLOATING_POINT_REGISTER_LIST    = o_idpspec4
    ARM_ARBITRARY_TEXT_STORED_OPERAND   = o_idpspec5
    ARM_CONDITION_OPERAND               = _arm_condition_operand

    PPC_SPECIAL_PURPOSE_REGISTER    = o_idpspec0
    PPC_TWO_FPR                     = o_idpspec1
    PPC_SH_ME_ME                    = o_idpspec2
    PPC_CRFIELD_X_REG               = o_idpspec3
    PPC_CRBIT_X_REG                 = o_idpspec4
    PPC_DEVICE_CONTROL_REGISTER     = o_idpspec5



class Operand(Sequenceable):
    def __init__(self, instruction: Instruction, idx: int):
        self.instruction = instruction
        self._idx = idx

    def __repr__(self) -> str:
        try:
            return f'Operand({self.register})'
        except RuntimeError:
            try:
                return f'Operand({self.object})'
            except:
                try:
                    return f'Operand({self.value})'
                except RuntimeError:
                    return 'Operand()'

    def __str__(self) -> str:
        return idc.print_operand(self.instruction.ea, self._idx)

    def __eq__(self, other) -> bool:
        if other is None:
            return False

        if not isinstance(other, Operand):
            raise NotImplementedError

        return self.instruction == other.instruction and self._idx == other._idx

    def __ne__(self, other) -> bool:
        if other is None:
            return True

        if not Instruction(other, Operand):
            raise NotImplementedError

        return self.instruction != other.instruction or self._idx != other.idx

    @property
    def next(self) -> Optional[Operand]:
        if self._idx + 1 >= self.instruction.count_operands:
            return None

        return Operand(self.instruction, self._idx + 1)

    @property
    def prev(self) -> Optional[Operand]:
        if self._idx == 0:
            return None

        return Operand(self.instruction, self._idx - 1)

    @property
    def operand_type(self) -> OperandType:
        return OperandType(idc.get_operand_type(self.instruction.ea, self._idx))

    def _get_pointed_integer(self) -> int:
        from repyda.base.data import Data
        from repyda.base.types import SizeT


        if self.operand_type != OperandType.DIRECT_MEMORY_ACCESS:
            raise RuntimeError(f'Unable to get memory object of non memory object operand {self.operand_type}')

        value = idc.get_operand_value(self.instruction.ea, self._idx)

        if ida_ida.inf_get_procname() == 'ARM':
            value = Data.type_value_at(type=SizeT, ea=value)

        return value

    @property
    def value(self) -> int:
        if self.operand_type == OperandType.DIRECT_MEMORY_ACCESS:
            return self._get_pointed_integer()

        if self.operand_type != OperandType.IMMEDIATE:
            raise RuntimeError(f'Unable to get value of non immediate operand {self.operand_type}')

        dtype = self.instruction._instruction.ops[self._idx].dtype
        value = idc.get_operand_value(self.instruction.ea, self._idx)

        if dtype == ida_ua.dt_byte:
            return value & 0xFF
        elif dtype == ida_ua.dt_word:
            return value & 0xFFFF
        elif dtype == ida_ua.dt_dword:
            return value & 0xFFFFFFFF
        elif dtype == ida_ua.dt_float:
            return value & 0xFFFFFFFF
        elif dtype == ida_ua.dt_double:
            return value & 0xFFFFFFFFFFFFFFFF
        elif dtype == ida_ua.dt_qword:
            return value & 0xFFFFFFFFFFFFFFFF

        raise RuntimeError('Should never reach here')

    @property
    def register(self) -> str:
        if self.operand_type not in (OperandType.GENERAL_PURPOSE_REGISTER,
                                     OperandType.REGISTERS_ADDITION_MEMORY_ACCESS,
                                     OperandType.REGISTERS_AND_IMMEDIATE_ADDITION_MEMORY_ACCESS,
                                     OperandType.X86_TRACE_REGISTER,
                                     OperandType.X86_DEBUG_REGISTER,
                                     OperandType.X86_FLOATING_POINT_REGISTER,
                                     OperandType.X86_MMX_REGISTER,
                                     OperandType.X86_MMX_REGISTER,
                                     OperandType.ARM_REGISTER_LIST,
                                     OperandType.ARM_COPROCESSOR_REGISTER_LIST,
                                     OperandType.ARM_COPROCESSOR_REGISTER,
                                     OperandType.ARM_FLOATING_POINT_REGISTER_LIST,
                                     OperandType.PPC_SPECIAL_PURPOSE_REGISTER,
                                     OperandType.PPC_TWO_FPR,
                                     OperandType.PPC_SH_ME_ME,
                                     OperandType.PPC_CRFIELD_X_REG,
                                     OperandType.PPC_CRBIT_X_REG,
                                     OperandType.PPC_DEVICE_CONTROL_REGISTER):
            raise RuntimeError(f'Unable to register of non immediate operand {self.operand_type}')

        return str(self)

    @property
    def object(self) -> Addressable:
        from repyda.base.elements import Addressable
        return Addressable.at(self._get_pointed_integer())