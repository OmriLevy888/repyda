from typing import Optional

from . import Expression
from .. import bound_value
from repyda.base.types import Type

import ida_hexrays
import idc
import ida_name

from repyda.base.elements.addressable import Addressable


class Literal(Expression):
    pass


class Number(Literal):
    HEXRAYS_TYPE = ida_hexrays.cot_num

    def __init__(self, value: int = None, *, size_bytes: int = None, **kwargs):
        super().__init__(**kwargs)
        self._value = value
        self._size_bytes = size_bytes

    @property
    @bound_value
    def value(self) -> int:
        mask = (1 << (self.size_bytes * 8)) - 1
        return self._hexrays_item.n.value(self._hexrays_item.type) & mask

    @property
    @bound_value
    def size_bytes(self) -> int:
        return self._hexrays_item.n.nf.org_nbytes[0].encode()[0]

    def make_citem_t(self) -> ida_hexrays.citem_t:
        return ida_hexrays.make_num(self.value)


class FloatLiteral(Literal):
    HEXRAYS_TYPE = ida_hexrays.cot_fnum

    def __init__(self, value: float = None, *, size_bytes: int = None, **kwargs):
        super().__init__(**kwargs)
        self._value = value
        self._size_bytes = size_bytes

    @property
    @bound_value
    def value(self) -> float:
        return self._hexrays_item.fpc.fnum

    @property
    @bound_value
    def size_bytes(self) -> int:
        return self._hexrays_item.fpc.nbytes

    def make_citem_t(self) -> ida_hexrays.citem_t:
        #TODO: implement make_citem_t
        raise NotImplementedError


class String(Literal):
    HEXRAYS_TYPE = ida_hexrays.cot_str

    def __init__(self, value: str = None, **kwargs):
        super().__init__(**kwargs)
        self._value = value

    @property
    @bound_value
    def value(self) -> str:
        return self._hexrays_item.string

    def make_citem_t(self) -> ida_hexrays.citem_t:
        #TODO: implement make_citem_t
        raise NotImplementedError


class ObjectAddress(Literal):
    HEXRAYS_TYPE = ida_hexrays.cot_obj

    def __init__(self,
                 ea: int = None,
                 *,
                 name: str = None,
                 object: Addressable = None,
                 **kwargs):
        super().__init__(**kwargs)
        self._ea = ea
        self._name = name
        self._object = object

    @property
    @bound_value
    def type(self) -> Type:
        return self.object.type or self.object.guessed_type

    @property
    @bound_value
    def ea(self) -> int:
        return self._hexrays_item.obj_ea

    @property
    @bound_value
    def name(self) -> Optional[str]:
        name = idc.get_name(self.ea)
        if name is None or len(name) == 0:
            return None
        return name

    @property
    @bound_value
    def object(self) -> Optional[Addressable]:
        try:
            return Addressable.at(self.ea)
        except ValueError:
            return None

    def make_citem_t(self) -> ida_hexrays.citem_t:
        expr = ida_hexrays.cexpr_t()
        expr.op = ida_hexrays.cot_obj

        if self.name is not None:
            ea = ida_name.get_name_ea(idc.BADADDR, self.name)
        else:
            ea = self.ea

        expr.obj_ea = ea
        return expr