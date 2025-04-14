from __future__ import annotations
from typing import Optional, Generator, Tuple, Union

import ida_typeinf
import idc

from .basic_types import Type


class Argument:
    def __init__(self, function_type: FunctionType, idx: int):
        self._function_type = function_type
        self.idx = idx

    def __str__(self) -> str:
        name = self.name or '<NONAME>'
        return f'{self.type} {name}'

    @property
    def name(self) -> Optional[str]:
        return self._function_type._get_func_details()[self.idx].name

    @name.setter
    def name(self, value: str):
        new_details = self._function_type._get_func_details()
        new_details[self.idx].name = value
        new_tinfo = ida_typeinf.tinfo_t()
        if not new_tinfo.create_func(new_details):
            raise RuntimeError(f'Failed to rename argument {self.name} to {value}')

        self._function_type._tinfo = new_tinfo

    @property
    def type(self) -> Type:
        return Type.from_tinfo(self._function_type._get_func_details()[self.idx].type)

    @type.setter
    def type(self, value: Union[Type, str]):
        if isinstance(value, str):
            value = Type.from_c(value)

        new_details = self._function_type._get_func_details()
        new_details[self.idx].type = value.get_tinfo()
        new_tinfo = ida_typeinf.tinfo_t()
        if not new_tinfo.create_func(new_details):
            raise RuntimeError(f'Failed to set argument type {value}')

        self._function_type._tinfo = new_tinfo


class FunctionType(Type):
    @staticmethod
    def is_function_type(declaration: str) -> bool:
        declaration = Type._fix_declaration_padding(declaration)
        return declaration.endswith(');')

    @staticmethod
    def make_function_type_ida_parseable(declaration: str) -> Optional[str]:
        CALLING_CONVENTIONS = {'__usercall',
                               '__stdcall',
                               '__fastcall',
                               '__thiscall',
                               '__userpurge',
                               '__cdecl',
                               '__pascal',
                               '__gloang'}

        declaration = Type._fix_declaration_padding(declaration)

        if declaration.count(')') != declaration.count('(') \
            or declaration.count('(') == 0 \
            or declaration.rstrip(' \t\r\n;')[-1] != ')':
            return None

        close_params_index = declaration.rfind(')')
        fixed_declaration = declaration[close_params_index + 1:]
        found_open_paren = False
        found_close_paren = False
        should_read_string = False
        read_string = ''

        for idx in range(close_params_index, -1, -1):
            if should_read_string:
                if declaration[idx].isspace() or idx == 0:
                    should_read_string = False
                    if read_string in CALLING_CONVENTIONS:
                        convention = f'({read_string})'
                    else:
                        convention = f'{read_string} (__stdcall)'

                        if idx == 0:
                            convention = declaration[idx] + convention

                    without_pre_whitespace = fixed_declaration.lstrip()
                    count_whitespace = len(fixed_declaration) - len(without_pre_whitespace)
                    whitespaces = fixed_declaration[:count_whitespace]
                    fixed_declaration = whitespaces + convention + without_pre_whitespace

                    if idx == 0:
                        continue
                else:
                    read_string = declaration[idx] + read_string
                    continue

            elif found_close_paren:
                if declaration[idx] == '(':
                    found_close_paren = False
            elif declaration[idx] == '(':
                found_open_paren = True
            elif found_open_paren and not declaration[idx].isspace():
                found_open_paren = False

                if declaration[idx] == ')':
                    found_close_paren = True
                else:
                    should_read_string = True
                    read_string = declaration[idx]
                    continue

            fixed_declaration = declaration[idx] + fixed_declaration

        return fixed_declaration

    def get_type_details(self) -> Tuple[str, bytes, bytes]:
        declaration = FunctionType.make_function_type_ida_parseable(str(self))
        details = idc.parse_decl(declaration, idc.PT_SILENT)
        if details is None:
            raise RuntimeError(f'Failed to parse {declaration}, this is a bug!')

        return details

    def _get_func_details(self) -> ida_typeinf.tinfo_t:
        function_type_data = ida_typeinf.func_type_data_t()
        if not self._tinfo.get_func_details(function_type_data):
            raise RuntimeError(f'Failed to get function details for {self.name}')

        return function_type_data

    def get_argument(self, name: Optional[str] = None, *, position: Optional[int] = None) -> Argument:
        if name is None and position is None:
            raise ValueError('Must pass either name or position')

        for idx, arg in enumerate(self.iter_arguments()):
            if idx == position or name == arg.name:
                return arg

        raise ValueError('No such argument')

    def add_argument(self, name: str, type: Union[Type, str]):
        if isinstance(type, str):
            type = Type.from_c(type)

        funcarg = ida_typeinf.funcarg_t()
        funcarg.name = name
        funcarg.type = type.get_tinfo()

        new_details = self._get_func_details()
        if not new_details.add_unique(funcarg):
            raise RuntimeError(f'Failed to add argument {type} {name}')

        new_tinfo = ida_typeinf.tinfo_t()
        if not new_tinfo.create_func(new_details):
            raise RuntimeError(f'Failed to add argument {type} {name}')

        self._tinfo = new_tinfo

    @property
    def count_args(self) -> int:
        return self._tinfo.get_nargs()

    @property
    def return_type(self) -> Type:
        function_type_data = ida_typeinf.func_type_data_t()
        if not self._tinfo.get_func_details(function_type_data):
            raise RuntimeError(f'Failed to get function details for {self.name}')

        rettype = ida_typeinf.tinfo_t(function_type_data.rettype)
        return Type.from_tinfo(rettype)

    def iter_arguments(self) -> Generator[Argument, None, None]:
        for idx in range(self.count_args):
            yield Argument(self, idx)