from __future__ import annotations
from typing import Optional, Union, Any
from pathlib import PurePosixPath
import enum

from abc import ABC, abstractmethod

import ida_ida
import idc
import ida_dirtree


class TreeType(enum.Enum):
    Breakpoints         = ida_dirtree.DIRTREE_BPTS
    Functions           = ida_dirtree.DIRTREE_FUNCS
    Bookmarks           = ida_dirtree.DIRTREE_IDAPLACE_BOOKMARKS
    Imports             = ida_dirtree.DIRTREE_IMPORTS
    Types               = ida_dirtree.DIRTREE_LOCAL_TYPES
    TypesBookmarks      = ida_dirtree.DIRTREE_LTYPES_BOOKMARKS
    Names               = ida_dirtree.DIRTREE_NAMES


class NamePathIterator:
    def __init__(self, path: NamePath):
        self.path = path
        self._iterator = ida_dirtree.dirtree_iterator_t()
        if not self.path._tree.findfirst(self._iterator, str(PurePosixPath(path.path) / '*')):
            self._iterator = None

    def __next__(self) -> NamePath:
        if self._iterator is None:
            raise StopIteration

        value = self._iterator
        tree = self.path._tree
        name = tree.get_abspath(value.cursor, 0)

        if not tree.findnext(self._iterator):
            self._iterator = None

        return NamePath(PurePosixPath(name), self.path.type)


class NamePath:
    def __init__(self,
                 path: Optional[Union[PurePosixPath, str]] = None,
                 type: Optional[TreeType] = TreeType.Names,
                 *,
                 tree: Optional[ida_dirtree.dirtree_t] = None):
        if tree is None:
            tree = ida_dirtree.get_std_dirtree(type.value)

            if tree is None:
                raise RuntimeError(f'Failed to open dirtree {TreeType=}')

        if isinstance(path, str):
            path = PurePosixPath(path)

        self._path = path or PurePosixPath('/')
        self._tree = tree

    def is_directory(self) -> bool:
        return self._tree.isdir(str(self._path))

    def is_file(self) -> bool:
        return self._tree.isfile(str(self._path))

    def exists(self) -> bool:
        return self.is_directory() or self.is_file()

    def mkdir(self):
        if self.exists():
            raise ValueError(f'{self} already eixsts')

        self._tree.mkdir(str(self))

    def rmdir(self):
        if not self.exists():
            raise ValueError(f'{self} does not exist')
        elif not self.is_directory():
            raise ValueError(f'{self} is not a directory')

        if self._tree.rmdir(str(self)) != 0:
            raise ValueError(f'Trying to delete non emptry directory {self}')

    def __str__(self) -> str:
        return str(self.path)

    @property
    def name(self) -> str:
        return self.path.name

    @property
    def path(self) -> PurePosixPath:
        return self._path

    @property
    def type(self) -> TreeType:
        match self._tree.get_id():
            case '$ dirtree/bpts':
                return TreeType.Breakpoints
            case '$ dirtree/funcs':
                return TreeType.Functions
            case '$ dirtree/bookmarks_idaplace_t':
                return TreeType.Bookmarks
            case '$ dirtree/imports':
                return TreeType.Imports
            case '$ dirtree/tinfos':
                return TreeType.Types
            case '$ dirtree/bookmarks_tiplace_t':
                return TreeType.TypesBookmarksy
            case '$ dirtree/names':
                return TreeType.Names

    def __iter__(self):
        if not self.is_directory():
            raise RuntimeError('Cannot iterate nonexistent directory')

        return NamePathIterator(self)

    def __repr__(self) -> str:
        return f'NamePath({self.path}, {self.type})'


class Nameable(ABC):
    def __eq__(self, other: Any) -> bool:
        if other is None:
            return False
        elif not isinstance(other, Nameable):
            return NotImplemented

        return self.name == other.name and self.__class__ is other.__class__

    def __ne__(self, other: Any) -> bool:
        if other is None:
            return True
        elif not isinstance(other, Nameable):
            return NotImplemented

        return self.name != other.name

    @property
    @abstractmethod
    def name(self) -> str:
        raise NotImplementedError

    @name.setter
    def name(self, name: Optional[str]):
        raise NotImplementedError

    @name.deleter
    def name(self):
        raise NotImplementedError

    @property
    def demangle_name(self) -> str:
        demangled = idc.demangle_name(self.name, ida_ida.inf_get_short_demnames())
        return demangled or self.name

    @property
    @abstractmethod
    def is_auto_name(self) -> bool:
        raise NotImplementedError

    @property
    @abstractmethod
    def is_user_defined_name(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def _default_tree_type(self) -> TreeType:
        raise NotImplementedError

    @abstractmethod
    def _is_valid_tree_type(self, type: TreeType) -> bool:
        raise NotImplementedError

    def get_directory(self, *, tree: Optional[TreeType] = None) -> NamePath:
        if tree is None:
            tree = self._default_tree_type()
        elif not self._is_valid_tree_type(tree):
            raise ValueError(f'Invalid type {tree}')

        root = NamePath(type=tree)
        def traverse_dir(direcotry: NamePath, name: str):
            directories = list()
            for entry in direcotry:
                if entry.is_directory():
                    directories.append(entry)
                elif entry.name.replace('::', '__') == name:
                    return direcotry

            for found_directory in directories:
                found = traverse_dir(found_directory, name)
                if found is not None:
                    return found

        return traverse_dir(root, self.name)

    def _get_destination_directory(self,
                                   directory: Union[NamePath, PurePosixPath, str],
                                   tree: Optional[TreeType] = None) -> NamePath:
        if isinstance(directory, (PurePosixPath, str)):
            if tree is None:
                tree = self._default_tree_type()

            if not self._is_valid_tree_type(tree):
                raise ValueError(f'Invalid type {tree}')

            directory = NamePath(path=directory, type=tree)

        if directory.is_file():
            raise ValueError(f'Trying to move under file {directory}')

        return directory

    def move_to_path(self,
                     directory: Union[NamePath, PurePosixPath, str],
                     *,
                     tree: Optional[TreeType] = None):
        directory = self._get_destination_directory(directory, tree)
        if not directory.exists():
            directory.mkdir()

        current_path = self.get_path(tree=directory.type)
        current_path._tree.rename(str(current_path), str(directory.path / current_path.name))

    def make_link_in(self,
                     directory: Union[NamePath, PurePosixPath, str],
                     *,
                     tree: Optional[TreeType] = None):
        directory = self._get_destination_directory(directory, tree)
        if not directory.exists():
            directory.mkdir()

        current_path = self.get_path(tree=directory.type)
        current_path._tree.link(str(directory.path / current_path.name).replace('__', '::'))

    def get_path(self, *, tree: Optional[TreeType] = None) -> NamePath:
        direcotry = self.get_directory(tree=tree)
        return NamePath(direcotry.path / self.name, direcotry.type)