.. _general-architecture:

Repyda Project architecture
##########################

.. module:: repyda

.. contents::

Module architecture
===================

Repyda is meant to be used with a single import

.. code-block:: pycon

    >>> import repyda
    >>> # or alternatively
    >>> from repyda import *

Therer are no name colisions inside the packge and importing Repyda this way
will give you access to all of its features.

Internally repyda is separated into base and hexrays where the first handles
most functionality (disassembly, data, idb...) and the latter handles the
decompiler functionality. If you want, you can import them separately:

.. code-block:: pycon

    >>> from repyda import base
    >>> from repyda import hexrays

Common names
============

The following are rules followed by the packaged to keep the names consistent.

- Addresses are called ``ea`` (as per IDA)
- If a function/property either take or return a direct IDA type, they use the
  actual IDA name i.e. :meth:`HexraysItem.make_citem_t`.

Inheritence
===========

Repyda uses inheritence to denote relation between different objects. This comes
into play in two places: elements and :class:`HexraysItem`.

Elements
--------

Elements are repyda' way to group functionality to different objects in IDA.
These can be thought of as interfaces.

- :class:`Addressable` - has an ea and a color
- :class:`Commentable` - can have a comment or a repeatable comment
- :class:`IDBIterable` - use `class.iter()` to get all instances of this object
- :class:`Nameable` - can be named, also adds functionality for name demangling
- :class:`Referenceable` - can be referenced
- :class:`Referencing` - can reference other objects
- :class:`Sequenceable` - has `next` and `prev`
- :class:`MultipleSequenceable` - has `next` and `prev` but they are generators (basic blocks)
- :class:`Typed` - has a type

HexraysItem
-----------

HexraysItem is the base of all AST items in repyda. To check if a node is of a
certain type, the ``isinstance(node, type)`` syntax is encouraged. For more
complex comparisons, see the page on :ref:`AST matching<ast-matching>`.

Object creation
===============

If an object has an ``ea``, passing no parameters will fetch the current curosr
ea and use it to instantiate the object.

For objects which can be instantiated in more than one way, keyword arguments
*must* be used. For example, see :meth:`Function.__init__`.

Using collections
=================

When a function returns more than one object, it always returns a generator.

If a function takes an iterable as a parameter, it is also possible to pass a
single object, in which case the function will wrap it as a tuple with size 1.

Properties
==========

For retrieving things that are part of what makes an object itself, properties
are used. For example, the type of some :class:`Data` instance. This also
extends to iterables, for example :meth:`BlockStatement.statements`. This
holds even if the property does work behind the scenes.

On the other hand, fetching other representations of the object is implemented
as a method. For example, :meth:`Type.get_tinfo()`.

When it makes sense to change the value of a property, a setter is defined. For
example, :meth:`Typed.type`, :meth:`Nameable.name`,
:meth:`Commentable.comment` and :meth:`Addressable.color` fields all have
setters defined. If a property has a setter, it will automatically refresh the
view. If there is a default value for the property (sub_X for function names,
empty commment for :class:`Instruction`) then using either the ``del`` syntax on
the property or just assigning it the value of ``None`` will revert it to the
original value.