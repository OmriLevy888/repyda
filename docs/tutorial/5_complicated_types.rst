More complicated types
======================

.. module:: repyda

Having gone over simple types, it's time to go over more complex, compound
types.

Common interfaces
-----------------

The compound types are:

* :class:`Enum`
* :class:`Struct`
* :class:`Union`

All have a class method to create a new empty object (same as defining a new
one in the types view in IDA). You can configure the new object (give it a
name, size...).

Using the `__init__` syntax does not create a new object. It returns a Repyda
object representing an already existing compound type. If the name is not
found, an error is raised.

Note that changes to two objects that refer to the same underlying compound
type will reflect on each other and on all places where this type is set in the
IDB.

.. code-block:: pycon

    >>> # Assume the following definition
    >>> # struct foo { int a; float b; };
    >>> foo = Struct('foo')
    >>> data = Data()
    >>> data.type = foo
    >>> data.size
    8
    >>> foo_b = foo.get_member('b')
    >>> foo_b.type = 'bool'
    >>> data.size
    5

Even though we didn't change `data` directly, its size changed since the
underlying compound type has changed.

The different classes also expose other useful methods, such as funtionality to
add/remove members, modify existing members and query the types themselves.

Enums
-----

:class:`Enumerations<Enum>` contain named constants. These are C enums, not c++
enums (i.e. the constants live in the global namespace, this is how IDA treats
enums). Another unique property of an enum is :meth:`Enum.is_bitfield`. This
property makes it possible to work with bitfields (Python "Flag").

Structs and unions
------------------

:class:`Structs<Struct>` and :class:`unions<Union>` are really similar to one
another and this reflects in their API. Most of the funcitonality looks about
the same: adding members, removing members, modifying member type, among
others.