.. _typing:

Types API
=========

.. module:: repyda

Types are fun. Using them in pure IDA isn't.

IDA uses `ida_typeinf.tinfo_t` to represent types. It can be used to query
simple properties (`is_scalar()`, `is_float()`...) but when it comes to more
complicated operations or more complex queries, it starts introducing a lot of
functions and data types to perform these operations (adding a member to a
struct, finding out how many elements an array has...).

Repyda introduces the :class:`Type` class and its subclasses:

* :class:`Pointer`
* :class:`Array`
* :class:`Scalar`
* :class:`Struct` and :class:`StructMember`
* :class:`Union` and :class:`UnionMember`
* :class:`Enum` and :class:`EnumMember`

This section covers the simpler types, the complex (structs, unions and enums
are covered in the next chapter).

Basic operations
----------------

:class:`Scalar` is the most basic of the classes and represents all integers,
floats and their variations (booleans and char types too). Generally, you
should use one of the already defined types exported by Repyda:
* :autodata:`Bool`

.. code-block:: pycon

    >>> d = Data()
    >>> d.type
    signed __int32
    >>> d.type = UnsignedInt64

:class:`Pointer` and :class:`Array` are wrapper types. They take some type
and modify it.

.. code-block:: pycon

    >>> # Creating a pointer from a type is simple
    >>> t = Data().type
    >>> a_pointer = Pointer(t)
    >>> a_pointer.pointed == t
    True
    >>> Array(a_pointer, 5)
    char*[5]

.. note::
    All of :class:`Type` subclasses can be initialized using `tinfo` though
    this should not be used directly by the user.

Creating types
--------------

Above is a simple example of how to use one type and make another from it. You
may also want to create a type from a string. In general, all places where you
can assign/pass a type, you can also pass a string and it will be automatically
converted to a :class:`Type` instance. The underlying function that does this
is :meth:`Type.from_c`.

.. code-block:: pycon

    >>> d = Data()
    >>> d.type = 'int'
    >>> d.type == 'float'
    False
    >>> d.type == Type.from_c('int')
    True
    >>> d.type == 'int'
    True

Construct
---------

Types in Repyda have construct integration. They all implement
:meth:`Type.get_construct_struct` which builds the relevant data
representation. This can be used to integrate with other libraries and is used
in Repyda when accessing :meth:`Data.value` and the likes.

When a type is a variable sized array (i.e. `char[]`, `void*[]`...) and
accessing :meth:`Data.value` Repyda will:

- Try to fetch a C-style string in case of `char[]`
- Will fail miserably

To avoid being miserable, use :meth:`Data.value_with_constraints`. This
function takes a callable which takes in the `Construct` object generated
from :class:`Type` and allows you to return a different `Construct`. Note that
you have to return a new one, this is a limitation on `Construct`'s side... To
make things clearer, here is an example from the `repyda_cpp` plugin:

.. code-block:: python

    def set_base_classes_size(struct: construct.Struct) -> construct.Struct:
        fields = {field.name: field.subcon for field in struct.subcons}
        sized_array = Array(SignedInt32, self._hierarchy_descriptor.value.count_base_classes)
        fields['base_classes'] = sized_array.get_construct_struct()
        return construct.Struct(*(name / type for name,type in fields.items()))

    return self._base_classes_array.value_with_constraints(set_base_classes_size).base_classes

.. note::
    The constraints API is limited and complicated to use at its present state.
    There are plans to make it simpler to use for the case above. There are
    also plans for making it possible to partially parse data and use that data
    as constraints to the rest of the data (think of Microsoft's love for
    structs with variable sized data in them where the size is indicated using
    some enum just before the buffer).