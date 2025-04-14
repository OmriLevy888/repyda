Referencing
===========

.. module:: repyda

.. contents::

Disassembly
-----------

Say we have some global named `user_input`, let's see how to get all referneces
to it.

.. code-block:: pycon

    >>> user_input = Data(name='user_input')
    >>> for xref in user_input.references:
    >>>   print(xref)
    ...

References are represented using the :class:`Xref` class. It exposes different
properties such as :meth:`is_call<Xref.is_call>`, :meth:`is_jump<Xref.is_jump>`
and :meth:`is_read<Xref.is_read>`.

Like :meth:`references<Referenceable.references>` there is also
:meth:`referencing<Referencing.referencing>` which generates all the references
from our item.

The place where the xref originates from is the :meth:`source<Xref.source>` and
the other end is the :meth:`destination<Xref.destination>`. An important
distinction arises when looking at :meth:`exact_source<Xref.exact_source>` and
its counterpart :meth:`exact_destination<Xref.exact_destination>`. To explain
the difference, think of the following: say we have our global, `user_input`,
it is accessed inside a function, `read_input()`. What should the following
code return?

.. code-block:: pycon

    >>> user_input = Data(name='user_input')
    >>> for xref in user_input.references:
    >>>   print(type(xref.source))
    ...

Should we see a :class:`function<Function>` or an
:class:`instruction<Instruction>`? To make it clear what we fetch,
:meth:`source<Xref.source>` will yield the largest item given the source `ea`
whereas :meth:`exact_source<Xref.exact_source>` yields the most specific item.
So in the case of the code above, we would have :class:`functions<Function>`.

Another distinction comes up when taking into account the different reference
types IDA works with, one of which being
:meth:`ORDINARY_FLOW<XrefType.ORDINARY_FLOW>` which represents code flow from
one :class:`basic block<Block>` to another. This is usually no too useful for
us so `Repyda` gives does not yield these references by default. In case you do
need these references, use :meth:`all_references<Referenceable.all_references>`.

Remember `read_input()` from above? Let's look into it.

.. code-block:: pycon

    >>> read_input = Function(name='read_input')
    >>> # Where is the function called?
    >>> for caller in read_input.iter_callers():
    >>>   print(caller)
    ...
    >>> # What functions are called from read_input()?
    >>> for callee in read_input.iter_callees():
    >>>   print(callee)
    ...

:meth:`iter_callers()<Function.iter_callers>` and
:meth:`iter_callees()<Function.iter_callees>` are very similar and take the
same set of parameters:

- `include_jump`: should references from `jump` instructions also be included (`True` by default)
- `as_instructions`: should return result as :class:`Instruction` rather than :class:`Function` (`False` by default)

`as_instructions` comes in handy if your functions is called/jumped to or
calls/jumps to a place where the is valid code (i.e. :class:`Instruction`
instance) but no :class:`function<Function>` defined. Think of stubs or code
blocks with no stack frame. This way `Repyda` allows you to include these cases
too.

Decompiled
----------

.. code-block:: pycon

    >>> read_input = DecompiledFunction(name='read_input')
    >>> for caller in read_input.iter_callers():
    >>>   print(caller)
    ...
    >>> for callee in read_input.iter_callees():
    >>>   print(callee)
    ...

Like their counterparts from the :class:`Function` type, both
:meth:`iter_callers<DecompiledFunction.iter_callers>` and
:meth:`iter_callees<DecompiledFunction.iter_callees>` accept `include_jump`
which acts exactly the same. Unlike their counterparts there is no
`as_instructions` switch. Instead, only
:meth:`iter_callers<DecompiledFunction.iter_callers>` accepts aother parameter,
namely `as_calls` which is `False` by default and determines whether
:class:`DecompiledFunction` or :class:`Call` objects are returned.

Behind the scenes, :meth:`iter_callers<DecompiledFunction.iter_callers>` uses
:meth:`Xref.decompiled_source_from` which returns where there is an
:class:`ObjectAddress` containing the source address of the xref object.

Types
-----

Like :class:`Data`, :class:`Function` and :class:`DecompiledFunction`, types
can also be referenced:

.. code-block:: pycon

    >>> # Where is my_struct used?
    >>> for xref in Struct('my_struct').references:
    >>>   print(xref)
    ...
    >>> # Or query a specific field
    >>> for xref in Union('my_union').get_member('value').references:
    >>>   print(xref)
    ...
    >>> # Or an enum
    >>> for xref in EnumMember('MY_ERROR_CODE').references:
    >>>   print(xref)
    ...

