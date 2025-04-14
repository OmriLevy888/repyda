Simple HexRays API
==================

.. module:: repyda

.. contents::

Now that you are familiar with the base Repyda API, it's time to get used to the
HexRays API. This part of Repyda will help you reason and automate tasks using
the decompiler.

What Repyda' HexRays API is
---------------------------

* A way to reason about decompiler output
* A way to modify decompiler output

What Repyda' HexRays API isn't
------------------------------

* A way of implementing decompilers for more architectures

A whole new world of functions
------------------------------

The decompiler is simply one more view of the same things we can already
interact with. It all revolves around :class:`DecompiledFunction`. Just like
:class:`Function` they share many traits (being :class:`Nameable`,
:class:`Referenceable`...) and there is a link between a :class:`Function`
object and its :class:`DecompiledFunction` and vice versa.

.. note::
    :class:`DecompiledFunction` are only created when a :class:`Function` is
    being decompiled for the first time. IDA does not hold the internal
    :class:`ida_hexrays.cfunc_t` until a call to :meth:`ida_hexrays.decompile`
    is issued. This means that when it comes to finding :class:`xrefs<Xref>` in
    decompiled output, only references that exist in functions that have
    already been decompiled will show up. This is a limitation not only of the
    Python API supplied by IDA but also of IDA itself (think about referencing
    a global, you will see the references only show up in IDA view. If you then
    decompile the function containing that reference, you will see it in the
    decompiled output too).

.. code-block:: pycon

    >>> func = DecompiledFunction()
    >>> # The link between Function and DecompiledFunction
    >>> isinstance(func.function, Function)
    True
    >>> func.function.decompiled_function is func
    True
    >>> func.ea == func.function.ea
    True
    >>> for arg in func.iter_arguments(): print('an argument!')
    an argument!
    an argument!

Variable, like consts, but much more rebelious
----------------------------------------------

So let's actually do something useful with this :class:`DecompiledFunction`. A
good place to start would be :class:`variables<Variable>`.

.. code-block:: pycon

    >>> func = DecompiledFunction()
    >>> for variable in func.iter_variables(): print('variable!')
    variable!
    variable!
    variable!
    >>> v1 = func.get_variable('v1')
    >>> # Arguments are also variables
    >>> a1 = func.get_variable('a1')
    >>> a1.is_argument
    True
    >>> v1.is_argument
    False
    >>> # These changes will automatically reflect in your view
    >>> a1.name = 'my_amazing_argument_name'
    >>> a1.type = 'float *'
    >>> v1.stack_offset
    10

So we've seen some ways to interact with variable, query them and also change
them. This can be useful for all kinds of things:

* Getting the stack offset and redefining a variable as a struct where IDA thought there are multiple variables
* Matching against the name to see uses