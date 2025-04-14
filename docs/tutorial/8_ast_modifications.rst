Changing the AST
================

.. module:: repyda

This chapter assumes you are already familiar with matching. If you aren't it
is advised to read that chapter first.

IDA's ctree
-----------

As mentioned beofre IDA has multiple AST representations. The one used in repyda
is based around the :class:`ida_hexrays.ctree_t` structure and its nodes
:class:`ida_hexrays.citem_t`. This tree is generated each time the function is
decompiled.

When is a function decompiled?

* The first time it is opened an the decompiled view, a :class:`ida_hexrays.ctree_t` is created
* When you press `F5`, the :class:`ida_hexrays.ctree_t` is re-generated

When the tree is regenerated, all chagnes made to it disappear. This means that
changes made with Repyda' AST API will not persist forever. You can work around
this by saving the modifications to the IDB and applying them using events, but
this is out of the scope of this chapter. In the future there are plans to
implement this mechanism into the AST API.

Making a change
---------------

Making changes is simple. Just create a :class:`HexRaysItem`, find where you
want to set it to and use the :meth:`HexRaysItem.swap` method to switch them
around!

.. code-block:: pycon

    >>> func = DecompiledFunction()
    >>> v1_set = func.match(Assignment(left=VariableExpression(name='v1')))
    >>> new_value = Number(5)
    >>> v1_set.right.swap(new_value)

This will automatically refresh the view and now `v1` is set to be `5`!
Refreshing the view happens by regenerating the string representation of the
:class:`ida_hexrays.ctree_t`. If you want to optimize multiple changes in a row
and only regenerate when the last change is made, use the `do_refresh`
parameter to the :meth:`HexRaysItem.swap` function, `True` by default.

.. note::
    Due to Repyda' internal implementation of finding the associated
    :class:`View` matching the opened :class:`DecompiledFunction`, Repyda has to
    first register the :class:`View`. This happens when a :class:`View` is
    either opened for the first time, or a re-decompilation is done. This
    limitation will hopefully be solved in newer versions of Repyda.