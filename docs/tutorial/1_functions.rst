Functions and basic API
=======================

.. module:: repyda

Locating things
---------------

Repyda is meant to be used as a single import, accessible directly under repyda'
namespace.

.. code-block:: pycon

    >>> import repyda
    >>> repyda.Function
    repyda.base.functions.function.Function
    >>> repyda.Block
    repyda.base.functions.block.Block

.. note::
    From this point forward, assume all code blocks start with the line ``from repyda
    import *``

My first function
-----------------

Fetching :class:`functions<Function>` is simple with repyda:

.. code-block:: pycon

    >>> # Get the function where the cursor is
    >>> # Alternatively pass ea or name
    >>> func = Function()
    >>> func.name
    'r_my_function'
    >>> func.ea
    0xdeadcafe
    >>> func.size
    0x1000
    >>> 0xdeadcaff in func
    True
    >>> func.comment = 'this is a function'

Now we have a :class:`function<Function>`, we can access its attributes, read
them and also modify them. We can also fetch its blocks and instructions:

.. code-block:: pycon

    >>> for block in func.iter_blocks():
    >>>     print(block)
    ...

:meth:`func.iter_instructions<Function.iter_instructions>` and
:meth:`func.iter_arguments<Function.iter_arguments>` are also available.

Like function like son
----------------------

:class:`Blocks<Block>` and :class:`instructions<Instruction>` are also simple
to work with:

.. code-block:: pycon

    >>> block.size
    0x27
    >>> block.function.name
    'r_my_function'
    >>> block.count_instructions
    0xb
    >>> next_blocks = list(block.next)
    >>> len(next_blocks)
    2
    >>> instruction in block
    True
    >>> instruction.comment = 'calculate magic factor'
    >>> instruction.mnemonic
    'ADD'
    >>> instruction.count_operands
    2
    >>> previous_instruction = instruction.prev
    >>> previous_instruction in block
    False
    >>> previous_instruction in instruction.function
    True
    >>> instruction.color = Color(0xff, 0x00, 0x80)

In general, repyda tries to make parent-children relationships accessible.
Objects have properties/functions to access their parent/child. Some properties
of objects can be changed. Repyda' approach is to make the change immediately.