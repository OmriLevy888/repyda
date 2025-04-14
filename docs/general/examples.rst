.. _general-examples:

Examples
########

Use this page to see examples on common usages and get used to the overall
behaviour of Repyda.

.. contents::

Base
====

Functions
---------

.. code-block:: pycon

    >>> import repyda
    >>> # with no parameters, get the current function
    >>> function = repyda.Function()
    >>> first_block = function._first_block
    >>> # a block can have multiple successive block
    >>> successive_blocks = list(function.first_block.next)
    >>> successive_blocks[0].prev == first_block
    True
    >>> function.name
    sub_1D0480
    >>> function.is_auto_name
    True
    >>> function.name = '_Z4funcif'
    >>> function.name
    '_Z4funcif'
    >>> function.is_user_defined_name
    True
    >>> function.demangle_name
    'func(int,float)'
    >>> # any attribute that has a default value can be restored using del or by
    >>> # assigning None
    >>> del function.name
    >>> function.name, function.is_user_defined_name
    (sub_1D0480, False)
    >>> function.comment = '???'
    >>> function.guessed_type == '__int64 __fastcall(int, int, int, int, __int64, __int64)'
    True
    >>> # check if the user defined a type
    >>> function.has_user_defined_type
    False
    >>> function.type = repyda.Type.from_c('__int64 (int, int, int, int, void *, int (*)(int))')
    >>> function.has_user_defined_type
    True
    >>> function.count_args
    6
    >>> len(list(function.iter_arguments()))
    6
    >>> reference = list(function.references)[0]
    >>> reference.type
    XrefType.CALL_FAR
    >>> isinstance(reference.source, repyda.Addressable)
    True
    >>> isinstance(reference.destination, repyda.Function)
    True
    >>> isinstance(reference.exact_destination, repyda.Instruction)
    True
    >>> len(list(function.all_references)) >= len(list(function.references))
    True
    >>> flow = (ref for ref in function.all_references if ref.type == XrefType.ORDINARY_FLOW)

IDB
---

.. code-block:: pycon

    >>> import repyda
    >>> repyda.IDB.ptr_size()
    64
    >>> repyda.IDB.min_ea(), repyda.IDB.max_ea()
    0x180001000, 0x180174000
    >>> repyda.IDB.image_base()
    0x180000000
    >>> list(repyda.IDB.strings())[0].name
    'aRtlunlockheap'
    >>> first_string = list(repyda.IDB.strings())[0]

Data
----

.. code-block:: pycon

    >>> import repyda
    >>> data = repyda.Data(0x18014cfff)
    >>> data.size
    4
    >>> # repyda will find the start of the element
    >>> repyda.Data(data.ea + 1).ea == data.ea
    True
    >>> # Data is Nameable
    >>> data.name
    g_buffer
    >>> # Data is also Sequenceable
    >>> data.next.name, data.prev.name
    ('aRtlchartointeg', 'aRtlcapturecont')
    >>> # and Data is IDBIterable
    >>> len(list(repyda.Data.iter()))
    big number goes here
    >>> data.guessed_type
    repyda.SignedInt32

Types
-----

.. code-block:: pycon

    >>> import repyda
    >>> repyda.Void
    repyda.Void
    >>> repyda.Bool
    repyda.Bool
    >>> 'void' == repyda.Void
    True
    >>> repyda.SignedInt32.size
    4
    >>> repyda.Type.get_at(ea=0xdead)
    repyda.Float
    >>> repyda.Pointer(repyda.SignedInt32) == 'int *'
    True
    >>> repyda.Array(repyda.Double, 5).size
    40
    >>> # repyda.Struct, repyda.Union and repyda.Enum also exist

Hexrays
=======

Basic interaction
-----------------

.. code-block:: pycon

    >>> import repyda
    >>> decompiled_func = repyda.DecompiledFunction(name='RtlQueryProcessLockInformation')
    >>> func = decompiled_func.function
    >>> func.ea == decompiled_func.ea
    True
    >>> # interact with lines
    >>> func.lines
    ...
    >>> func.view.refresh_ctext()
    >>> func.view.visible = False
    >>> # includes arguments too
    >>> len(list(func.iter_variables()))
    15
    >>> first_var = list(func.iter_variables())[0]
    >>> first_var.name
    'a1'
    >>> first_var.type
    repyda.SignedInt64
    >>> first_var.is_argument
    True
    >>> first_var.name = 'my_var_name'
    >>> first_var.type = repyda.Type.from_c('const bool const *')

Matching the AST
----------------

.. code-block:: pycon

    >>> import repyda
    >>> func = repyda.DecompiledFunction(name='RtlQueryProcessLockInformation')
    >>> len(list(func.match_all(repyda.Return())))
    2
    >>> ret = func.match(repyda.Return(expression=repyda.Number()))
    >>> ret.expression.value
    3221225495
    >>> # find an if statement where inside the true branch there is a break statement
    >>> func.match(repyda.If(true=repyda.Contains(repyda.Break()))) is None
    False
    >>> # if an item has multiple children (condition, true and false for if statements)
    >>> # we can use the contains= to denote any of the children rather than a specific one
    >>> func.match(repyda.If(contians=repyda.VariableExpression(name='v10'))) is None
    False

Modifying the AST
-----------------

.. code-block:: pycon

    >>> import repyda
    >>> func = repyda.DecompiledFunction(name='RtlQueryProcessLockInformation')
    >>> ret = func.match(repyda.Return(expression=repyda.Number()))
    >>> ret.expression.swap(repyda.Number(value=0))

Events
------

.. code-block:: pycon

    >>> import repyda
    >>> def my_hook(event: repyda.HexraysEvent, view: repyda.View):
    >>>     if event == repyda.HexraysEvent.OPEN_HEXRAYS_VIEW:
    >>>         print('new view opened')
    >>>     else:
    >>>         print('view closed')
    >>>
    >>> repyda.HookManager.register(my_hook,
    >>>                            repyda.HexraysEvent.OPEN_HEXRAYS_VIEW |
    >>>                            repyda.HexraysEvent.CLOSE_HEXRAYS_VIEW)