.. _statements:

Statements
##########

.. module:: repyda

+------------------------+----------------------------------+--------------------------+
| HexraysItem            | Notation                         | Description              |
+========================+==================================+==========================+
| `Statement`_           |                                  | Match all statements     |
+------------------------+----------------------------------+--------------------------+
| `EmptyStatement`_      |                                  | Meta for IDA, do not use |
+------------------------+----------------------------------+--------------------------+
| `BlockStatement`_      | .. code-block:: c                |                          |
|                        |                                  |                          |
|                        |    {                             |                          |
|                        |      statements...               |                          |
|                        |    }                             |                          |
+------------------------+----------------------------------+--------------------------+
| `ExpressionStatement`_ | .. code-block:: c                |                          |
|                        |                                  |                          |
|                        |    expression;                   |                          |
+------------------------+----------------------------------+--------------------------+
| `AssemblyBlock`_       | .. code-block:: c                |                          |
|                        |                                  |                          |
|                        |    __asm {                       |                          |
|                        |      instructions...             |                          |
|                        |    }                             |                          |
+------------------------+----------------------------------+--------------------------+
| `ControlFlow`_         |                                  | Matches all control flow |
+------------------------+----------------------------------+--------------------------+
| `If`_                  | .. code-block:: c                |                          |
|                        |                                  |                          |
|                        |    if (condition) {              |                          |
|                        |      true                        |                          |
|                        |    } else {                      |                          |
|                        |      false                       |                          |
|                        |    }                             |                          |
+------------------------+----------------------------------+--------------------------+
| `Default`_             | .. code-block:: c                |                          |
|                        |                                  |                          |
|                        |    default:                      |                          |
|                        |      body                        |                          |
+------------------------+----------------------------------+--------------------------+
| `SwitchCase`_          | .. code-block:: c                |                          |
|                        |                                  |                          |
|                        |    value:                        |                          |
|                        |      body                        |                          |
+------------------------+----------------------------------+--------------------------+
| `Switch`_              | .. code-block:: c                |                          |
|                        |                                  |                          |
|                        |    switch (expression) {         |                          |
|                        |      cases...                    |                          |
|                        |    }                             |                          |
+------------------------+----------------------------------+--------------------------+
| `Break`_               | .. code-block:: c                |                          |
|                        |                                  |                          |
|                        |    break;                        |                          |
+------------------------+----------------------------------+--------------------------+
| `Continue`_            | .. code-block:: c                |                          |
|                        |                                  |                          |
|                        |    continue;                     |                          |
+------------------------+----------------------------------+--------------------------+
| `Return`_              | .. code-block:: c                |                          |
|                        |                                  |                          |
|                        |    return expression;            |                          |
+------------------------+----------------------------------+--------------------------+
| `Goto`_                | .. code-block:: c                |                          |
|                        |                                  |                          |
|                        |    goto label_id;                |                          |
+------------------------+----------------------------------+--------------------------+
| `Loop`_                |                                  | Matches all loops        |
+------------------------+----------------------------------+--------------------------+
| `ForLoop`_             | .. code-block:: c                |                          |
|                        |                                  |                          |
|                        |    for (init; condition; step) { |                          |
|                        |      body                        |                          |
|                        |    }                             |                          |
+------------------------+----------------------------------+--------------------------+
| `WhileLoop`_           | .. code-block:: c                |                          |
|                        |                                  |                          |
|                        |    while (condition) {           |                          |
|                        |      body                        |                          |
|                        |    }                             |                          |
+------------------------+----------------------------------+--------------------------+
| `DoWhileLoop`_         | .. code-block:: c                |                          |
|                        |                                  |                          |
|                        |    do {                          |                          |
|                        |      body                        |                          |
|                        |    } while (condition);          |                          |
+------------------------+----------------------------------+--------------------------+

Statement
---------

.. autoclass:: Statement
    :show-inheritance:
    :members:
    :undoc-members:

EmptyStatement
==============

.. autoclass:: EmptyStatement
    :show-inheritance:
    :members:
    :undoc-members:

BlockStatement
==============

.. autoclass:: BlockStatement
    :show-inheritance:
    :members:
    :undoc-members:

ExpressionStatement
===================

.. autoclass:: ExpressionStatement
    :show-inheritance:
    :members:
    :undoc-members:

AssemblyBlock
=============

.. autoclass:: AssemblyBlock
    :show-inheritance:
    :members:
    :undoc-members:

ControlFlow
-----------

.. autoclass:: ControlFlow
    :show-inheritance:
    :members:
    :undoc-members:

If
==

.. autoclass:: If
    :show-inheritance:
    :members:
    :undoc-members:

Default
=======

.. autoclass:: Default

SwitchCase
==========

.. autoclass:: SwitchCase
    :show-inheritance:
    :members:
    :undoc-members:

Switch
======

.. autoclass:: Switch
    :show-inheritance:
    :members:
    :undoc-members:

Break
=====

.. autoclass:: Break
    :show-inheritance:
    :members:
    :undoc-members:

Continue
========

.. autoclass:: Continue
    :show-inheritance:
    :members:
    :undoc-members:

Return
======

.. autoclass:: Return
    :show-inheritance:
    :members:
    :undoc-members:

Goto
====

.. autoclass:: Goto
    :show-inheritance:
    :members:
    :undoc-members:

Loop
====

.. autoclass:: Loop
    :show-inheritance:
    :members:
    :undoc-members:

ForLoop
_______

.. autoclass:: ForLoop
    :show-inheritance:
    :members:
    :undoc-members:

WhileLoop
_________

.. autoclass:: WhileLoop
    :show-inheritance:
    :members:
    :undoc-members:

DoWhileLoop
___________

.. autoclass:: DoWhileLoop
    :show-inheritance:
    :members:
    :undoc-members: