Welcome to Repyda' documentation!
#################################

Indices and tables
==================

* :ref:`genindex`
* :ref:`search`

How to read the docs
====================

If you're new to repyda, strat by following the :ref:`general-install`.
For examples and actual usage, see the :ref:`general-examples` page.
To get an understanding of how to use repyda, see the
:ref:`general-architecture` page.

First steps
===========

.. toctree::
    :maxdepth: 1

    general/install
    general/architecture
    general/examples
    tutorial/0_tutorial
    tutorial/1_functions
    tutorial/2_data
    tutorial/3_elements
    tutorial/4_types
    tutorial/5_complicated_types
    tutorial/6_hexrays
    tutorial/7_matching
    tutorial/8_ast_modifications
    tutorial/9_xrefs
    tutorial/10_events

API documentation
=================

Base interface
--------------

This regroups the part about the base interface on top of the IDA basic API.
All classes in this part are regroup in the ``repyda.base`` module.

.. toctree::
    :maxdepth: 1

    base/elements
    base/functions
    base/types
    base/idb
    base/data
    base/errors

Hexrays interface
-----------------

This regroups the interface on top of the IDA Hexrays API, in particular it
allows to visit the AST generated for the functions and make changes to it.
This module will be useful only if the decompiler for the binary exist and
is installed.

.. toctree::
    :maxdepth: 1

    hexrays/functions
    hexrays/matching
    hexrays/expressions
    hexrays/statements
    hexrays/gui