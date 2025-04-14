Working with data
=================

.. module:: repyda

So we know how to access functions and perform some cool party tricks. Now
let's get to more useful stuff. Introducting Data: that big thing the cool kids
rave about!

Repyda' :class:`Data` API is your best friend when you want to manipulate,
well, data. :meth:`Fetching<Data.__init__>` already defined data or rather
:meth:`creating it<Data.create_at>` on your own is quite straight forward:

.. code-block:: pycon

    >>> string = Data(name='a_quack')
    >>> string.type
    char[15]
    >>> float = Data.create_at(ea=string.ea + string.size, type='float')
    >>> float.value = 5.0

Other functionality exposed includes comments, xrefs and more, see discussion
in :ref:`elements<elements>`.

A cool trick about data in Repyda is that thanks to the :ref:`typing<typing>` API, it
works seemlessly with construct:

.. code-block:: pycon

    >>> # Assume 'my_struct' is defined as:
    >>> # struct my_struct { int a; float b; };
    >>> data = Data.create_at(type='my_struct')
    >>> data.value
    Container(a=32493, b=3.532)
    >>> value = data.value
    >>> value.a = 5
    >>> value.b = -5.3
    >>> data.value = value
    >>> data.value
    Container(a=5, b=-5.3)