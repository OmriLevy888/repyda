.. _elements:

What are elements
=================

.. module:: repyda

Elements in Repyda inherit from element base classes. These classes help share
functionality and have a unified API.

In general, when looking at the documentation for a class, you will also see
what classes it inherits from. They implement a lot of logic so it is worth
while to know them.

* :class:`Addressable`: anything that has an address (:class:`Function`, :class:`Instruction`, :class:`Data`...)
* :class:`Commentable`: things you can comment (:class:`Instruction`, :class:`StructMember`, :class:`Variable`...)
* :class:`IDBIterable`: can iterate over all instances in the IDB ( :class:`Function`, :class:`Data`, :class:`Enum`...)
* :class:`Nameable`: things with names, also implements demangling ( :class:`Function`, :class:`Data`, :class:`DecompiledFunction`...)
* :class:`Referenceable`: things that can be referenced (:class:`Data`, :class:`Instruction`, :class:`StructMember`...)
* :class:`Referencing`: things that can reference (:class:`Data`, :class:`Instruction`, :class:`Block`...)
* :class:`Sequenceable`: things that have a next of the same type ( :class:`Function`, :class:`Instruction`, :class:`Data`...)
* :class:`MultipleSequenceable`: basically only :class:`Block`, it has more than one possible next
* :class:`Typed`: objects with defined types (:class:`Data`, :class:`Function`, :class:`UnionMember`...)

Some of these base classes define properties. These properties all behave in a
similar way. Let's take :meth:`Typed.type` for example. It can be read. It can
also be written to, updating the object automatically. Furthermore, using
either the `del` syntax or assigning `None` to this property will revert it to
its original value. The same goes for other properties exported through these
base classes: comments, name and more. There are a few exceptions, for example
the :meth:`ea<Addressable.ea>` property (as setting a value to it would not
make much sense) but most properties follow these rules.