.. _ast-matching:

Matching the AST
================

.. module:: repyda

.. contents::

Introduction
------------

AST matching and modification is Repyda' main attraction so to say. In this
chapter we will focus on matching. We will go over what is an AST, what we can
get by matching against it and how to do it efficiently using Repyda. If you are
already familiar with an AST, I would still recommend reading the part about
what is an AST as it includes some notes as to how IDA handles its AST which
aren't trivial.

What is an AST
--------------

Abstract Syntax Tree (AST for short) is a way to reason about code and its
correctness. Meant to be a representation of human readable code in a way that
is easier for a computer to work with.

In short, an AST is a tree, whose nodes are different parts of the code it
represents. What is a part then? Well, that depends on the language we are
working with. Different language such as C, C++, Python and other define
different nodes, all with their own rules. Since IDA works with C as its
decompiler output we will focus on the C definition of an AST.

.. note::
    IDA does not exaclty implement a certain standard of the C language
    definition but rather closely resembles it.

Consider the following code

.. code-block:: c

    int main() {
        return 1 + 2;
    }

In textual form, the AST for this code would look something like

.. code-blocK:: json

    {
        "node": "function",
        "type": "int()()",
        "body": {
            "node": "block",
            "statements": [
                "node": "return",
                "expression": {
                    "node": "add",
                    "left": {
                        "node": "number",
                        "value": 1
                    },
                    "right": {
                        "node": "number",
                        "value": 2
                    }
                }
            ]
        }
    }

This is just another representation of the code. It is much easier to reason
about with code. We don't care much about how such ASTs are built or how to
check their validity but only that the code can be represented in this way and
this is the thing we are going to much against. We will use this AST example
to write match filters so keep this example in mind.

.. note::
    IDA has multiple AST representations. All of Repyda' AST API is based on
    :class:`ida_hexrays.citem_t` and its derivatives.

Expressions and statements
--------------------------

C separates nodes into two types, statements and expressions:

* :class:`Statement`: generally, control flow related (:class:`If`, :class:`Switch`, :class:`Return`...)
* :class:`Expression`: operations, can be queried for their type (:class:`Add`, :class:`Call`, :class:`Number`...)

Repyda groups different statements and expressions. This is done to help reduce
duplicate code in Repyda and also to allow matching on thesegroups:

.. code-block:: pycon

    >>> # What if we wanted to match against all bianry operations (oeprations
    >>> # with two operands)? No problem!
    >>> main.match(BinaryOp())
    ...

* :class:`Statement`: all statements
* :class:`ControlFlow`: :class:`If`, :class:`Switch` and loops
* :class:`Loop`: inherit from :class:`ControlFlow`, matches :class:`ForLoop`, :class:`WhileLoop`...
* :class:`Expression`: all expressions, anything that inherits from this class has a :meth:`type<Expression.type>` property
* :class:`BinaryOp`: operations with two operands (a + b, a - b...)
* :class:`ShiftRight`, :class:`Div`, :class:`Mod`: these operations have signed and unsigned variations, these groupings match both variations
* :class:`Comparison`: comparison (a == b, a != b...)
* :class:`AssignmentOp`: all assignment operations (a = b, a += b...)
* :class:`AssignmentShiftRight`, :class:`AssignmentDiv`, :class:`AssignmentMod`: for signed and unsigned matching, but for the assignement variations
* :class:`Literal`: literals (:class:`Number`, :class:`ObjectAddress`...)
* :class:`UnaryOp`: unary operations (only one oeprand)
* :class:`PreOp`: unary operands where the action comes before the operand (:class:`LogicalNot`, :class:`PointerDeref`...)
* :class:`PostOp`: unary operands where the action comes after the operand (:class:`PostInc`, :class:`PostDec`)

.. note::
    It is recommend to look into the :ref:`expressions` and :ref:`statements`
    to get a feel for the different objects and how to match them.

Simple matches
--------------

Say we wanted to go to the `main` function defined above and check if somewhere
in its body it uses the literal `1`.

.. code-block:: pycon

    >>> main = DecompiledFunction('main')
    >>> main.match(Number(1)) is not None
    True
    >>> main.match(Number(2)) is not None
    True
    >>> main.match(Number(3)) is not None
    False

Congrats, you've just written your first match. We can match against numbers
that are used but when we try match against `3`, we don't get a match, our
function does not use this literal.

Rather than modifying on simple numbers, we can match on compound nodes

.. code-block:: pycon

    >>> # Get any Add (x + y) node
    >>> add = main.match(Add())
    >>> # We can get the sub nodes
    >>> add.left
    1
    >>> add.right
    2
    >>> # We can also get the parent of the node
    >>> isinstance(add.parent, Return)
    True
    >>> # Say we had multiple additions and we wanted to find the one where the
    >>> # left hand side is the number 1
    >>> main.match(Add(left=Number(1))) == add
    True

Like :meth:`Matchable.match` there is also :meth:`Matchable.match_all` that
like match takes a filter but returns all matches rather than only the first
one.

Match modifiers
---------------

Say you wanted to find any return where somewhere inside its expression, the
variable `v1` is used. A naive filter would be

.. code-block:: pycon

    >>> main.match(Return(VariableExpression(name='v1')))

This would literaly match `return v1;`. What if we also wanted to catch stuff
like `return v1 + v2;`. In come match modifiers. There are two in Repyda:

* :class:`Contains`: will matching a node where someone inside any of its children the contained node exists, recursively
* :class:`Either`: will math either of multiple nodes

To get our desired effect in the example above, we can use :class:`Contains`

.. code-block:: pycon

    >>> main.match(Return(Contains(VariableExpression(name='v1'))))

Done! Now this will match any `return` statement where somewhere inside of it
the variable `v1` is used. Another way of using :class:`contains<Contain>` is
with the `contains` keyword arguemnt to :class:`HexRaysItem`. The difference
between using the `contains` keyword and actually passing a :class:`Contains`
object is that the keyword version is matched against all children of the node
whereas with a :class:`Contains` object we can dictate that only a specific
field is matched against the contains.

.. code-block:: pycon

    >>> # Will recursively match if the constant 1 is found under the left hand
    >>> # side of an add
    >>> main.match(Add(left=Contains(Number(1))))
    ...
    >>> # Will match against both the left and right hand sides, recursively
    >>> main.match(Add(Contains(Number(1))))
    ...
    >>> # Another way of writing the match statement above
    >>> main.match(Add() / Number(1))
    ...
    >>> # Another way of using Contains is +x, this is the same as Contains(x)
    >>> +Add()
    ...

Like :class:`Contains`, :class:`Either` is meant to match against multiple
values and filter when any of its sub nodes are matched.

.. code-block:: pycon

    >>> main.match(Add(left=Either(Number(1), Number(2))))
    ...
    >>> # A shorter version would be
    >>> main.match(Add(left=Number(1) | Number(2)))
    ...
    >>> # Since all we are doing is matching against different possible values
    >>> # for the value property of a Number instance, we can also create one
    >>> # Number instance and pass multiple values
    >>> main.match(Add(left=Number((1, 2))))
    ...

Note that in the example above, it would make it seem as though :class:`Either`
is useless, since we can pass multiple values. Behind the scenes, Repyda takes
the iterable passed and creates an :class:`Either` node from it.

Values can also takle in callable, such as lambdas or functions to match using
more complicated logic.

.. code-block:: pycon

    >>> main.match(Add(left=Number(lambda x: x < 3)))
    ...

Match gimel gimel
-----------------

Say you have a function with a loop. You only want to match :class:`Return`
statements that come before the loop. To achieve this, we can use the `start`
and `end` keyword arguments to the match functions.

.. code-block:: pycon

    >>> main.match_all(Return(), end=ForLoop())

Shorthand notations
-------------------

To avoid being too verbose and make scripting easier, `Repyda` introduces short
ways to match against common expressions. Passing an object of one of these
types either as a pattern/limit to match or when instantiating
:class:`HexRaysItem` will automatically convert them to the following:

- `int`: :meth:`Number.value` or :meth:`ObjectAddress.ea`
- `float`: :meth:`FloatLiteral.value`
- `str`: :meth:`ObjectAddress.name`, :meth:`ObjectAddress.value` or :meth:`VariableExpression.name`
- `bytes`: :meth:`ObjectAddress.value`
- `construct.Container`: :meth:`ObjectAddress.value`

.. code-block:: pycon

    >>> main.match(Sub(left='a2', right=14))

Unwrap, but not for error handling
----------------------------------

It is common to come across code such as `v3 = *(int *)&v1 + 5;`. Matching this
can be a bit tricky, how do you generalize this pattern? Using contains would
be the right way but writing this out becomes tidious, thankfuly we can use the
shorthand described above:

.. code-block:: pycon

    >>> main.match(Assignment(left=VariableExpression('v3'), right=Add(left=Contains(VariableExpression('v1')), right=Number(5))))
    ...
    >>> # Lets make this shorter
    >>> main.match(Assignment(left='v3', right=Add(left=Contains('v1'), right=5)))
    ...
    >>> # Note we can't use the +x shorthand here since it only works
    >>> # HexRaysItem objects, we can't apply it before 'v1' which is a string

`Repyda` also has shorthands for accessing the members of these cases. Look at
the following examples to access `v1`:

.. code-block:: pycon

    >>> # match is the entire Assignement
    >>> match = ...
    >>> # math.right => *(int *)&v1 + 5
    >>> # match.right.left => *(int *)&v1
    >>> # match.right.left.operand => (int *)&v1
    >>> # match.right.left.operand.operand => &v1
    >>> # match.right.left.operand.operand.operand => v1
    >>> match.right.left.operand.operand.operand
    ...
    >>> # x.unwrap() recursively returns x.operand and does nothing if an item
    >>> # that has no operand was reached
    >>> match.right.left.unwrap()
    ...

:meth:`Expression.unwrap` only opens :class:`Cast`, :class:`AddressRef` and
:class:`PointerDeref`.

The sky is the limit
--------------------

From here we can just about match against anything. Lets give a classic example
of finding all uses of `memcpy` where the `num` parameter is a computed using
an argument.

.. code-block:: python

    def find_memcpy_calls() -> List[Call]:
        calls = list()
        memcpy = Function(name='memcpy')
        memcpy_call_filter = Call(callee=Contains('memcpy'))

        for caller in memcpy.callers:
            calls.extend(caller.decompiled_function.match_all(memcpy_call_filter))

        return calls

    def is_computed_from_argument(var: VariableExpression) -> bool:
        if var.is_argument:
            return True

        affecting_variables = set()

        # Match all assignment operations (a = b, a += b...) before the usage
        # location, var. Since var is a bound HexRaysItem it has a location
        # that can be used as the end of the match_all function.
        assignments = var.function.match_all(
            AssignmentOp(left=+var, right=Contains(VariableExpression())), end=var)

        for assignment in assignments:
            # Get variables from the right hand side
            rhs_variables = assignment.right.match_all(VariableExpression())
            for rhs_var in rhs_variables:
                affecting_variables.add(rhs_var.get_variable())

        # Now for all the variables on the right hand side, check if they are
        # computed from arguments
        return any(is_computed_from_argument(var) for var in affecting_variables)

    def is_controlled_call(call: Call) -> bool:
        num = call.get_argument('num')
        for var in num.match_all(VariableExpression()):
            if is_computed_from_argument(var):
                return True
        return False

    def find_vulnerable_memcpys():
        for call in find_memcpy_calls():
            if is_controlled_call(call):
                print('found call!')

You can make this example even better by counting in references to variables
being passed into functions.