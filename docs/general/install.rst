.. _general-install:

Installation steps
##################

Using pip
=========

.. code-block:: bash

    py -3 -m pip install repyda

From source
===========

.. code-block:: bash

    git clone
    cd repyda
    py -3 setup.py install

Repyda adds code to your `idapythonrc.py` and `ipyidarc.py` files (These files
are located under ``%APPDATA%\Hex-Rays\IDA Pro\`` for Windows and
``$HOME/.idapro`` for Linux and MacOSX).

.. note::
    Make sure you are installing repyda using the python interpreter your IDA
    uses. To check this, use the ``idapyswitch`` program located under your IDA
    installation directory.