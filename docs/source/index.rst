.. dd-py documentation master file, created by
   sphinx-quickstart on Wed Nov  2 16:08:12 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directives...


|
Welcome to dd-py
===============

A Python 3 client for Trend Micro's Deep Discovery Platform.


Installation
------------

.. code-block:: python

   pip install dd-py

This project is an early stage effort.

|
| Note: Requires Python >= 3.6.4.
|


Getting Started
---------------
Start by creating a ddan object. This objects abstracts and represents the DDAN/DTAS API endpoint

.. code-block:: python

   from ddpy.interfaces.ddan import DDAN

   ddan = DDAN(api_key="", analyzer_ip="")
   resp = ddan.test_connection()


Example Usage
--------------
Please refer to the ddan interface api doc at :doc:`ddpy.inferfaces.ddan` for dd-py capabilities.


1.  Authentication: `github <https://github.com/trend206/dd-py/blob/master/examples/authentication.py/>`_.
2.  Get black lists: `github <https://github.com/trend206/dd-py/blob/master/examples/get_blacklists.py/>`_.
3.  Submit File: `github <https://github.com/trend206/dd-py/blob/master/examples/submit_file.py/>`_.


All code Examples can be found on `github <https://github.com/trend206/dd-py/tree/master/examples/>`_



