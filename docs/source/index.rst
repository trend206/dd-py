.. deep_security documentation master file, created by
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

This project is an early stage effort and is currently hosted at pypi.

|
| Note: Requires Python 3.5.2 or higher due to reliance on Python's typing module.
|


Getting Started
---------------
Start by creating a ddan object. This ddan represents the DDaN API endpoint

.. code-block:: python

   from ddpy.interfaces.ddan import DDAN

   ddan = DDAN(api_key="", analyzer_ip="")
   resp = ddan.test_connection()


Be sure to close the session when finished to avoid exceeding connection limits.

.. code-block:: python






Example Usage
--------------
Please refer to the Manager api doc at :doc:`ddpy.inferfaces.ddan` for dd-py capabilities.


1.  Authentication: `github <https://github.com/trend206/dsp3/blob/master/examples/authentication.py/>`_.
2.  Get events: `github <https://github.com/trend206/dsp3/blob/master/examples/get_events.py/>`_.
3.  Create block by file hash rules: `github <https://github.com/trend206/dsp3/blob/master/examples/block_by_hash.py/>`_.
4.  Get manager info: `github <https://github.com/trend206/dsp3/blob/master/examples/manager_info.py/>`_.
5.  Alerts: `github <https://github.com/trend206/dsp3/blob/master/examples/alerts.py/>`_.
6.  Host/s operations: `github <https://github.com/trend206/dsp3/blob/master/examples/host.py/>`_.
7.  Administrators: `github <https://github.com/trend206/dsp3/blob/master/examples/administrators.py/>`_.
8.  Event based tasks: `github <https://github.com/trend206/dsp3/blob/master/examples/event_based.py/>`_.
9.  Relays: `github <https://github.com/trend206/dsp3/blob/master/examples/relays.py/>`_.
10. Scripts: `github <https://github.com/trend206/dsp3/blob/master/examples/scripts.py/>`_.
10. Reports: `github <https://github.com/trend206/dsp3/blob/master/examples/reports.py/>`_.

All code Examples can be found on `github <https://github.com/trend206/dsp3/tree/master/examples/>`_



