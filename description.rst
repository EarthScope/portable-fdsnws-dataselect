Portable fdsnws-dataselect
==========================

This is a portable fdsnws-dataselect/1 implementation which allows users to
run a standardized web service to serve their own, arbitrary seismological
data sets in miniSEED format.  Users can then take advantage of existing data
selection and collection tools to access their own data repository.

The system uses a miniSEED data index stored in SQLite.  The index is created
with the `mseedindex`_ program.

The specification for the `fdsnws-dataselect`_ web service is published by
the `International Federation of Digital Seismograph Networks`_.

This software is a product of the `IRIS Data Management Center`_.

.. _mseedindex: https://github.com/iris-edu/mseedindex
.. _fdsnws-dataselect: http://www.fdsn.org/webservices
.. _International Federation of Digital Seismograph Networks: http://www.fdsn.org/
.. _IRIS Data Management Center: http://ds.iris.edu/
