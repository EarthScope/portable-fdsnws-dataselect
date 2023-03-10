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

This software is a product of the `EarthScope Data Services`_.

.. _mseedindex: https://github.com/earthscope/mseedindex
.. _fdsnws-dataselect: https://www.fdsn.org/webservices
.. _International Federation of Digital Seismograph Networks: https://www.fdsn.org/
.. _EarthScope Data Services: https://www.earthscope.org/
