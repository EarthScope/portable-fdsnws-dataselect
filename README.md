# portable-fdsnws-dataselect

A portable [fdsnws-dataselect](http://www.fdsn.org/webservices/) server implementation.

This is a portable fdsnws-dataselect/1 implementation which allows users to
run a standardized web service to serve their own, arbitrary seismological
data sets in miniSEED format. Users can then take advantage of existing data
selection and collection tools to access their own data repository.

The system uses a miniSEED data index stored in SQLite. The index is created
with the [mseedindex](https://github.com/earthscope/mseedindex) program.

The specification for the [fdsnws-dataselect](https://www.fdsn.org/webservices)
web service is published by the
[International Federation of Digital Seismograph Networks](https://www.fdsn.org/).

This software is a product of [EarthScope Data Services](https://www.earthscope.org/).

For more information see the [User Guide](https://earthscope.github.io/portable-fdsnws-dataselect/).
