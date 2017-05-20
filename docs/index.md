# The portable-fdsnws-dataselect user guide

1. [Overview](#overview)
1. [Installing the server](#installing-the-server)
1. [Running the server](#running-the-server)
1. [Preparing your data for use with server](#preparing-your-data-for-use-with-server)

## Overview

The portable-fdsnws-dataselect server is an implementation of the
[International FDSN's](https://www.fdsn.org/)
[fdsnws-dataselect](http://www.fdsn.org/webservices/) web service specification.
In a nutshell, this server can be used to provide access to a repository of miniSEED
formatted data using a standardized web service.

The server requires a data index, as created by [mseedindex](https://github.com/iris-edu/mseedindex/wiki)
to serve data from a repository.

## Installing the server

Requirements: Python 2.7 or higher, [ObsPy](http://obspy.org) and some common modules.

The instructions below identify key programs as `/path/to/python/bin/<program>`, which should
be adjusted to wherever your preferred python setup is located.

### [Optional] Install a dedicated Python

If you would prefer to have a dedicated Python installation just for the server we
recommend Minicona like this:

1. Download Miniconda for your OS:

    ```
    https://repo.continuum.io/miniconda/Miniconda3-latest-MacOSX-x86_64.sh
    https://repo.continuum.io/miniconda/Miniconda3-latest-Linux-x86_64.sh
    https://repo.continuum.io/miniconda/Miniconda3-latest-Windows-x86_64.exe
    ```

2. Install in a specified directory (`miniconda3`), e.g. for a macOS and Linux:

    ```
    bash Miniconda3-latest-MacOSX-x86_64.sh -p miniconda3 -b
    ```

3. Add the conda-forge channel, install ObsPy and make sure future and requests are installed:

    ```
    miniconda3/bin/conda config --add channels conda-forge
    miniconda3/bin/conda install -y pip obspy future requests
    ```

### Install the server from PyPI using `pip`

    ```
    /path/to/python/bin/pip install portable-fdsnws-dataselect
    ```

If you installed Miniconda as illustrated above the command would be `miniconda3/bin/pip`.

To later upgrade the server to future releases use the following command:

    ```
    /path/to/python/bin/pip install -U portable-fdsnws-dataselect
    ```

## Running the server

The server is started by using the `/path/to/python/bin/portable-fdsnws-dataselect`
(e.g. `miniconda3/bin/portable-fdsnws-dataselect`).  But first you must create a server
configuration file.  The `portable-fdsnws-dataselect` command will print an example
configuration file if the `-s` option is specified.  To get started:

    ```
    /path/to/python/bin/portable-fdsnws-dataselect -s > server.ini
    ```

Next edit the `server.ini` file, changing values to match your configuratation, in particular:

* The `path` option in the `[index_db]` section must point to your SQLite database file
* The `datapath_replace` option in the same section might be needed to modify the data file paths if the index table in the database does not match the actual data path.

    ```
    run_fdsnws_dataselect -c <path-to-your-config-file>
    ```

Finally, run the server:

    ```
    /path/to/python/bin/portable-fdsnws-dataselect server.ini
    ```

You should then be able to see the service interface documentation using a web browser
with an address like `http://ServerHost:ServerPort/`, e.g. `http://localhost:8080/`.

Make sure to look into the server log file (specified in the config file) for errors
if things are not working as ex

## Preparing your data for use with server

Use the program [mseedindex](https://github.com/iris-edu/mseedindex) to create a SQLite
database containing an index of the miniSEED data you wish to make available through your server.
[Instructions are available in the Wiki for mseedindex](https://github.com/iris-edu/mseedindex/wiki).

## This software is a product of the [IRIS Data Management Center](http://ds.iris.edu/ds/nodes/dmc/)
