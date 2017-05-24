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

### [OPTIONAL] Install a dedicated Python

Any version of Python matching the requirements may be used.  If you
would prefer to have a dedicated Python installation just for the
server we recommend installing
[Miniconda](https://conda.io/miniconda.html) like this:

1. Download [Miniconda](https://conda.io/miniconda.html) for your OS:

    ```
    https://repo.continuum.io/miniconda/Miniconda3-latest-MacOSX-x86_64.sh
    https://repo.continuum.io/miniconda/Miniconda3-latest-Linux-x86_64.sh
    https://repo.continuum.io/miniconda/Miniconda3-latest-Windows-x86_64.exe
    ```

2. Install in a specified directory (`miniconda3`), e.g. for a macOS and Linux:

    ```
    bash Miniconda3-latest-MacOSX-x86_64.sh -p miniconda3 -b
    ```

3. Add the conda-forge channel, install pip and ObsPy:

    ```
    miniconda3/bin/conda config --add channels conda-forge
    miniconda3/bin/conda install -y pip obspy
    ```

### Install the server from [PyPI](https://pypi.python.org/pypi) using `pip`

    /path/to/python/bin/pip install portable-fdsnws-dataselect

If you installed Miniconda as illustrated above the command would be `miniconda3/bin/pip`.

To later upgrade the server to future releases use the following command:

    /path/to/python/bin/pip install -U portable-fdsnws-dataselect

## Running the server

The server is started by using the `/path/to/python/bin/portable-fdsnws-dataselect`
(e.g. `miniconda3/bin/portable-fdsnws-dataselect`).  But first you must create a server
configuration file.  The `portable-fdsnws-dataselect` command will print an example
configuration file if the `-s` option is specified.  To get started:

    /path/to/python/bin/portable-fdsnws-dataselect -s > server.ini

Next edit the `server.ini` file, changing values to match your configuration, in particular:

* The `path` option in the `[index_db]` section must point to your SQLite database file
* The `datapath_replace` option in the same section might be needed to modify the data file paths if the index table in the database does not match the actual data path.

Finally, run the server specifying the config file:

    /path/to/python/bin/portable-fdsnws-dataselect server.ini

You should then be able to see the service interface documentation using a web browser
with an address like `http://ServerHost:ServerPort/`, e.g. `http://localhost:8080/`.

Make sure to look into the server log file (specified in the config file) for errors
if things are not working as ex

## Preparing your data for use with server

Use the program [mseedindex](https://github.com/iris-edu/mseedindex) to create a SQLite
database containing an index of the miniSEED data you wish to make available through your server.
[Instructions are available in the Wiki for mseedindex](https://github.com/iris-edu/mseedindex/wiki).

## This software is a product of the [IRIS Data Management Center](http://ds.iris.edu/ds/nodes/dmc/)

The source code repository is here: [https://github.com/iris-edu/portable-fdsnws-dataselect](https://github.com/iris-edu/portable-fdsnws-dataselect)

<!-- GitHub corner from https://github.com/tholman/github-corners -->
<a href="https://github.com/iris-edu/portable-fdsnws-dataselect" class="github-corner" aria-label="View source on GitHub"><svg width="80" height="80" viewBox="0 0 250 250" style="fill:#70B7FD; color:#fff; position: absolute; top: 0; border: 0; right: 0;" aria-hidden="true"><path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path><path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path><path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path></svg></a><style>.github-corner:hover .octo-arm{animation:octocat-wave 560ms ease-in-out}@keyframes octocat-wave{0%,100%{transform:rotate(0)}20%,60%{transform:rotate(-25deg)}40%,80%{transform:rotate(10deg)}}@media (max-width:500px){.github-corner:hover .octo-arm{animation:none}.github-corner .octo-arm{animation:octocat-wave 560ms ease-in-out}}</style>

