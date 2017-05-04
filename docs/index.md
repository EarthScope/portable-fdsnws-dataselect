# The portable-fdsnws-dataselect user guide

## How to Install the Server:

1. You need an installation on Python 3.5 or higher.

2. Issue the command

    `pip install portable_fdsnws_dataselect`
    
(To upgrade to the current version, add a `-U` after `install` (with a space between the two)

3.  There is no step 3!  You should now have an executable named `run_fdsnws_dataselect`.


## How to Prepare your Data for the Server:

1. Use the program mseedindex (https://github.com/iris-edu/mseedindex) to create a Sqlite database containing an index of the miniseed data you wish to make available through your server.

2. You can print a config file example by running `run_fdsnws_dataselect -s`; if you direct this to a file, you can edit it for your installation.

The parameters that need to be supplied are:

* The IP address and port number your server will be accessible from
* The path to the database file you created in the previous step
* The name of the table you created using mseedindex, if it was not the default

There are other settings which are optional.

3. Before the program can use your database, a table must be created in it.  This can be done with the command:

    `run_fdsnws_dataselect -i -c <path-to-your-config-file>`
    
If `-c` is left out, the program will look for a config file named `server.ini` in the current directory

## How to Run your Server:

    `run_fdsnws_dataselect -c <path-to-your-config-file>`


