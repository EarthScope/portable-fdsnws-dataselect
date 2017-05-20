# Instructions for updating the portable-fdsnws-dataselect package on PyPI

1. Bump last value in version at `portable_fdsnws_dataselect/__init__.py`

1. Check `setup.py` for anything that needs to be updated.  Overview:
    https://packaging.python.org/distributing/#configuring-your-project

1. Tag `master` branch with release version and push changes and tags to repo

1. Remove the `dist` subdirectory if it exists

1. Rebuild the source distribution by issuing:

    ```
    python setup.py sdist
    ```

1. Upload the new distribution to PyPI (you will be asked for the necessary username and password:)

    ```
    twine upload dist/*
    ```
