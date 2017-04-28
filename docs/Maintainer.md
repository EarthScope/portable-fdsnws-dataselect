# Instructions for Updating the Package in the Repository

0. Assumes you have already downloaded the `src` directory from here and made your changes.

1. Update the appropriate entries in setup.py; at the very least, update the version (or you won't be able to push the changes to the repository)

https://packaging.python.org/distributing/#configuring-your-project gives details to the various parts of setup.py

2. Remove the `dist` subdirectory (or at least remove everything from it).

3. You can rebuild the source distribution by issuing:

    `python setup.py sdist`
    
3. If you don't already have `twine` installed, install it via `pip`.

4. This will upload the new version to the repository; you will be asked for the necessary username and password:

    `twine upload dist/*`
