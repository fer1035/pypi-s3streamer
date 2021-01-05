==============
**S3Streamer**
==============

**BASH MultiFile**

Overview
--------

This BASH wrapper script allows the Python module to run in a parallel manner. What this means is that you can upload multiple files, with each of them in multipart. You can also specify an entire directory instead of each file individually, and the upload will preserve the structure inside the directory.

*The script is an example of its capabilities, so you can modify it to include other module arguments if necessary*.

Arguments
-------------------------------

- Position 1: Authorization code
- Position 2: Target relative path in the S3 bucket
- Position 3: Path to directory or file to upload
- Position 4: Overwrite option (YES or NO)
- Position 5: Purge option (YES or NO)

Usage
-----

.. code-block:: BASH

   ./multifile.sh <code> <target/relative/path> <path/to/file> <overwrite> <purge>
