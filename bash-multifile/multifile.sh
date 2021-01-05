#!/usr/bin/env bash

# Get the max number of processes for the user and set a limit.
max_num_processes=$(ulimit -u)
limiting_factor=5
num_processes=$((max_num_processes/limiting_factor))

# Get inputs.
code="$1"
path="$2"
inputdir="$3"
overwrite="$4"
purge="$5"

# Upload.
while read -r file
do

    # Make subdirectories.
    subdir="$(dirname $file | sed 's|^/||g')"

    # Limit number of processes to run simultaneously.
    ((i=i%num_processes)); ((i++==0)) && wait

    # Call the Python module and execute.
    python3 -c "from s3streamer.s3streamer import multipart; response = multipart('$code', '$file', '$path/$subdir', overwrite = '$overwrite', purge = '$purge'); print(response)" &

done < <(find "$inputdir" -type f)

exit 0
