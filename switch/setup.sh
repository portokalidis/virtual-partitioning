#!/bin/bash

if [ -f image_keys.db ]; then
	echo "Database image_keys.db already exists!"
else
	sqlite3 image_keys.db ".read image_keys.sql"
	chmod 644 image_keys.db
fi

mkdir -p -m 755 encrypted_lib
mkdir -p -m 755 encrypted_bins
