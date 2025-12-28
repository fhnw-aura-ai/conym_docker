mariadb -u root -p"$MARIADB_ROOT_PASSWORD" -e "
CREATE USER cocoa@'%' IDENTIFIED BY '$MARIADB_COCOA_PASSWORD';
SET PASSWORD FOR cocoa@'%' = PASSWORD('$MARIADB_COCOA_PASSWORD');

CREATE DATABASE IF NOT EXISTS cocoa;
GRANT ALL ON cocoa.* TO cocoa@'%';
"

echo "Added Cocoa User and database."
