# Maybe make a special conym user instead?
# We just create, as it is only a priviledge problem, if jans would be the mysql root user we would not need this file
CREATE DATABASE IF NOT EXISTS conym;
GRANT ALL PRIVILEGES ON conym.* TO 'jans'@'%';
FLUSH PRIVILEGES;