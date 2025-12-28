#!/usr/bin/env python3
import sys
import os
import mysql.connector
from mysql.connector import Error
from exceptions import RetryException, AbortException

#Just an entrypoint: (so we can switch during experimenting)
def deanonymize_recipient(recipient: str) -> str:
    return _db_load(recipient)

_static_subject_mapping = { 'test': 'markus.knecht@fhnw.ch' }        
def _static_resolve_recipient(recipient: str) -> str:
    # Static mapping for now
    if "@" in line:
        subject, _ = line.split("@", 1)
        if subject in _static_subject_mapping:
            return _static_subject_mapping[subject]
    raise AbortException("No mapping found for recipient")
      
def _switch_domain(recipient: str, newDomain:str) -> str:
    # Static mapping for now
    if "@" in line:
        subject, _ = line.split("@", 1)
        return subject+"@"+newDomain
    raise AbortException("Malformed recipient address")
  
def _db_load(recipient: str) -> str:
    # Read from environment variables
    DB_USER = os.environ.get("RDBMS_USER")
    DB_PASSWORD = os.environ.get("RDBMS_PASSWORD")  #just for test later env needs to be routed here
    DB_HOST = os.environ.get("RDBMS_HOST")          # default to "mysql" if not set
    DB_NAME = os.environ.get("RDBMS_DATABASE")
    try:
        connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )

        cursor = connection.cursor()
        query = (
            "SELECT original FROM replacements "
            "WHERE value = %s AND claim = 'email' "
            "AND (expirationTime > CURRENT_TIMESTAMP OR expirationTime IS NULL)"
        )

        cursor.execute(query, (recipient,))
        results = cursor.fetchall()

        if not results:
            raise AbortException(f"No original found for value: {recipient}")

        original = results[0][0];
        
        if not isinstance(original, str):
             raise AbortException("Expected a string for original")

        return original
    except Error as e:
        raise RetryException("Database could not be queried")
        
    finally:
        if connection and connection.is_connected():
            cursor.close()
            connection.close()