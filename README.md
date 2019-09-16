# redcaplib

Python functions for working with REDCap.

Refer to core.py for functions and docstrings.

## requirements

- Python 2.7 (ideally 2.7.9+)

## redcap_spec format

One or more functions in the package take an argument called redcap_spec. This
should be a map with the following format:

~~~~
{"api-url": "the full URL of your REDCap server's API endpoint"
,"token": "your api token as a string" 
,"username": "username associated with the API token"}
~~~~

**Note:** The username needs to be present and must be the username associated
with the token. Some functions check to ensure full access and the username
is used to discover this.

