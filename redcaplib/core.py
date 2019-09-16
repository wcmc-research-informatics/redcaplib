from __future__ import division
from __future__ import print_function

import os
import codecs
import cStringIO
import json
import re
import urlparse
import requests
import requests.exceptions
import urllib3.exceptions

import kickshaws as ks

__all__ = ['parse_det_payload'
          ,'get_full_record'
          ,'get_all_full_records'
          ,'get_all_partial_records'
          ,'get_max_record_id'
          ,'bulk_import_records'
          ,'delete_record'
          ,'get_attachment'
          ,'attach_as_csv'
          ,'update_field'
          ]

#------------------------------------------------------------------------------
# det

def parse_det_payload(pyld):
  '''Returns a map of key-value pairs. pyld should be a
  REDCap DET payload (which should be a string
  of key=value pairs separated by ampersands -- i.e., 
  application/x-www-form-urlencoded format).'''
  out = {}
  step = urlparse.parse_qs(pyld, True)
  # Now each value is inside its own list, so transform
  # into simple key-value pairs.
  for k in step:
    out[k] = step[k][0]
  return out

#------------------------------------------------------------------------------
# api

def _parse_filename(http_response_headers):
  '''Parses out filename from headers; use when retrieving an
  attachment from REDCap.
  E.g., an example value for the Content-Type header might be:
    'text/plain; name="contact full upload 4.29.csv";charset=UTF-8'
  Returns empty string if nothing found.
  '''
  r = r'(?: name="(.*?)")'
  rslt = re.findall(r, http_response_headers.get('Content-Type',''))
  return rslt[0] if rslt else ''

def _htpost(redcap_spec, post_data, desired_status, attempts_left=3
            ,output='json', files_data=None):
  '''This is a low-level func that performs the actual HTTP 
  POST to the REDCap API, returning a result or possibly 
  raising an exception. In particular, it will raise an 
  error if the HTTP status of the response does not equal 
  the desired_status arg.
  The default output is Python-native data structure that is the
  result of treating the response data as JSON. If that is not
  what you want, use the optional 'output' arg: it can be one of either
  'json' or 'raw'.'''
  url = redcap_spec['api-url']
  if not url.startswith('https'):
    raise Exception('Insecure URL. API URL must use HTTPS.')
  try:
    # Doc: http://docs.python-requests.org/en/master/user/advanced/#timeouts
    # Two timeout exceptions can happen: ConnectTimeout and ReadTimeout.
    # We allow the latter to propagate, but catch the former.
    # Regarding if logic immediately below, see 
    # https://greenbytes.de/tech/webdav/rfc2616.html#rfc.section.4.4 
    # Basically, Content-Length will not normally occur when Transfer-Encoding exists.
    result = None
    if files_data:
      result = requests.post(url, data=post_data
                            ,files=files_data, timeout=180, allow_redirects=False)
    else:
      result = requests.post(url, data=post_data, timeout=180, allow_redirects=False)
    if (result.headers.get('Transfer-Encoding', '*') == '*'
       or result.headers.get('Transfer-Encoding', '').lower() == 'identity'):
      if not ks.verify_response_content_length(result):
        raise Exception('Incomplete read: connection was closed before '
                        'all data was received.') 
    status = result.status_code
    if status == desired_status:
      if output == 'raw':
        return {'filename': _parse_filename(result.headers), #might be empty str
                'data': result.content}
      else:
        return json.loads(result.text)
    else:
      raise Exception('REDCap API call returned HTTP status of {}; '
                      'details: {}'.format(status, result.text))
  except (requests.exceptions.ConnectionError
         ,requests.exceptions.ConnectTimeout
         ,urllib3.exceptions.NewConnectionError) as ex:
    # Rarely, a call to the API would hang and then fail 
    # with the following error:
    #         Max retries exceeded with url: /redcap_protocols/api/ (Caused by 
    #         NewConnectionError('<urllib3.connection.VerifiedHTTPSConnection 
    #         object at such-and-such>: Failed to establish a new connection: 
    #         [Errno 110] Connection timed out',))
    # The 'max retries' verbiage is actually misleading (see for details: 
    # https://github.com/kennethreitz/requests/issues/1198 for details) as no
    # retries are attempted. We retry manually here using a recursive call.
    attempts_left -= 1
    if attempts_left == 0:
      raise Exception('Connection to REDCap API could not be established '
                      'after multiple tries.')
    else:
      _htpost(redcap_spec, post_data, desired_status
              ,attempts_left=attempts_left, files_data=files_data)

def _get_all_users(redcap_spec):
  '''Returns all users for a REDCap project as a list of maps. Each map
  contains various properties about a user, but the keys you'll possibly
  be most interested in are 'username' and 'email'.
  '''
  post_data = {'token': redcap_spec['token']
              ,'content': 'user'
              ,'format': 'json'
              ,'type': 'flat' }
  result = _htpost(redcap_spec, post_data, desired_status=200)
  if result == None:
    raise Exception('redcaplib._get_all_users: API returned empty result.')
  else:
    return result

def _get_user(redcap_spec, username):
  '''Returns a map containing the fields returned from REDCap 
  for the username. Raises when:
  - Exception if HTTP status is not 200
  - LookupError if username not found.
  '''
  users = _get_all_users(redcap_spec)
  for user in users:
    if user['username'] == username:
      return user
  raise LookupError('Username [' + username + '] not found in REDCap project.') 

# DataExportAccess enumeration.
# REDCap's Data Export privilege levels are as follows.
# (These are the values which can appear in the 'data_export' field in 
# an 'Export Users' result set.)
#  0 --> NO_ACCESS
#  1 --> FULL_DATA_SET
#  2 --> DE-IDENTIFIED
# Because of this, the order of items passed into ks.enum() matters. 
DataExportAccess = ks.enum('NO_ACCESS', 'FULL_DATA_SET', 'DE-IDENTIFIED')

def _token_has_full_data_export_privs(redcap_spec):
  '''Returns True/False. Note that a token is normally tied to a user and
  a user's/role's access can be changed in the REDCap project under User Rights.
  Throws if HTTP status code is not 200.'''
  user_rcd = _get_user(redcap_spec, redcap_spec['username'])
  data_export_priv = int(user_rcd.get('data_export',-1)) 
  return data_export_priv == DataExportAccess.FULL_DATA_SET

def get_full_record(redcap_spec, record_id):
  '''Calls REDCap API to get the full contents of a single record.
  Returns a map, or a list containing maps (which can happen if the REDCap
  project has any repeating instruments).
  Note: for this function, the token/user (they should match) in redcap_spec
  must have **Data Export** privileges set to **Full Data Set**.
  Note about nonexistent records: the current API behavior is to return 
  an empty result with a status of 200.
  _Arguments:_
  - redcap_spec filled out per README.md.
  - record_id -- record id as a string or int
  _Exceptions raised:_
  - Exception if any HTTP call does not return 200
  - Exception when token's associated user does not have Full Data Set access.
  - LookupError if the username in redcap_spec is not part of the REDCap project.
  ''' 
  if not _token_has_full_data_export_privs(redcap_spec):
    raise Exception('Username of [{}] does not have Full Data Set '
                    'export access.'.format(redcap_spec['username']))
  post_data = {'token': redcap_spec['token']
              ,'content': 'record'
              ,'format': 'json'
              ,'type': 'flat'
              ,'records': unicode(record_id) }
  return _htpost(redcap_spec, post_data, desired_status=200)

def get_all_full_records(redcap_spec):
  '''This function is essentially the same as 'get_full_record' but
  will return the entire dataset from the REDCap project.
  _Exceptions raised:_
  - Exception if any HTTP call does not return 200
  - Exception when token's associated user does not have Full Data Set access.
  - LookupError if the username in redcap_spec is not part of the REDCap project.
  ''' 
  if not _token_has_full_data_export_privs(redcap_spec):
    raise Exception('Username of [{}] does not have Full Data Set ' 
                    'export access.'.format(redcap_spec['username']))
  post_data = {'token': redcap_spec['token']
              ,'content': 'record'
              ,'format': 'json'
              ,'type': 'flat'}
  return _htpost(redcap_spec, post_data, desired_status=200)
  
def get_all_partial_records(redcap_spec, fields):
  '''This function is essentially the same as 'get_all_full_records' but
  here you specify which fields you want (one benefit is that you can exclude
  instrument-related metadata fields such foo_complete).
  * IMPORTANT NOTE: If you specify a single field, and one or more records
  have a NULL value for that field, those records are not included.
  * Note about repeating instrument fields: if a specified field in the fields
  arg is part of a repeating instrument, this will result in multiple maps
  in the result set for a single REDCap record.
  _Args:_
    - redcap_spec: see README
    - fields: this should be a Python list of field names as strings.
  _Exceptions raised:_
  - Exception if any HTTP call does not return 200
  - Exception when token's associated user does not have Full Data Set access.
  - LookupError if the username in redcap_spec is not part of the REDCap project.
  ''' 
  if not _token_has_full_data_export_privs(redcap_spec):
    raise Exception('Username of [{}] does not have Full Data Set' \
                   ' export access.'.format(redcap_spec['username']))
  post_data = {'token': redcap_spec['token']
              ,'content': 'record'
              ,'format': 'json'
              ,'type': 'flat'
              ,'fields': ','.join(fields) }
  return _htpost(redcap_spec, post_data, desired_status=200)

def _get_all_record_ids(redcap_spec, field_name_for_record_id='record_id'):
  '''Get a list of all record IDs for the REDCap project.
  Note:the REDCap API still is prone to insert certain fields into
  the result set, e.g., 'redcap_repeat_instance' and ''redcap_repeat_instrument'.
  '''
  return map(lambda mp: int(mp[field_name_for_record_id]),
             get_all_partial_records(redcap_spec, [field_name_for_record_id]))

def get_max_record_id(redcap_spec, field_name_for_record_id='record_id'):
  '''Retrieve the max record ID for the REDCap project.
  (Recall that redcap_spec will contain a token that is already
  associated with a PID.) Returns an int, or None if the project
  has no records.
  '''
  ids = _get_all_record_ids(redcap_spec, field_name_for_record_id)
  return max(ids)

def bulk_import_records(redcap_spec, records):
  '''Add/update one or a group of records.
  Args:
    - redcap_spec: see README
    - records: this should be a Python-native
      list of maps. Each map must have a key-value pair corresponding
      to the record ID field; otherwise an error such as
      'The record id field (itemid) is missing' will
      occur.
  Returns: list of record IDs that were added/updated.
  Notes on potential errors:
    - "You do not have permissions to use the API": this error can
      happen even when you do have sufficient permissions, so this
      can be misleading; the request might in fact be malformed in some
      fashion.
    - "The value you provided could not be validated because it 
      does not follow the expected format": in the Online Designer,
      check whether the field has any Validation setting on it.
  '''
  post_data = {'token': redcap_spec['token']
              ,'content': 'record'
              ,'format': 'json'
              ,'type': 'flat'
              ,'overwriteBehavior': 'normal'
              ,'forceAutoNumber': 'false'
              ,'returnContent': 'ids'
              ,'returnFormat': 'json'
              ,'data': json.dumps(records)
              }
  # Above, json.dumps can handle str and unicode data; will
  # output JSON as a str containing unicode escape sequences.
  return _htpost(redcap_spec, post_data, desired_status=200)

def delete_record(redcap_spec, record_id):
  '''Delete a record from a REDCap project.
  Args:
    - redcap_spec: see README
    - record_id: ID of the record (i.e., field that usually but 
      not always is called 'record' or 'record_id').
  Returns 1 if successful.
  Ref: https://domain/redcap_protocols/api/help/?content=del_records
  '''
  post_data = {'token': redcap_spec['token']
              ,'content': 'record'
              ,'action': 'delete'
              ,'records[0]': unicode(record_id) }
  return _htpost(redcap_spec, post_data, desired_status=200)

def get_attachment(redcap_spec, record_id, field):
  '''Given a record ID and field name, retrieve the attached file.
  Note: REDCap might incorrectly declare a file to have a charset of UTF-8 even
  when it doesn't, which is why we pass the 'raw' flag to _htpost --
  which will then return the value of '.content' rather than '.text'
  (requests lib uses the charset declaration when preparing the value
  of '.text').
  '''
  post_data = {'token': redcap_spec['token']
              ,'content': 'file'
              ,'action': 'export'
              ,'record': unicode(record_id)
              ,'field': field
              }
  return _htpost(redcap_spec, post_data, desired_status=200, output='raw')

def attach_as_csv(redcap_spec, record_id, field, filename, seq_of_maps):
  '''Given a sequence of maps, convert and attach to a REDCap record as
  a CSV file.'''
  post_data = {'token': redcap_spec['token']
              ,'content': u'file'
              ,'action': u'import'
              ,'record': unicode(record_id)
              ,'field': field
              }
  files_data = {'file': (filename,
                         ks.seq_of_maps_into_csv_data(seq_of_maps,
                                                      include_bom=True),
                         u'text/plain')}
  # Note that REDCap itself returns empty string; _htpost will return
  # its standard map (w/ empty values).
  return _htpost(redcap_spec, post_data, desired_status=200,
                 files_data=files_data, output='raw')

def update_field(redcap_spec, record_id, field, val):
  '''Puts/overwrites a value into a field on a REDCap record.
  Note: if the record_id passed in does not currently exist, this
  call results in that record first being created, and then having
  the value applied. (A new record will not be created, however, if
  the field name doesn't exist.)
  If successful, returns a JSON string containing the
  record ID affected. '''
  post_data = {'token': redcap_spec['token']
              ,'content': 'record'
              ,'format': 'json'
              ,'type': 'flat'
              ,'overwriteBehavior': 'normal'
              ,'forceAutoNumber': 'false'
              ,'returnContent': 'ids'
              ,'returnFormat': 'json'
              ,'data': json.dumps([{'record_id': unicode(record_id),
                                   field: val}])
              }
  # A little gotcha above: your 'data' should be couched in
  # inside a list (e.g., using the brackets). Otherwise, REDCap responds
  # with 200 but takes no action.
  return _htpost(redcap_spec, post_data, desired_status=200, output='raw')

