import json
import redcaplib

redcap_spec_file = 'enclave/test_config.json'

def do_test():
  redcap_spec = {}
  with open(redcap_spec_file, 'r') as f:
    redcap_spec = json.load(f)
  rslt = redcaplib.core._get_user(redcap_spec, redcap_spec.get('username'))
  print rslt
  rslt = redcaplib.core._token_has_full_data_export_privs(redcap_spec)
  print "Token has full privs: " + str(rslt)
  rslt = redcaplib.get_full_record(redcap_spec, 1) 
  print rslt
  
if __name__ == '__main__':
  do_test()  

