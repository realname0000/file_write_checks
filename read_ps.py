#!/usr/bin/python3

import subprocess
import sys
import re
import vuln

# suitable for Linux
args=['/usr/bin/ps','-eo','uid,command']

p = subprocess.Popen(args,
                     stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE)
s='test'
out, _ = p.communicate(s.encode())
p.wait()
out_lines = out.__str__().split("\\n")
out_lines = out_lines[1:] # remove title from ps listing

vuln_program = vuln.Vulnerable() # new object for thinking about filenames seen by ps

for line in out_lines:
    matchObj = re.match( r'^\s*(\d+)\s+(/\S+)', line)
    if matchObj:
       uid = matchObj.group(1)
       program = matchObj.group(2)
       # check_write_access            /prog    deeper_exists  uid  reason_text                             link_depth
       vuln_program.check_write_access(program, 0,             uid, uid + " seen in ps running " + program, 0)

vuln_program.report()
