#!/usr/bin/python3

import subprocess
import os
import sys
import re
import vuln
import unittest

# Set up test data by making /tmp/somefile exist and /tmp/nofile not exist.
open('/tmp/somefile','w')
os.chmod('/tmp/somefile',  420) # 0644
try:
    os.remove('/tmp/nofile')
except:
    pass

class TestAdd(unittest.TestCase):
    """
    Test the vuln module
    """
 
    def test_root_directory(self):
        """
        Test /
        """
        vulninst = vuln.Vulnerable() # new object for thinking about filenames
        vulninst.check_write_access('/', 0, 0, "test case", 0)
        vulninst.report
        self.assertEqual(len(vulninst.cache), 1)
        self.assertEqual(vulninst.cache['/'], [])

    def test_dev_null(self):
        """
        Test /dev/null
        """
        vulninst = vuln.Vulnerable() # new object for thinking about filenames
        vulninst.check_write_access('/dev/null', 0, 0, "test case", 0)
        vulninst.report
        self.assertEqual(len(vulninst.cache), 3)
        self.assertEqual(vulninst.cache['/'], [])
        self.assertEqual(vulninst.cache['/dev'], [])
        self.assertEqual(vulninst.cache['/dev/null'], []) # special case
 
    def test_tmp_directory(self):
        """
        Test /tmp
        """
        vulninst = vuln.Vulnerable() # new object for thinking about filenames
        vulninst.check_write_access('/tmp', 0, 0, "test case", 0)
        vulninst.report
        self.assertEqual(len(vulninst.cache), 2)

    def test_tmp_directory_(self):
        """
        Test /tmp/
        """
        vulninst = vuln.Vulnerable() # new object for thinking about filenames
        vulninst.check_write_access('/tmp/', 0, 0, "test case", 0)
        vulninst.report
        self.assertEqual(len(vulninst.cache), 3)
        self.assertEqual(vulninst.cache['/'], [])
        self.assertEqual(vulninst.cache['/tmp'], []) # because of sticky
        foo = vulninst.cache['/tmp/']
        self.assertEqual(len(foo[0]), 4)

    def test_tmp_nofile(self):
        """
        Test /tmp/nofile
        """
        vulninst = vuln.Vulnerable() # new object for thinking about filenames
        vulninst.check_write_access('/tmp/nofile', 0, 0, "test case", 0)
        vulninst.report
        self.assertEqual(len(vulninst.cache), 3)
        self.assertEqual(vulninst.cache['/'], [])
        # nofile does not exist so sticky does not help
        foo = vulninst.cache['/tmp']
        self.assertEqual(foo[0], ['/tmp', 0, 0, 'world-write'])
        bar = vulninst.cache['/tmp/nofile']
        self.assertEqual(bar[0], ['/tmp', 0, 0, 'world-write'])
 
    def test_tmp_somefile(self):
        """
        Test /tmp/somefile
        """
        vulninst = vuln.Vulnerable() # new object for thinking about filenames
        vulninst.check_write_access('/tmp/somefile', 0, 0, "test case", 0)
        vulninst.report
        self.assertEqual(len(vulninst.cache), 3)
        self.assertEqual(vulninst.cache['/'], [])
        # sticky avoids warning on /tmp
        self.assertEqual(vulninst.cache['/tmp'], [])
        foo = vulninst.cache['/tmp/somefile']
        self.assertEqual(foo[0][0], '/tmp/somefile')
        # [1] is for the uid
        self.assertEqual(foo[0][2], None)
        self.assertEqual(foo[0][3], None)
 
    def test_etc_passwd(self):
        """
        Test /etc/passwd
        """
        vulninst = vuln.Vulnerable() # new object for thinking about filenames
        vulninst.check_write_access('/etc/passwd', 0, 0, "test case", 0)
        vulninst.report
        self.assertEqual(len(vulninst.cache), 3)
        self.assertEqual(vulninst.cache['/'], [])
        self.assertEqual(vulninst.cache['/etc'], [])
        self.assertEqual(vulninst.cache['/etc/passwd'], [])
 
    def test_usr_bin_python(self):
        """
        Test /usr/bin/python - is a relative symbolic link on both SuSE and Fedora
        """
        vulninst = vuln.Vulnerable() # new object for thinking about filenames
        vulninst.check_write_access('/usr/bin/python', 0, 0, "test case", 0)
        vulninst.report
        self.assertGreaterEqual(len(vulninst.cache), 5) # varies between SuSe and Fedora
        self.assertEqual(vulninst.cache['/'], [])
        self.assertEqual(vulninst.cache['/usr'], [])
        self.assertEqual(vulninst.cache['/usr/bin'], [])
        self.assertEqual(vulninst.cache['/usr/bin/python'], [])
 
if __name__ == '__main__':
    unittest.main()
