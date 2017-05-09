import os
import re
import genericpath
from stat import *
# from genericpath import *

class Vulnerable():
    def __init__(self):
        self.cache = {} # file permission info
        self.findings = {} # process uid info applicable to each absolute program pathname

    # recursive, sometimes multiply so
    def check_write_access(self, filename, deeper_exists, uid, reason, depth):
        if depth > 20:
            print ("depth exceeded")
            return
        try:
            findings = self.findings[filename]
        except:
            self.findings[filename]=[]
        if (reason):
            self.findings[filename].append([uid, reason])
        try:
            cached = self.cache[filename]
            return
        except:
            self.cache[filename]=[]
        #
        try:
            lst = os.lstat(filename)
            next_deeper_exists = 1
            # Missing file not a problem
            if S_ISLNK(lst.st_mode):
                rl = os.readlink(filename)
                if rl:
                    # absolute or relative ?
                    # lrwxrwxrwx /sbin/agetty -> /usr/sbin/agetty
                    # lrwxrwxrwx /usr/bin/python -> python2.7
                    matchObj = re.match( r'^/', rl)
                    if matchObj:
                        # absolute
                        self.check_write_access(rl, 0, uid, None, depth+1)
                        for chunk in self.cache[rl]:
                            self.cache[filename].append(chunk)
                    else:
                        # relative
                        base = os.path.dirname(filename)
                        combined = base + '/' + rl
                        self.check_write_access(combined, 0, uid, None, depth+1)
                        for chunk in self.cache[combined]:
                            self.cache[filename].append(chunk)
            else:
                one_result = self.check_single_file(filename, lst, deeper_exists)
                if ((one_result[1]) or (one_result[2]) or (one_result[3])):
                    self.cache[filename].append(one_result)
        except:
            # If a file was missing keep looking at parent directories.
            next_deeper_exists = 0
        # recursion, shortened by one component
        shorter = os.path.dirname(filename)
        self.check_write_access(shorter, next_deeper_exists, uid, None, depth)
        if filename != '/':
            for chunk in self.cache[shorter]:
                self.cache[filename].append(chunk)

    def check_single_file(self, filename, lst, deeper_exists):
       group_write = None
       other_write = None
       if (S_IWGRP & lst.st_mode):
           group_write = lst.st_gid
       # world write has exclusions
       if ((filename != '/dev/null') and (filename != '/dev/zero')
       and (filename != '/dev/random') and (filename != '/dev/urandom')):
           if (S_IWOTH & lst.st_mode):
               other_write = 'world-write'
       # adjust for sticky bit on a directory
       if (S_ISDIR(lst.st_mode) and (S_ISVTX & lst.st_mode) and deeper_exists):
           #print ("Adjust for write access " +  filename + " " + other_write)
           group_write = None
           other_write = None
       wr=[filename, lst.st_uid, group_write, other_write]
       return wr

    def report(self):
        for f in self.findings:
            if len(self.findings[f]) and len(self.cache[f]):
                for reason in self.findings[f]:
                    for onestat in self.cache[f]:
                        if ((onestat[1] != int(reason[0])) or (onestat[2]) or (onestat[3])):
                            print ("Danger from ", f, " access for ", onestat)
                            print (reason[1])
