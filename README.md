

http://www.zen19351.zen.co.uk/article_series/oscap_file_checks.html


I had look at OSCAP filemode checks as seen in the latest Fedora (26 alpha) and found the following:

Ensure that Root's Path Does Not Include World or Group-Writable Directories
Rule ID accounts_root_path_dirs_no_write
Result
pass
Time    2017-05-...
Severity        low
Identifiers and References

References:  CM-6(b), 366
Description

For each element in root's path, run:

$ sudo ls -ld DIR

and ensure that write permissions are disabled for group and other.

Rationale

Such entries increase the risk that root could execute code provided by unprivileged users, and potentially malicious code.

Ensure that Root's Path Does Not Include World or Group-Writable Directories    low pass




The check "For each element in root's path, run sudo ls -ld DIR" is inadequate as I can demonstrate with some examples.

[root@fedora26 ~]# echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/root/bin:/opt/silly/bin
[root@fedora26 ~]# ls -lad /opt/silly/bin /opt/silly /opt /
dr-xr-xr-x. 17 root root 224 May  8 20:07 /
drwxr-xr-x.  3 root root  19 May  9 01:16 /opt
drwxrwxrwx.  3 root root  17 May  9 01:16 /opt/silly
drwxr-xr-x.  2 root root   6 May  9 01:16 /opt/silly/bin

Any user can take steps like these to replace the directory used by root.

cd /opt/silly
mv bin oldbin
mkdir bin

The python code here is for checking a full pathname including parent directories.
It also includes following symbolic links (relative or absolute).
