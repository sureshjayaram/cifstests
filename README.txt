cifstests 0.1
Aug 08 2012
README
===============

These tests are designed for regression testing of the Linux CIFS VFS client.
Tests are written based on the past bug reports and experiences. These tests
are by no means comprehensive but aim to provide basic infrastructure upon
which tests can be added easily.

Tests are written in Python and Pyunit testing framework is being used to make
addition of new tests easier.


Dependencies
------------
These tests depend on posix1e (for ACL tests) and xattr (Extended attribute
tests) modules. Without these modules, those tests will be skipped.


Installation
------------

	tar xzvf cifstests-0.1.tar.gz
	cd cifstests
	python setup.py install

How to run the tests
--------------------

Currently, there is no provision to mount a CIFS share using this test. So, it
requires mounting to be done prior to running the tests.

The `testcifs.py' is the python program that contains all the tests and can
be run on a cifs mount by:

	$./testcifs.py

Tests can be run selectively by:

	$python -m unittest -v testcifs.<Classname> (or)
	$python -m unittest -v testcifs.<Classname>.<TestCase>

For e.g.

	$python -m unittest -v testcifs.OpenTests (or)
	$python -m unittest -v testcifs.XattrTests.test_file_posix_acl


Adding new tests
----------------
You are most welcome to contribute test cases or group of tests. Ideally, it
would be nice to have a testcase for each regression. To write your own test
or test class the following PyUnit documentation in the "References" section
or existing tests might be useful.


References
----------

PyUnit documentation

	http://pyunit.sourceforge.net/pyunit.html
	http://docs.python.org/library/unittest.html


Author
------
Suresh Jayaraman
E-mail: sjayaraman@suse.com

