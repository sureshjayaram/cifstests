#!/usr/bin/env python

#
# Regression tests for the Linux cifs VFS client.
# 
# Author: Suresh Jayaraman <sjayaraman@suse.com>
#

import os
import unittest
import zipfile
import fcntl
import shutil
import errno

try:
	import mmap
	has_mmap = True
except ImportError:
	has_mmap = False
	print 'mmap module required for mmap test not found, will skip.'

try:
	import hashlib
	has_hashlib = True
except ImportError:
	has_hashlib = False
	print 'hashlib module required for MD5Sum test not found, will skip.'

try:
	import xattr
	has_xattr = True
except ImportError:
	has_xattr = False
	print 'xattr module required for Extended attribute test not found,'
	'will skip.'

try:
	import posix1e
	has_posix1e = True
except ImportError:
	has_posix1e = False
	print 'posix1e module required for POSIX ACL tests not found,'
	'will skip.'


TESTFILE = "testfile"
TESTSDIR = "cifstests" # dir in which tests will be executed
TESTDIR = "test"
TMPDIR = "temp"
TESTDATA = 'abcdefghijk12345'
MORE_TESTDATA = 'lmnopqrstuvxyz'
FILE_ATTR = 'user.mime_type'
FILE_ATTR_VAL = 'text/plain'
DIR_ATTR = 'user.backup'
DIR_ATTR_VAL = 'yes'
FACL_TO_SET = 'u::rx,g::-,o::-'
DACL_TO_SET = 'u::rwx,g::-,o::-'
SYS_TMP = '/tmp'


def safe_rm(f_test):
	try:
		os.remove(f_test)
	except OSError:
		pass


class OpenTests(unittest.TestCase):

	''' Tests using various File creation and status flags '''

	def test_create(self):

		''' create a file, open for RDWR '''

		fd = os.open(TESTFILE, os.O_RDWR|os.O_CREAT)
		self.assertNotEqual(fd, -1, 'Error: open with O_CREAT failed')
		os.close(fd)

	def test_readonly(self):

		''' open a file with O_RDONLY, try to write to file '''

		fd = os.open(TESTFILE, os.O_RDONLY)
		try:
			wrote = os.write(fd, TESTDATA)	
		except OSError, e:
			if e.errno == errno.EBADF:
				print 'write to read-only file failed. Expected.'
			else:
				print e
				raise e
		else:
			self.assertNotEqual(wrote, -1, 'Error: write to'
					    'read-only file succeeded')
		finally:
			os.close(fd)

	def test_truncate(self):

		''' open a file with O_TRUNC '''

		fd = os.open(TESTFILE, os.O_WRONLY|os.O_TRUNC)
		self.assertNotEqual(fd, -1, 'Error: open with O_TRUNC failed')
		os.close(fd)

	def test_append(self):

		''' open a file with O_APPEND '''

		f = open(TESTFILE, 'w')
		f.close()
		fd = os.open(TESTFILE, os.O_WRONLY|os.O_APPEND)
		self.assertNotEqual(fd, -1, 'Error: open with O_APPEND failed')
		os.close(fd)

	def test_largefile(self):

		''' open a file with O_LARGEFILE '''

		fd = os.open(TESTFILE, os.O_WRONLY|os.O_LARGEFILE)
		self.assertNotEqual(fd, -1, 'open with O_LARGEFILE failed')
		os.close(fd)

	def test_largefile_truncate(self):

		''' open a file with O_LARGEFILE|O_TRUNC '''

		fd = os.open(TESTFILE, os.O_WRONLY|os.O_LARGEFILE|os.O_TRUNC)
		self.assertNotEqual(fd, -1, 'open with O_LARGEFILE|O_TRUNC'
				    'failed')
		os.close(fd)

	def test_directIO(self):

		''' open a file with O_DIRECT '''

		# XXX: expected to fail even with 'directio' mount option?
		try:
			fd = os.open(TESTFILE, os.O_WRONLY|os.O_DIRECT)
		except OSError, e:
			print e
			raise e
		self.assertNotEqual(fd, -1, 'open with O_DIRECT failed')
		os.close(fd)

	def test_excl_creat(self):

		''' open a new file with O_EXCL|O_CREAT '''

		if os.path.exists(TESTFILE):
			safe_rm(TESTFILE)
		fd = os.open(TESTFILE, os.O_WRONLY|os.O_EXCL|os.O_CREAT)	
		self.assertNotEqual(fd, -1, 'create file with'
				    'O_EXCL|O_CREAT failed')
		os.close(fd)
		safe_rm(TESTFILE)

	def test_excl_open(self):

		''' open an existing file with O_EXCL|O_CREAT '''

		f = open(TESTFILE, 'w')
		f.close()
		try:
			fd = os.open(TESTFILE, os.O_WRONLY|os.O_EXCL|os.O_CREAT)
		except OSError, e:
			if e.errno == errno.EEXIST:
				print 'file already exists. Expected.'
			else:
				print e
				raise e
		else:
			self.assertEqual(fd, -1, "open with O_EXCL|O_CREAT"
				         "didn't fail")
			os.close(fd)

	@classmethod
	def tearDownClass(self):
		safe_rm(TESTFILE)	


class CacheTest(unittest.TestCase): 
				
	def runTest(self):

		''' create dirs, remove, create them again to check consistency '''

		for i in range(1, 24):
			os.mkdir(str(i))

		list1 = os.listdir(os.getcwd())

		for i in range(1, 24):
			os.rmdir(str(i))

		for i in range(1, 24):
			os.mkdir(str(i))

		list2 = os.listdir(os.getcwd())
		self.assertEqual(list1, list2, 'Error: directory listing not'
				 'consistent, perhaps stale cache data?')

	def tearDown(self):
		for i in range(1, 24):
			os.rmdir(str(i))


class StatTest(unittest.TestCase):

	def runTest(self):

		''' stat, open and lstat, compare modes on lstat with stat '''

		f = open(TESTFILE, 'w')
		mode1 = os.stat(TESTFILE).st_mode
		fd = os.open(TESTFILE, os.O_RDONLY)
		mode2 = os.lstat(TESTFILE).st_mode
		self.assertEqual(mode1, mode2, 'Error: modes does not match')

		f.close()
		os.close(fd)
		safe_rm(TESTFILE)


class AppendTest(unittest.TestCase):

	def runTest(self):

		''' open a file with some text, append more '''
		# XXX: only test if forcedirectio mount option is set?

		f = open(TESTFILE, 'w')
		f.write(TESTDATA)
		f.close()

		f = open(TESTFILE, 'a')
		f.write(MORE_TESTDATA)

		f.close()
		safe_rm(TESTFILE)


class BusyFileRenameTest(unittest.TestCase):

	def runTest(self):

	    	''' try renaming the file that is open across dir.'''
		# should get -EBUSY

		f = os.open('t_busy_rename', os.O_CREAT|os.O_WRONLY)
		mypath = os.getcwd()
		os.mkdir(TMPDIR)
		os.chdir(TMPDIR)
		path = os.getcwd()
		try:
			os.rename('../t_busy_rename', 'f_renamed')
		except OSError, e:
			if e.errno == errno.EBUSY:
				print '-EBUSY while renaming open files across dir. Expected.'
			else:
				print e
				raise e
		finally:
			os.close(f)
			safe_rm('f_renamed')
			os.chdir(mypath)
			os.rmdir(TMPDIR)


class LockTests(unittest.TestCase):

	def runTest(self):

		''' test byte-range locking '''

		child_pid = os.fork()
		if child_pid == 0:
			cf = open(TESTFILE, 'w')
			try:
				fcntl.lockf(cf.fileno(), fcntl.LOCK_EX|fcntl.LOCK_NB,
						4, 8, 0)
			except IOError, e:
				print e
				print 'unable to obtain lock from the child'
				raise e
			os._exit(0)
		else:
			pf = open(TESTFILE, 'w')
			pf.write(TESTDATA)
			try:
				fcntl.lockf(pf.fileno(), fcntl.LOCK_EX|fcntl.LOCK_NB,
						4, 0, 0)
			except IOError, e:
				print e
				print 'unable to obtain lock from the parent'
				raise e 
			os.waitpid(child_pid, 0)

		safe_rm(TESTFILE)


class MmapTest(unittest.TestCase):

	@unittest.skipUnless(has_mmap, "requires mmap module")

	def runTest(self):

		''' basic mmap Test '''

		f = open(TESTFILE, 'wb')
		f.write(TESTDATA)
		f.close()

		f = open(TESTFILE, 'rb+')
		size = os.path.getsize(TESTFILE)
		fmap = mmap.mmap(f.fileno(), size)
		fmap.readline()

		fmap = mmap.mmap(f.fileno(), size)
		fmap.write(MORE_TESTDATA)
		fmap.close()
		f.close()
		safe_rm(TESTFILE)


class XattrTests(unittest.TestCase):

	@unittest.skipUnless(has_xattr, "requires xattr module")

        def test_file_attr(self):

        	''' set attrs, get attrs and remove attrs for a file '''

                f = open(TESTFILE, 'w')
                f.close()
		try:
                	xattr.setxattr(TESTFILE, FILE_ATTR, FILE_ATTR_VAL)
		except IOError, e:
			print e
                	safe_rm(TESTFILE)
			raise e

                got_attr = xattr.getxattr(TESTFILE, FILE_ATTR)
		self.assertEqual(got_attr, FILE_ATTR_VAL, 'Error: attributes'
				'mismatch')
                xattr.listxattr(TESTFILE)
                xattr.removexattr(TESTFILE, FILE_ATTR)
                safe_rm(TESTFILE)

	@unittest.skipUnless(has_xattr, "requires xattr module")

        def test_dir_attr(self):

        	''' set attrs, get attrs and remove attrs for a dir '''

                os.mkdir(TESTDIR, 0755)
		try:
			xattr.setxattr(TESTDIR, DIR_ATTR, DIR_ATTR_VAL)
		except IOError, e:
			print e
                	os.rmdir(TESTDIR)
			raise e

                got_attr = xattr.getxattr(TESTDIR, DIR_ATTR)
		self.assertEqual(got_attr, DIR_ATTR_VAL, 'Error: attributes'
				 'mismatch')
                xattr.listxattr(TESTDIR)
                xattr.removexattr(TESTDIR, DIR_ATTR)
                os.rmdir(TESTDIR)

        ''' POSIX ACL tests - setfacl, getfacl '''

	@unittest.skipUnless(has_posix1e, "requires posix1e module")

        def test_file_posix_acl(self):

        	''' set POSIX acl, get remove ACL on a file '''

                f = open(TESTFILE, 'w')
                facl = posix1e.ACL(text=FACL_TO_SET)
                facl.applyto(TESTFILE)
		got_acl = posix1e.ACL(file=TESTFILE)
                f.close()
                safe_rm(TESTFILE)

	@unittest.skipUnless(has_posix1e, "requires posix1e module")

        def test_dir_posix_acl(self):

        	''' set POSIX acl, get remove ACL on a dir '''

                os.mkdir(TESTDIR, 0755)
                dacl = posix1e.ACL(text=DACL_TO_SET)
                dacl.applyto(TESTDIR)
		got_acl = posix1e.ACL(file=TESTDIR)
                os.rmdir(TESTDIR)


class CompressionTest(unittest.TestCase):

	def setUp(self):
		f1 = open('foo', 'w')
		f1.write('Linux CIFS VFS client')
		f1.close()
		f2 = open('bar', 'w')
		f2.write('A quick brown fox jumped')
		f2.close()
		f3 = open('baz', 'w')
		f3.write('Some random text')
		f3.close()

        def runTest(self):
                print 'create ZIP archive and check if the zip file is valid'
                zf = zipfile.ZipFile('foo.zip', mode='w')
		print 'adding file foo to foo.zip'
		zf.write('foo')
		print 'adding file bar to foo.zip'
		zf.write('bar')
		zf.close()
                self.assertNotEqual(zipfile.is_zipfile('foo.zip'), 0, "unable"
		                    "to extract zip file. It may be corrupt")

                print 'append to the archive and check if the zip file is valid'
                zf = zipfile.ZipFile('foo.zip', mode='a')
		print 'appending file baz to foo.zip'
		zf.write('baz')
		zf.close()
                self.assertNotEqual(zipfile.is_zipfile('foo.zip'), 0,
				'unable to extract zip file. It may be corrupt')

	def tearDown(self):
		os.unlink('foo')
		os.unlink('bar')
		os.unlink('baz')
		os.unlink('foo.zip')


class MD5sumTest(unittest.TestCase):

	@unittest.skipUnless(has_hashlib, "requires hashlib module")

	def setUp(self):
		f1 = open('foo', 'w')
		f1.write('Linux CIFS VFS client')
		f1.close()
		f2 = open('bar', 'w')
		f2.write('A quick brown fox jumped')
		f2.close()
		f3 = open('baz', 'w')
		f3.write('Some random text')
		f3.close()
                zf = zipfile.ZipFile('foo.zip', mode='w')
		zf.write('foo')
		zf.write('bar')
		zf.write('bar')
		zf.close()

        def runTest(self):

	        ''' Compute md5sum and verify '''

                try:
                        f = file("foo.zip", 'rb')
                except IOError, e:
			print e
			raise e

                m = hashlib.md5()
                while True:
                        d = f.read(8096)
                        if not d:
                                break
                        m.update(d)
                sum1 = m.hexdigest()
                f.close()

                ''' change dir to /tmp, get full path of the file
                    generate md5sum from there and compare '''

                cur_path = os.getcwd()

		# XXX: Assuming /tmp is present and changeable

                os.chdir(SYS_TMP)
                try:
			zf_path = os.path.join(cur_path, 'foo.zip')
                        f = file(zf_path, 'rb')
                except IOError, e:
			print e
			return
                m = hashlib.md5()
                while True:
                        d = f.read(8096)
                        if not d:
                                break
                        m.update(d)
                sum2 = m.hexdigest()
                f.close()
                os.chdir(cur_path)
		self.assertEqual(sum1, sum2, 'Error: MD5sum does not match')

	def tearDown(self):
		os.unlink('foo')
		os.unlink('bar')
		os.unlink('baz')
		os.unlink('foo.zip')


class TwoWriterTest(unittest.TestCase):

        def runTest(self):

        	''' 2 writers write to file, check if child sees parent's write '''
		# XXX: assumes sched_child_runs_first is 0 (default)
                child_pid = os.fork()

                if child_pid == 0:
                        size = os.stat(TESTFILE).st_size
			self.assertEqual(size, 30, 'Error: child not seeing'
					 'parent writes')
			f = open(TESTFILE, 'a')
                        f.write(TESTDATA)
                        f.write(MORE_TESTDATA)
                	f.close()
			os._exit(0)
                else:
			f = open(TESTFILE, 'a')
                        f.write(TESTDATA)
                        f.write(MORE_TESTDATA)
                	f.close()
			pid, status = os.waitpid(child_pid, 0)

		safe_rm(TESTFILE)


def cleanup():
	work_dir = os.getcwd()
	testdir_path = os.path.join(work_dir, TESTSDIR) 
	if os.path.exists(testdir_path):
		for f_object in os.listdir(testdir_path):
			object_path = os.path.join(testdir_path, f_object)
			print object_path
			if os.path.isfile(object_path):
				print 'removing file'
				os.unlink(object_path)
			else:
				print 'removing dir'
				shutil.rmtree(object_path)
		os.rmdir(TESTSDIR)


def setUpModule():

	print "Create test directory 'cifstests' and change to it."
	cleanup()
	os.mkdir(TESTSDIR, 0755)
	os.chdir(TESTSDIR)


def tearDownModule():
	''' Change directory and deleting test directory. '''
	print 'Clean up and change back to parent dir ...'
	work_dir = os.getcwd()
	parent_dir = os.path.dirname(work_dir)
	os.chdir(parent_dir)
	cleanup()


if __name__ == '__main__':
	test_suite = unittest.TestSuite()
	test_suite.addTest(unittest.makeSuite(OpenTests))
	test_suite.addTest(CacheTest())
	test_suite.addTest(StatTest())
	test_suite.addTest(AppendTest())
	test_suite.addTest(BusyFileRenameTest())
	test_suite.addTest(LockTests())
	test_suite.addTest(MmapTest())
	test_suite.addTest(CompressionTest())
	test_suite.addTest(MD5sumTest())
	test_suite.addTest(TwoWriterTest())
	test_suite.addTest(unittest.makeSuite(XattrTests))
        unittest.TextTestRunner(verbosity=2).run(test_suite)
