#!/usr/bin/env python

import os, sys, re, glob, shutil, hashlib, subprocess
from optparse import OptionParser
from datetime import datetime
from PIL import Image, ExifTags

def main():
	'''
	parse command line options and take appropriate action
	'''
	import optparse
	
	# define and parse command-line options
	prog = os.path.basename(sys.argv[0])
	usage = "Usage: %s [options] action source dest" % prog
	
	parser = optparse.OptionParser(usage)
	parser.add_option("-c", "--copy",    dest="copy",    action="store_true",  help="copy files to destination [default]")
	parser.add_option("-m", "--move",    dest="copy",    action="store_false", help="move files to destination")
	parser.add_option("-v", "--verbose", dest="verbose", action="store_true")
	parser.add_option("-q", "--quiet",   dest="verbose", action="store_false")
	
	# sort action options
	group = optparse.OptionGroup(parser, "Sort Photos", "Usage: %s [options] sort source dest" % prog)
	group.add_option("-n", "--name",      dest="name",     help="specify a bucket name for this image source (default is the source directory name)", metavar="NAME")
	group.add_option("-p", "--preserve",  dest="preserve", action="store_true",  help="keep all alternates including low-res and duplicates [default]")
	group.add_option("-d", "--discard",   dest="preserve", action="store_false", help="discard duplicates and low-res alternates.")
	group.add_option("-t", "--trusted",   dest="trust",    action="store_true",  help="trust this source to displace existing sources [default]")
	group.add_option("-u", "--untrusted", dest="trust",    action="store_false", help="do not displace existing sources, treat as potentialy corrupt.")
	group.add_option("-j", "--combine",   dest="combine",  action="store_true",  help="combine identical images into one file [default]")
	group.add_option("-s", "--separate",  dest="combine",  action="store_false", help="treat identical images as alternates.")
	parser.add_option_group(group)
	
	# restore action options
	group = optparse.OptionGroup(parser, "Restore Original Filenames", "Usage: %s [options] restore source [dest]" % prog)
	parser.add_option_group(group)
	
	# fix action options
	group = optparse.OptionGroup(parser, "Fix Photo Dates", "Usage: %s [options] fix source [dest]" % prog)
	group.add_option("-z", "--test", dest="test", action="store_true", help="perform a test run (do not modify anything)")
	parser.add_option_group(group)
	
	# parse our options
	parser.set_defaults(verbose=True, copy=True, preserve=True, combine=True, trust=True, test=False)
	(options, args) = parser.parse_args()
	
	if len(args) == 0:
		parser.print_help()
		return
	elif args[0] not in ('sort','fix','restore','replace'):
		parser.error("Invalid action provided")
	elif args[0] in ('fix','restore') and len(args) == 2:
		args.append(args[1])
	elif len(args) != 3:
		parser.error("Incorrect number of arguments")
	
	(action, src, dest) = args
	src  = src.rstrip('/\\')
	dest = dest.rstrip('/\\')
		
	# ensure source and destination both exist and are directories
	for path in (src, dest):
		if (action == 'replace' and not os.path.isfile(path)) or (action != 'replace' and not os.path.isdir(path)):
			parser.error("No such file or directory '%s'" % path)
	
	# handle sort action
	if action == 'sort':
		if not options.name:
			options.name = os.path.basename(os.path.abspath(src))
		
		name = unique_name(options.name, dest)
		if name != options.name:
			print "[WARNING] A file or directory named '%s' already exists at '%s'. Using '%s' instead." % (options.name, dest, name)
		
		sort_images(src, dest, name, options.copy, options.combine, options.trust, options.preserve, options.verbose)
	
	# handle restore action
	if action == 'restore':
		restore_images(src, dest, options.copy, options.verbose)
	
	# handle fix action
	if action == 'fix':
		fix_images(src, dest, options.copy, options.verbose, options.test)
	
	# handle replace action
	if action == 'replace':
		replace_image(src, dest, options.copy, options.verbose)


def sort_images(src, dest, src_bucket, copy=True, combine=True, trusted=True, preserve=True, verbose=True):
	'''
	sort images within src to labeled buckets within dest
	'''
	
	# generate our log closure
	logfile = dest + '/' + src_bucket + '/_sort.log.txt'
	prefix = "\nSOURCE: %s\n" % src_bucket
	log = logger(logfile, verbose, prefix)
	
	# generate our move closure
	move = mover(copy)
	
	# ensure the source and destination exist
	if not os.path.isdir(src) or not os.path.isdir(dest):
		raise IOError('Source or destination directory not found')
	
	# ensure the destination bucket exists
	assert_dir(dest+'/'+src_bucket, "Unable to create needed directories within destination ('%s')" % dest)
	
	# capture all directory names within dest path, ensure src_bucket is last in the list
	buckets = filter(lambda name: os.path.isdir(dest + '/' + name), os.listdir(dest))
	buckets.remove(src_bucket)
	buckets += [src_bucket]
	
	log("Reading from '%s' (%s)...\n" % (src, src_bucket))
	log("Sorting Images...\n")
	
	# iterate through all files within src
	files = get_all_files(src)
	tally = {
		'files': 0,
		'file_match': 0,
		'meta_match_rep': 0,
		'meta_match_unk': 0,
		'meta_match_low': 0,
		'meta_match_alt': 0,
		'no_match': 0,
		'no_meta': 0,
		'corrupt': 0
	}
	
	for filepath in files:
		# capture filename and extension
		filename = os.path.basename(filepath)
		extension = os.path.splitext(filename)[1].lower()
		
		# generate local file path
		relpath = re.sub('^%s/?' % src, '', filepath)
		
		# attempt to obtain file meta-data
		filemeta = get_file_metadata(filepath)
		filehash = get_file_hash(filepath)[:6:]
		
		if filemeta:
			# file is an image
			if filemeta['date_taken']:
				date = filemeta['date_taken']
				metapath = '/exif'
			else:
				date = filemeta['file']['mtime']
				metapath = '/noexif'
			
			# generate match-string for the image
			res = sorted((filemeta['width'], filemeta['height']))
			subpath = date.strftime('/%Y/%m')
#			matchmeta = date.strftime('%Y.%m.%d %H.%M.%S-') + str(filemeta['hdr'])
			matchmeta = date.strftime('%Y.%m.%d %H.%M.%S-') + '%s %s' % (str(filemeta['hdr']), filemeta['signature'][0:4])
			matchfile = matchmeta + ' %04dx%04d %s %s' % (res[1], res[0], filemeta['status'], filehash)
			
			# tally corrupted files
			if filemeta['corrupt'] > 1:
				tally['corrupt'] += 1
			
			# look for matches within each source bucket
			for bucket in buckets:
				sortbase = bucket + metapath + subpath
				logfiles = [dest + '/' + sortbase + '/_sort.log.txt']
				matches = glob.glob('/'.join((dest, sortbase, matchmeta)) + '*')
				
				if matches:
					# metadata match found
					# get minimum resolution from the match(es)
					def parse_res(s):
						m = re.search(" (\d{4})x(\d{4}) ", s)
						if m:
							return int(m.group(1)) * int(m.group(2))
						return -1
					
					replacefile = None
					min_res = min([parse_res(os.path.basename(match)) for match in matches])
					
					# compare photo resolutions
					if bucket != src_bucket:
						if filemeta['width'] * filemeta['height'] > min_res:
							# higher resolution image found
							if len(matches) > 1 and bucket != src_bucket:
								subpath = '/unk'
							elif not trusted or filemeta['corrupt']:
								subpath = '/alt'
							else:
								replacefile = matches[0]
						else:
							# lower or equal resolution image found
							subpath = '/low'
						
						# extract the canonical filename from our matched image
						canonical = re.search("\[([^\[]*)\]", os.path.basename(matches[0]))
						if canonical:
							filename = canonical.group(1)
							if len(matches) > 1:
								filename = '?' + filename
						
						# log this in the corresponding bucket as well
						logfiles.append(dest + '/' + bucket + '/_sort.log.txt')
					
					# set our new sortbase if necessary
					sortbase = bucket + metapath + subpath
					
					# search for identical copies
					if combine:
						matches += glob.glob('/'.join((dest, sortbase, matchmeta)) + '*')
						identical = [match for match in matches if os.path.basename(match).startswith(matchfile)]
						if identical:
							# identical file found
							# add src_bucket to the list of sources within the filename
							rename = identical[0].split('].')
							sources = rename.pop().split('.')
							rename_ext = sources.pop()
							
							for i, source in enumerate(sources):
								if source == src_bucket:
									sources[i] = src_bucket + '(x2)'
									break
								m = re.search("^(.*)\(x(\d*)\)$", source)
								if m and m.group(1) == src_bucket:
									sources[i] = '%s(x%d)' % (src_bucket, int(m.group(2)) + 1)
									break
							else:
								sources.append(src_bucket)
							rename = '].'.join(rename + ['.'.join(sources + [rename_ext])])
							
							# log this action
							log('File-Match : %s [MOVED TO] %s' % (relpath, rename[len(dest)+1::]), logfiles)
							log('             [RENAMED] %s' % identical[0][len(dest)+1::], logfiles)
							
							# rename the file and delete the duplicate if we're not copying
							move(identical[0], rename, copy=False)
							if not copy:
								os.unlink(filepath)
							tally['file_match'] += 1
							break
					
					# remove lower resolution images if they aren't duplicates of anything else
					if subpath == '/low' and not preserve:
						if not copy:
							os.unlink(filepath)
						log('Meta-Match : %s [REMOVED]' % relpath, logfiles)
						break
					
					# compile our new filename
					sortname = unique_name(matchfile + ' [%s].%s%s' % (filename, src_bucket, extension), dest + '/' + sortbase)
					sortpath = sortbase + '/' + sortname
					
					# log this action
					if bucket == src_bucket:
						log('  No-Match : %s [MOVED TO] %s' % (relpath, sortpath), logfiles)
					else:
						log('Meta-Match : %s [MOVED TO] %s' % (relpath, sortpath), logfiles)
					
					# move or copy file to the appropriate subfolder within this bucket
					move(filepath, dest + '/' + sortpath)
					
					# are we replacing a canonical photo?
					if replacefile:
						if preserve:
							# log this action and move replaced photo into /low
							replacepath = bucket + metapath + '/low'
							replacepath += '/' + unique_name(os.path.basename(replacefile), dest + '/' + replacepath)
							log('             [REPLACED] %s/%s [TO] %s' % (sortbase, os.path.basename(replacefile), replacepath), logfiles)
							move(replacefile, dest + '/' + replacepath, copy=False)
						else:
							# log this action and delete the replaced photo
							log('             [REPLACED] %s/%s' % (sortbase, os.path.basename(replacefile)), logfiles)
							os.unlink(replacefile)
					
					if bucket == src_bucket:
						tally['no_match'] += 1
					elif subpath == '/low':
						tally['meta_match_low'] += 1
					elif subpath == '/unk':
						tally['meta_match_unk'] += 1
					elif subpath == '/alt':
						tally['meta_match_alt'] += 1
					else:
						tally['meta_match_rep'] += 1
					break
			else:
				# no metadata match found
				sortbase = src_bucket + metapath + subpath
				sortname = matchfile + ' [%s].%s%s' % (filename, src_bucket, extension)
				sortpath = sortbase + '/' + sortname
				
				# log this action
				logfile = dest + '/' + sortbase + '/_sort.log.txt'
				log('  No-Match : %s [MOVED TO] %s' % (relpath, sortpath), logfile)
				
				# move or copy file to the appropriate subfolder within this source's bucket
				move(filepath, dest + '/' + sortpath)
				tally['no_match'] += 1
		else:
			# file is not an image
			sortbase = src_bucket + '/noimage'
			sortpath = sortbase + '/' + relpath
			
			# log this action
			logfile = dest + '/' + sortbase + '/_sort.log.txt'
			log(' Non-Image : %s [MOVED TO] %s' % (relpath, sortpath), logfile)
			
			# move or copy file to 'noimage' subfolder within this source's bucket
			move(filepath, dest + '/' + sortpath)
			tally['no_meta'] += 1
		
		tally['files'] += 1
	
	# print final tallies
	log("\n------------------------")
	log("%4d Unmatched Files" % tally['no_match'])
	log("%4d Exact Matches" % tally['file_match'])
	log("%4d Replaced Meta Matches" % tally['meta_match_rep'])
	log("%4d Alternate Meta Matches" % tally['meta_match_alt'])
	log("%4d Unknown Meta Matches" % tally['meta_match_unk'])
	log("%4d Lower Quality Meta Matches" % tally['meta_match_low'])
	log("------------------------")
	log("%4d Corrupt Files Encountered" % tally['corrupt'])
	log("------------------------")
	log("%4d Non-Images" % tally['no_meta'])
	log("%4d Total Files Processed" % tally['files'])
	log("------------------------\n\n\n")


def restore_images(src, dest, copy=True, verbose=True):
	'''
	restore image filenames generated by sort_images
	'''
	
	# ensure the source and destination exist
	if not os.path.isdir(src) or not os.path.isdir(dest):
		raise IOError('Source or destination directory not found')
	
	# generate our log closure
	log = logger(dest + '/_restore.log.txt', verbose)
	
	# generate our move closure
	if (src == dest):
		copy = False
	move = mover(copy)
	
	# iterate through all files within src
	files = get_all_files(src)
	tally = {
		'files': 0,
		'skipped': 0,
		'renamed': 0,
		'copied': 0
	}
	
	# to prevent recursion don't write the log file until we've listed our files
	log("Reading from '%s'...\n" % (src))
	log("Restoring filenames...\n")
	
	for filepath in files:
		# generate relative file path
		relpath = os.path.dirname(re.sub('^%s/?' % src, '', filepath))
		
		# capture filename and extension
		filename = os.path.basename(filepath)
		fileroot, extension = os.path.splitext(filename)
		
		# determine the original filename
		canonical = re.search(" \[([^\[]*)\]", fileroot)
		if canonical:
			newname = canonical.group(1)
		else:
			newname = filename
		newroot, newext = os.path.splitext(newname)
		
		# make note of files with unsure original filenames
		unsure = ''
		if (newroot[0] == '?'):
			newroot = newroot.lstrip('?')
			unsure = '?'
		
		# normalize previous attempts to modify a file name for uniqueness
		newroot = re.sub(r"^(IMG_\d+)-\d{1,2}$", r"\1", newroot, 1)
		
		# ensure the target has the same file extension as the source
		if extension.lower() != newext.lower():
			newext += extension
		
		# compile our new filename
		newname = newroot + unsure + newext
		
		# ensure the filename is unique, don't do anything if there's nothing to rename
		if newname == filename and src == dest:
			log('   Skipped : %s/%s' % (relpath, filename))
			tally['skipped'] += 1
		else:
			newname = unique_name(newname, dest + '/' + relpath)
			newpath = dest + '/' + relpath + '/' + newname
			move(filepath, newpath)
			if newname == filename:
				log('    Copied : %s/%s [TO] %s/%s' % (relpath, filename, relpath, newname))
				tally['copied'] += 1
			else:
				log('   Renamed : %s/%s [TO] %s/%s' % (relpath, filename, relpath, newname))
				tally['renamed'] += 1
		
		tally['files'] += 1
		
	# print final tallies
	log("\n------------------------")
	log("%4d Renamed Files" % tally['renamed'])
	log("%4d Copied Files" % tally['copied'])
	log("%4d Skipped Files" % tally['skipped'])
	log("------------------------")
	log("%4d Total Files Processed" % tally['files'])
	log("------------------------\n\n\n")


def fix_images(src, dest, copy=True, verbose=True, test=True):
	'''
	correct image date metadata
	
	TO DO: ensure exiv2 is installed `brew install exiv2`
	'''
	
	# ensure the source and destination exist
	if not os.path.isdir(src) or not os.path.isdir(dest):
		raise IOError('Source or destination directory not found')
	
	# generate our log closure
	log = logger(dest + '/_fix.log.txt', verbose)
	
	# generate our move closure
	if (src == dest):
		copy = False
	move = mover(copy)
	
	if test:
		def log(x, *y): print x
		def move(*x): pass
	
	# iterate through all files within src
	files = get_all_files(src)
	tally = {
		'files': 0,
		'skipped': 0,
		'fixed': 0,
		'noimage': 0
	}
	
	# to prevent recursion don't write the log file until we've listed our files
	log("Reading from '%s'...\n" % (src))
	log("Fixing Image Dates%s...\n" % (' (Test Run)' if test else ''))
	
	for filepath in files:
		# generate relative file path
		relpath = os.path.dirname(re.sub('^%s/?' % src, '', filepath))
		destpath = (dest + '/' + relpath) if relpath else dest
		filename = os.path.basename(filepath)
		modpath = destpath + '/' + filename
		
		# move/copy the source to the destination
		if src != dest:
			filename = unique_name(filename, destpath)
			move(filepath, destpath + '/' + filename)
		
		# attempt to obtain file meta-data
		filemeta = get_file_metadata(filepath)
		
		# ensure file is an image
		if filemeta:
			subdir = os.path.basename(os.path.dirname(filepath))
			
			# check whether it needs to be "fixed"
			if subdir != '_backup' and not filemeta['date_taken'] and filemeta['date_modified'] and filemeta['date_modified'] > filemeta['file']['mtime']:
				# log our attempt to fix this image
				log('    Fixing : %s (exif: %s [TO] mtime: %s)' % (modpath, filemeta['date_modified'], filemeta['file']['mtime']))
				
				if not test:
					# copy the file to '/backup' directory
					backupname = unique_name(filename, destpath + '/_backup')
					move(filepath, destpath + '/_backup/' + backupname, copy=True)
					
					# copy filesystem metadata
					stat = os.stat(modpath)
					
					# modify EXIF data
					# if 'Exif.Image.DateTime' in run_cmd('exiv2 -g "Exif.Image.DateTime" "%s"' % modpath):
					val = filemeta['file']['mtime'].strftime('%Y:%m:%d %H:%M:%S')
					run_cmd('exiv2 -M "set Exif.Image.DateTime Ascii %s" "%s"' % (val, modpath))
					
					# modify XMP data if necessary
					if 'Xmp.xmp.ModifyDate' in run_cmd('exiv2 -g "Xmp.xmp.ModifyDate" "%s"' % modpath):
						val = filemeta['file']['mtime'].strftime('%Y-%m-%dT%H:%M:%S')
						run_cmd('exiv2 -M "set Xmp.xmp.ModifyDate %s" "%s"' % (val, modpath))
					
					# reapply original filesystem metadata
					os.utime(modpath, (stat.st_atime, stat.st_mtime))
				
				tally['fixed'] += 1
			else:
				# no fix needed, log as a 'skipped' file
				log('   Skipped : %s' % modpath)
				tally['skipped'] += 1
		else:
			# not an image, log as a 'non-image' file
			log(' Non-Image : %s' % modpath)
			tally['noimage'] += 1
		
		tally['files'] += 1
		
	# print final tallies
	log("\n------------------------")
	log("%4d Fixed Images" % tally['fixed'])
	log("%4d Skipped Images" % tally['skipped'])
	log("%4d Non-Image Files" % tally['noimage'])
	log("------------------------")
	log("%4d Total Files Processed" % tally['files'])
	log("------------------------\n\n\n")


def replace_image(src, dest, copy=True, verbose=True):
	'''
	transcribe dest file's name and mtime onto src and then replace dest
	'''
	
	# ensure the source and destination exist
	if not os.path.isfile(src) or not os.path.isfile(dest):
		raise IOError('Source or destination directory not found')
	
	# get image metadata
	srchash  = get_file_hash(src)[:6:]
	srcmeta  = get_file_metadata(src)
	destmeta = get_file_metadata(dest)
	
	# build new image filename
	if not srcmeta or not destmeta:
		raise IOError('Unable to process provided files')
	
	# parse directory structure for src and dest
	srcfile  = os.path.basename(src)
	destfile = os.path.basename(dest)
	srcbase  = os.path.abspath(os.path.dirname(src))
	destbase = os.path.abspath(os.path.dirname(dest))
	srcpath  = ''
	destpath = ''
	srcmode  = ''
	destmode = ''
	
	match = re.search(r'^(.*)(/exif|/noexif|/noimage)(/\d{4}/\d{2}|/unk|/low|/alt)$', srcbase)
	if match:
		srcbase = match.group(1)
		srcmode = match.group(2)
		srcpath = match.group(3)
	srcbucket = os.path.basename(srcbase)
	
	match = re.search(r'^(.*)(/exif|/noexif|/noimage)(/\d{4}/\d{2}|/unk|/low|/alt)$', destbase)
	if match:
		destbase = match.group(1)
		destmode = match.group(2)
		destpath = match.group(3)
	destbucket = os.path.basename(destbase)
	
	# generate our log closure
	log = logger(destbase + '/_sort.log.txt', verbose)
	
	logfiles = []
	if srcbase != destbase:
		logfiles.append(srcbase + '/_sort.log.txt')
	if srcpath:
		logfiles.append(srcbase + srcmode + srcpath + '/_sort.log.txt')
	if destpath and destbase + destmode + destpath != srcbase + srcmode + srcpath:
		logfiles.append(destbase + destmode + destpath + '/_sort.log.txt')
	
	# generate our move closure
	move = mover(copy)
	
	# scrape canonical name from dest and build a new filename
	match = re.search(" \[([^\[]*)\]", destfile)
	if match and destpath:
		canon = match.group(1)
		if srcmeta['date_taken']:
			date = srcmeta['date_taken']
		else:
			date = destmeta['file']['mtime']
		res = sorted((srcmeta['width'], srcmeta['height']))
		
		match = re.search("\]\.(.*?)\..+", srcfile)
		if match:
			srcbucket = match.group(1)
		
		newname = date.strftime('%Y.%m.%d %H.%M.%S-') + '%s %s' % (str(srcmeta['hdr']), srcmeta['signature'][0:4])
		newname += ' %04dx%04d %s %s' % (res[1], res[0], srcmeta['status'], srchash)
		newname += ' [%s].%s%s' % (canon, srcbucket, os.path.splitext(srcfile)[1].lower())
	else:
		newname = destname
	
	newname = unique_name(newname, destbase + destmode + destpath)
	
	# log and perform this action
	log('', logfiles)
	log('    Manual : %s/%s [MOVED TO] %s/%s' % (srcmode + srcpath, srcfile, destmode + destpath, newname), logfiles)
	print
	
	move(src, destbase + destmode + destpath + '/' + newname)
	shutil.copystat(dest, destbase + destmode + destpath + '/' + newname)
	
	if destpath and destpath != '/low':
		log('             [REPLACED] %s/%s [TO] %s/%s' % (destmode + destpath, destfile, destmode + '/low', destfile), logfiles)
		move(dest, destbase + destmode + '/low/' + destfile, False)


def assert_dir(dirs, message=None):
	'''
	ensures a directory exists at each path specified in dirs.
	
	raises an exception if a directory does not exist and it is unable to create one.
	'''
	if not type(dirs) == list:
		dirs = [dirs]
	for dir in dirs:
		try:
			os.makedirs(dir)
		except OSError:
			if not os.path.isdir(dir):
				if not message:
					message = "Unable to create needed directory ('%s')" % dir
				raise IOError(message)


def unique_name(name, path):
	'''
	return a non-existing file or directory name within a given path
	
	if a suggested name already exists, appends a number to it to make it unique
	'''
	i = 1
	if os.path.isdir(path):
		dir_list = [x.lower() for x in os.listdir(path)]
		root, ext = os.path.splitext(name)
		while name.lower() in dir_list:
			name = root + '-' + str(i) + ext
			i += 1
	return name


def get_all_files(dir):
	'''
	returns a list of all file paths relative to `dir`
	'''
	all = []
	for root, dirs, files in os.walk(dir):
		all += map(lambda file: root + '/' + file, files)
	return all


def get_file_metadata(filename):
	'''
	returns a all available file metadata if file is an image, or None if non-image
	'''
	# return none if the file is not an image
	try:
		img = Image.open(filename)
		width, height = img.size
	except (IOError):
		return None
	
	# check for image type and jpeg file integrity
	jpeginfo = run_cmd('jpeginfo -c "%s"' % filename)
	
	# if the image is a jpeg file, get more info
	if 'not a jpeg file' not in jpeginfo.lower():
		status = re.search("\[([^\]]*)\][^\[]*$", jpeginfo)
		status = status.group(1) if status else 'UNKNOWN'
		if status == 'OK':
			corrupt = 0
		elif status == 'WARNING':
			corrupt = 2
		elif status == 'ERROR':
			corrupt = 3
		else:
			corrupt = 1
		
		# collect EXIF data
		try:
			exif = img._getexif() or {}
			meta = {
				ExifTags.TAGS[k]: v
				for k, v in exif.items()
				if k in ExifTags.TAGS
			}
		except (IndexError, AttributeError):
			if corrupt < 2:
				status = 'META_ERROR'
				corrupt = 3
				meta = {}
	else:
		status = 'UNKNOWN'
		corrupt = 1
		meta = {}
	
	# process and format all exif dates
	try:
		if 'DateTime' in meta:
			meta['DateTime'] = datetime.strptime(meta['DateTime'], '%Y:%m:%d %H:%M:%S')
		else:
			meta['DateTime'] = None
		
		if 'DateTimeOriginal' in meta:
			meta['DateTimeOriginal'] = datetime.strptime(meta['DateTimeOriginal'], '%Y:%m:%d %H:%M:%S')
		else:
			meta['DateTimeOriginal'] = None
		
		if 'DateTimeDigitized' in meta:
			meta['DateTimeDigitized'] = datetime.strptime(meta['DateTimeDigitized'], '%Y:%m:%d %H:%M:%S')
		else:
			meta['DateTimeDigitized'] = None
	except (TypeError, ValueError):
		meta['DateTime'] = None
		meta['DateTimeOriginal'] = None
		meta['DateTimeDigitized'] = None
	
	# generate a psudo-unique signature using obscure exif data
	sign = ''
	sign += str(meta['Make']) if 'Make' in meta else ''
	sign += str(meta['Model']) if 'Model' in meta else ''
	if 'FocalLength' in meta and len(meta['FocalLength']) >= 2:
		sign += ' %1.4f' % (float(meta['FocalLength'][0]) / float(meta['FocalLength'][1]))
	if 'ExposureTime' in meta and len(meta['ExposureTime']) >= 2:
		sign += ' %1.4f' % (float(meta['ExposureTime'][0]) / float(meta['ExposureTime'][1]))
	if 'ApertureValue' in meta and len(meta['ApertureValue']) >= 2:
		sign += ' %1.4f' % (float(meta['ApertureValue'][0]) / float(meta['ApertureValue'][1]))
	sign = hashlib.md5(sign).hexdigest()
	
	# compile all available image information
	info = {
		'hdr':     int(meta['CustomRendered']) if 'CustomRendered' in meta else 0,
		'width':   int(width),
		'height':  int(height),
		'status':  status,
		'corrupt': corrupt,
		'signature': sign,
		'date_taken':     meta['DateTimeOriginal'],
		'date_modified':  meta['DateTime'],
		'date_digitized': meta['DateTimeDigitized'],
		'file': {
			'ctime': datetime.fromtimestamp(os.path.getctime(filename)),
			'mtime': datetime.fromtimestamp(os.path.getmtime(filename)),
			'atime': datetime.fromtimestamp(os.path.getatime(filename))
		},
		'meta': meta
	}
	
	return info

def run_cmd(command):
	'''
	run the provided shell command and return the result
	'''
	return subprocess.Popen(command, stdout=subprocess.PIPE, shell=True).stdout.read()


def get_file_hash(filepath, blocksize=65536):
	'''
	return a md5 hash hex string of the target file
	'''
	afile = open(filepath, 'rb')
	hasher = hashlib.md5()
	buf = afile.read(blocksize)
	while len(buf) > 0:
		hasher.update(buf)
		buf = afile.read(blocksize)
	afile.close()
	return hasher.hexdigest()


def mover(copy_default=True):
	'''
	return a function which can be used to move files, enclosing the provided parameters.
	'''
	def move(src, dest, copy=None, overwrite=False):
		# ensure the destination directory exists
		assert_dir(os.path.dirname(dest))
		
		# ensure the source file exists and the destination file does not
		if not os.path.isfile(src):
			raise Exception("No such file exists ('%s')" % src)
		if not overwrite and os.path.isfile(dest):
			raise Exception("File already exists ('%s')" % dest)
		
		# allow copy param to override default copy/move setting
		if copy or (copy_default and copy != False):
			# copy file and stats
			shutil.copyfile(src, dest)
			shutil.copystat(src, dest)
		else:
			# move file and copy stats
			stat = os.stat(src)
			shutil.move(src, dest)
			os.utime(dest, (stat.st_atime, stat.st_mtime))
	return move


def logger(path, verbose=True, mirror_pretext=None):
	'''
	return a function which can be used to append to logs, enclosing the provided parameters.
	'''
	used = [path]
	
	def log(message, mirrors=None, echo=None):
		
		# allow echo to override verbose setting if specified
		if echo or (verbose and echo != False):
			print message
		
		if not mirrors:
			mirrors = []
		elif not type(mirrors) == list:
			mirrors = [mirrors]
		
		logfiles = [path] + mirrors
		for logfile in logfiles:
			assert_dir(os.path.dirname(logfile))
			with open(logfile, 'a') as res:
				if not (logfile in used):
					used.append(logfile)
					if mirror_pretext:
						res.write(mirror_pretext + "\n")
				res.write(message + "\n")
	return log


if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		print "\nOpteration Aborted\n"