#!/user/bin/env python
import os
import getopt

class ParserFiles(object):
	in_file = ""
	out_file = ""
	log_file = ""
	log_path = ""
	cwd_path = ""
	in_path = ""
	out_path = ""

	def __init__(self, infile = None):
		if infile !=  None:
			self.in_file = os.path.basename(infile)
			self.cwd_path = os.getcwd()
			if os.path.isabs(infile):
				self.in_path = infile
			else :
				self.in_path = os.path.normpath(os.path.join(self.cwd_path, infile))
			if not os.path.exists(self.in_path):
				print "ParserFiles error: input file does not exist " + self.in_path

	def set_output_file(self, outfile):
		self.out_file = os.path.basename(outfile)
		if os.path.isabs(outfile):
			self.out_path = outfile
		else :
			self.out_path = os.path.normpath(os.path.join(self.cwd_path, outfile))

	def set_log_file(self, logfile):
		self.log_file = os.path.basename(logfile)
		if os.path.isabs(logfile):
			self.log_path = logfile
		else :
			self.log_path = os.path.normpath(os.path.join(self.cwd_path, logfile))
	def get_input_path(self):
		return self.in_path

	def get_output_path(self):
		return self.out_path

	def get_log_path(self):
		return self.log_path

	def show_info(self):
		print ""
		print "ParserFiles input file [%s]" % self.in_path
		print "ParserFiles output file [%s]" % self.out_path


def main(argv):
	inputfile = ''
	outputfile = ''
	try:
		(opts, args) = getopt.getopt(argv, "hi:o:", ["ifile=", "ofile="])
	except getopt.GetoptError:
		print os.path.basename(__file__) + " -i <inputfile> -o <outputfile"
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print os.path.basename(__file__) + " -i <inputfile> -o <outputfile"
			sys.exit()
		elif opt in ("-i", "--ifile"):
			inputfile = arg
		elif opt in ("-o", "--ofile"):
			outputfile = arg

	pfiles = ParserFiles(inputfile)
	pfiles.set_output_file(outputfile)

	return pfiles



