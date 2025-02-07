#!/bin/python3
#	PixelBootloader.py:
# 		A loader module for IDA Pro that can handle the abl.bin binary 
#		for Google Pixel Phones, tested against abl binaries from:
#		-	Pixel 6 / 6a / 6 pro
#		-	Pixel 7 / 7 pro
#		-       Pixel 8
#
#		The loader was tested in IDA Pro version 7.6 - 8.3
#   Author:
#       Abdullah (https://github.com/0xAbby) 20-Mar-2023 - Initial Implementation

import idc
import idaapi
import ida_ida
import ida_entry
import ida_segment
import ida_name
import ida_bytes
import ida_ua
import ida_typeinf
import os
import struct
from time import sleep

# Read function table and set function names.
def resolve_func_table(offset):
	'''functions table (each entry is 16 bytes)
		 Function offset:  64bit
		 function size:    32bit
		 func name offset: 32bit
	'''
	size_offset = ida_bytes.get_word(offset - 0xC)
	print("# PixelAblLoader: size of function table: \t", hex(size_offset))
	print("# PixelAblLoader: Function table start:  \t", hex(offset))
	
	address_table_start = offset
	address_table_end = offset + (size_offset * 16)
	
	# end of function address table followed by a table for function names
	print("# PixelAblLoader: Functions table ends: \t", hex(address_table_end))

	# preparing to set function table struct type.
	#ida_ida.inf_set_cc_cm(ida_typeinf.CM_N64)   # compiler pointer size
	_type = idc.parse_decl("func_table_entry", 0)
	
	# For each function in the table, get its offset,
	# Tell IDA to analyze/make it code, then set func name.


	output_csv = open("func_csv", "w")
	while address_table_start < address_table_end:
    	# get function offset
		func_offset = ida_bytes.get_bytes(address_table_start, 8)

    	# read function address
		func_offset_bytes = int.from_bytes(func_offset, "little")

    	# read offset value of  "function name"
		string_offset = ida_bytes.get_bytes(address_table_start+12, 4)

    	# find function name (names offset + names table)
		func_name_addr = int.from_bytes(string_offset, "little") + address_table_end
		idc.create_strlit(func_name_addr, idc.BADADDR)
		func_name_len = ida_bytes.get_max_strlit_length(func_name_addr, idc.STRTYPE_C, ida_bytes.ALOPT_IGNHEADS)
		funct_str = ida_bytes.get_strlit_contents(func_name_addr, func_name_len, idc.STRTYPE_C).decode()
		csv_entry = "" + '\"' + funct_str + '\", \"' + hex(func_name_addr) + "\"\n"
		output_csv.write(csv_entry)
        
		#if funct_str == "pixel_loader_entry":
        #	ida_entry.add_entry(func_offset_bytes, func_offset_bytes, funct_str, True, 0)

        # analyze/set function to code, set name, mark offset / value in table.
		ida_ua.create_insn(func_offset_bytes)
		ida_name.set_name(func_offset_bytes, funct_str, idaapi.SN_NOWARN | idaapi.SN_NOCHECK | ida_name.SN_FORCE)
		idc.op_plain_offset(address_table_start, 0, 0)
		ida_bytes.create_dword(address_table_start+8, 4) 
		ida_bytes.create_dword(address_table_start+12, 4) 
        
        # Set data structure for each function entry
		idc.apply_type(address_table_start, _type, 0)
        
        # next entry in functions table (entry is 16 byte long)
		address_table_start += 16
	output_csv.close()

  
	

def get_file_size(blob):
	blob.seek(0, os.SEEK_END)
	return blob.tell()

# to supress a warning message.
def move_segm(a,b,c,d):
	pass
 
# Determine whether the blob is Pixel ABL file or not
def accept_file(blob, filename):
	buffer = blob.read(0x70)
	# find instruction bytes for these operations int 
	# the first 0x70 bytes (this needs to be improved somehow in the future)
	# 5C 42 38 D5    MRS   X28, CurrentEL
	# 09 10 38 D5    MRS   X9, SCTLR_EL1
	# 09 10 18 D5    MSR   SCTLR_EL1, X9
	mrs_bytes = [b'\xD5\x38\x42\x5C', b'\xD5\x38\x10\x09', b'\xD5\x18\x10\x09' ]
	
	for bytes in mrs_bytes:
		if not buffer.find(bytes):
			return 0
			
	
	return {"format": "Pixel bootloader (ABL)", 
			"processor": "arm", 
			"options":1 | idaapi.ACCEPT_FIRST}

def create_segment(start, end, bitness, name, segType):
	seg = idaapi.segment_t()
	seg.start_ea = start
	seg.end_ea =  end
	if segType == "CODE":
		seg.perm = idaapi.SEGPERM_READ | idaapi.SEGPERM_EXEC  | idaapi.SEGPERM_WRITE
	else:
		seg.perm = idaapi.SEGPERM_READ | idaapi.SEGPERM_WRITE
	seg.is_64bit = True
#	seg.align = 3
	seg.bitness = bitness
	
	idaapi.add_segm_ex(seg, name, segType, 0)



# given a start/end address, search for 'bytes_str'
def search_bytes(start_ea, end_ea, bytes_str):

	mypattern = idaapi.compiled_binpat_vec_t()
	
	#print("# PixelAblLoader: search start: \t", hex(start_ea))
	#print("# PixelAblLoader: search end: \t", hex(end_ea))

	str_pattern = idaapi.parse_binpat_str(mypattern, start_ea, bytes_str, 16, 0)
	if str_pattern is None:
		return False

	offset_found = idaapi.bin_search(start_ea, end_ea, mypattern, idaapi.BIN_SEARCH_CASE)
   
	if offset_found == idaapi.BADADDR:
		print("# PixelAblLoader: search failed")
		return False

	return offset_found
 
# search for and return offset of function table, and offset where code segment ends
def find_func_table(filesize_):
	data_search_offset = filesize_ - int(filesize_ * 0.2) 
	func_table_offset = search_bytes(data_search_offset, filesize_, "FFFF0000F8800000")

	if func_table_offset:
		# reading size of functions table 
		func_table_size = int.from_bytes(ida_bytes.get_bytes(func_table_offset - 0xC, 4) , "little")
		
		# calculating offset of table end 
		func_table_end = func_table_offset + (func_table_size * 16)
		
		# read address where code segment ends
		end_of_code_segment = int.from_bytes(ida_bytes.get_bytes(func_table_end - 0x10, 8) , "little")
		
		print("# PixelAblLoader: Functions table at: \t", hex(func_table_offset))
		print("# PixelAblLoader: offset of end of code: \t", hex(end_of_code_segment))
		
		return func_table_offset, end_of_code_segment
	else:
		print('''# PixelAblLoader: search for functions table offset failed,\
		probably not valid ABL, or newer unsupported version''')
		return False, False


def create_structs():
	def_structs = {
	"""struct fastboot_table_entry { 
		unsigned __int64 *command_name;  
		unsigned __int64 unk1;  
		unsigned __int64 unk2;  
		void *func_pointer; 
		};
		""",
	""" struct fastbootvar_table_entry {
		  unsigned __int64 *command_name;
		  unsigned __int64 unk;
		  void 	  *command_pointr;
		};
	""",
	"""struct func_table_entry {
		unsigned __int64 *func_pointer;
		unsigned __int32 func_size;
		unsigned __int32 name_offset;
		};
		"""}

	print("# PixelAblLoader: creating C-style struct defintions.")
	for struct in def_structs:
		ida_typeinf.idc_parse_types(struct, 0)

def find_sig(sig, ea_start, ea_end):

    while ea_start != idaapi.BADADDR:
        
        ea_start = idaapi.find_binary(ea_start, ea_end, sig, 16, idaapi.SEARCH_DOWN)
        insn = idaapi.insn_t()
        if ea_start != idaapi.BADADDR:
            if idaapi.decode_insn(insn, ea_start):
                if (insn.itype in [idaapi.ARM_stp, idaapi.ARM_mov, idaapi.ARM_sub]):
                    ida_ua.create_insn(ea_start)
                    idaapi.add_func(ea_start, idaapi.BADADDR)
            ea_start += 4

def find_code_by_prologue(ea_start, ea_end):
    prologue = {"fd 7b 01 ?",
                "fd 7b b8 ?",
                "fd 7b b9 ?",
                "fd 7b bb ?",
                "fd 7b ba ?",
                "fd 7b be ?",
                "fd 7b bc ?",
                "fd 7b bd ?",
                "fd 7b bf ?",
                "ff c3 02 ?",
                "ff c3 00 ?",
                "ff 03 03 ?",
                "ff 03 01 ?",
                "ff 43 01 ?",
                "ff 83 02 ?",
                "ff 83 01 ?" }


    for sig in prologue:
        find_sig(sig, ea_start, ea_end)

def find_possible_code_end(ea, maxea):
    sig = "00 " * 0x230
    while ea != idaapi.BADADDR:
        ea = idaapi.find_binary(ea, maxea, sig, 16, idaapi.SEARCH_DOWN)
        if ea != idaapi.BADADDR:
            #print("Found at ", hex(ea))
            return ea
    return 0

def resolve_fastboot_table():
	pass

# main loader function
def load_file(binaryBlob, neflags, format):
	base_addr = 0xFFFF0000F8800000
	
	# set processor as ARM (little endian) / 64 bit mode
	idaapi.set_processor_type('arm', idaapi.SETPROC_LOADER)
	ida_ida.inf_set_64bit(True)
	
	filesize_ = get_file_size(binaryBlob)
	create_segment(0, filesize_, 2, "BLOB", "DATA")
	binaryBlob.seek(0)
	binaryBlob.file2base(0, 0, filesize_, False)
    
	
	# find function table / and end of code / offset where code segment ends 
	func_table_offset, end_of_code_segment = find_func_table(filesize_) 
	
	if not func_table_offset:
		print("# PixelAblLoader: failed, existing")
		print("# continuing without function table")
        
		print("# Searching for end of CODE section")
		possible_code_end = find_possible_code_end( int(filesize_*0.4), int(filesize_*0.57))
        
		if possible_code_end != 0:
			create_segment(0, (possible_code_end), 2, "ABL_CODE", "CODE")
			create_segment((possible_code_end), filesize_, 2, "ABL_DATA", "DATA")
			ida_segment.rebase_program(base_addr, 0 )
		else:
			print("# No end of CODE section, treat segment as code")
			create_segment(0, filesize_, 2, "ABL", "CODE")
			ida_segment.rebase_program(base_addr, 0)
        
		ida_ua.create_insn(base_addr)
		idaapi.add_func(base_addr, idaapi.BADADDR)    
		find_code_by_prologue(base_addr, base_addr+filesize_)

	elif func_table_offset:
		# adjust code and data segments / update base address
        
		create_segment(0, (end_of_code_segment - base_addr), 2, "ABL_CODE", "CODE")
		create_segment((end_of_code_segment - base_addr), filesize_, 2, "ABL_DATA", "DATA")
		ida_segment.rebase_program(base_addr, 0 )	
        
		# create releavant data structures from C-style definitions
		create_structs()
        
		# set function' names / and tell ida pro to make each function into code 
		resolve_func_table(func_table_offset + base_addr)
        
		# find and set fastboot commands and var table structs
		resolve_fastboot_table()
		
	return 1
