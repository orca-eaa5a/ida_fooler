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

origin_api = ["CreateProcessA", "IsDebuggerPresent", "GetSystemTimeAsFileTime"]
disguised_api = ["CreateThread", "GetACP", "MapViewOfFileEx"]
target_file = "./bin/target.exe"
k32_dll = "./bin/kernel32.dll"
disguised_api_va = 0

shellcode_addr = {
    "va" : 0,
    "rva" : 0,
    "offset": 0
}

recover_api_va_va = 0
target_pe = utils.PETool(fname=target_file)
k32_pe = utils.PETool(fname=k32_dll)
real_api_va_list = k32_pe.get_export_api_rva(origin_api)
target_pe.change_import_api(target_api_list=origin_api, disguised_api_list=disguised_api)
# Make the resource data used for fool ida

# First, Create comparison data to check if the API has been forged.
fmt_disguised_api_list = b''
for api in disguised_api:
    fmt_disguised_api_list += api.encode("ascii") + bytes(1)
fmt_disguised_api_list += bytes(1) # <-- End Signature

fmt_disguised_api_list = utils.formatting_16byte(_data=fmt_disguised_api_list)

# Next, if checked API turns out that has been forged, Creates recovery data for recovery.
fmt_recover_api_va_list = b''
for api_va in real_api_va_list:
    fmt_recover_api_va_list += struct.pack("<I", api_va)
fmt_recover_api_va_list += bytes(4)

fmt_recover_api_va_list = utils.formatting_16byte(_data=fmt_recover_api_va_list)
fmt_disguised_api_struct_list = fmt_disguised_api_list + fmt_recover_api_va_list

# First, Write the disguised_api
candidate_sections = [".rdata", ".data", ".rdata"]
for sec_name in candidate_sections:
    section = target_pe.get_section_header_by_name(sec_name)
    if section:
        actual_allocate_vmem_size = target_pe.get_actual_allocated_vmem_size(section_hdr=section)
        available_size = actual_allocate_vmem_size - section.SizeOfRawData
        if available_size > len(fmt_disguised_api_struct_list):
            section_offset = section.PointerToRawData
            section_bin_origin = section_bin_origin = target_pe.pe.__data__[section_offset : section_offset + section.SizeOfRawData]
            section_bin_rewrite = section_bin_origin + fmt_disguised_api_struct_list # Write the Disguised api at the end of the section
            write_offset, number_of_bytes_written = target_pe.write_bytes_at_offset(offset=target_pe.size_of_current_raw, data=bytes(section_bin_rewrite), secure_insert=True)
            section.PointerToRawData=write_offset
            section.SizeOfRawData=len(section_bin_rewrite)

            disguised_api_va = section.VirtualAddress + len(section_bin_origin) + target_pe.pe.OPTIONAL_HEADER.ImageBase
            recover_api_va_va = disguised_api_va + len(fmt_disguised_api_list)
            break
    else:
        continue

shellcode = utils.Shellcode(fname="./bin/ida_fooler.bin")
shellcode.pass_parameters(api_set_va=disguised_api_va, recover_set_va=recover_api_va_va)

# First, insert shellcode in exist section which has avaliable memory space
already_write = False
for section in target_pe.pe.sections:
    if section.Name.decode("ascii").strip('\x00') in [".rdata", ".idata", ".text"]:
        continue

    actual_allocate_vmem_size = target_pe.get_actual_allocated_vmem_size(section_hdr=section)
    available_size = actual_allocate_vmem_size - section.SizeOfRawData

    if available_size > shellcode.shellcode_len:
        # use current section
        section_offset = section.PointerToRawData
        section_bin_origin = target_pe.pe.__data__[section_offset : section_offset + section.SizeOfRawData]
        padded_bin_len = available_size - section.SizeOfRawData - len(shellcode.shellcode)
        if padded_bin_len < 0:
            padded_bin_len = 0
        section_bin_rewrite = section_bin_origin + bytes(padded_bin_len) + shellcode.shellcode
        write_offset, number_of_bytes_written = target_pe.write_bytes_at_offset(target_pe.size_of_current_raw, bytes(section_bin_rewrite), secure_insert=True)

        # Manifulate section header
        section.PointerToRawData=write_offset
        shellcode_addr["va"] = target_pe.pe.OPTIONAL_HEADER.ImageBase + section.SizeOfRawData + padded_bin_len
        shellcode_addr["rva"] = section.VirtualAddress + section.SizeOfRawData + padded_bin_len
        shellcode_addr["offset"] = section.PointerToRawData + section.SizeOfRawData + padded_bin_len
        section.SizeOfRawData = number_of_bytes_written

        section.Characteristics = 0x20000000 | 0x40000000 | 0x80000000 | 0x00000040# EXECUTE_READWRITE
        already_write = True

        break

if not already_write:
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
    last_section_hdr = target_pe.get_last_section_header()
    actual_allocated_size = target_pe.get_actual_allocated_vmem_size(section_hdr=last_section_hdr)

    # Append .orca section
    new_section_offset, number_of_bytes_written = target_pe.write_bytes_at_offset(target_pe.size_of_current_raw, bytes(shellcode.shellcode), secure_insert=True)

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

    if shellcode.shellcode_len % target_pe.file_alignment == 0:
        if shellcode.shellcode_len >= target_pe.file_alignment:
            new_section_raw_size = shellcode.shellcode_len
        else:
            new_section_raw_size = target_pe.file_alignment
    else:
        n = (int(shellcode.shellcode_len/target_pe.file_alignment)+1)
        new_section_raw_size = target_pe.file_alignment * n

    if new_section_raw_size <= target_pe.section_alignment:
        new_section_virtual_size = target_pe.section_alignment
    else:
        n = (int(shellcode.shellcode_len/target_pe.section_alignment)+1)
        new_section_virtual_size = target_pe.section_alignment * n
    
    new_section_hdr = SectionHeader()
    new_section_hdr.name = ".orca".encode("utf-8")
    new_section_hdr.VirtualSize = new_section_virtual_size
    new_section_hdr.PointerToRawData = new_section_offset
    new_section_hdr.VirtualAddress = last_section_hdr.VirtualAddress + actual_allocated_size
    new_section_hdr.SizeOfRawData = new_section_raw_size
    new_section_hdr.Characteristics = 0x20000000 | 0x40000000 | 0x80000000 | 0x00000040# EXECUTE_READWRITE
    _section_bin = bytes(new_section_hdr)

    shellcode_addr["va"] = target_pe.pe.OPTIONAL_HEADER.ImageBase + new_section_hdr.VirtualAddress
    shellcode_addr["rva"] = new_section_hdr.VirtualAddress
    shellcode_addr["offset"] = new_section_hdr.PointerToRawData

    # get last section_hdr
    sections:List[SectionStructure] = target_pe.pe.sections
    idx = 0
    last_section = None
    nt_headers_offset = target_pe.pe.DOS_HEADER.e_lfanew
    optional_header_offset = nt_headers_offset+4+target_pe.pe.FILE_HEADER.sizeof()
    section_hdr_offset = optional_header_offset + target_pe.pe.FILE_HEADER.SizeOfOptionalHeader
    section = SectionStructure(target_pe.pe.__IMAGE_SECTION_HEADER_format__, pe=target_pe.pe)
    last_section_offset = 0
    for i in range(target_pe.pe.FILE_HEADER.NumberOfSections):
        cur_section_offset = section_hdr_offset + section.sizeof() * i
        last_section_offset = cur_section_offset
    new_section_offset = last_section_offset + section.sizeof()
    
    # append new section header
    target_pe.write_bytes_at_offset(new_section_offset, _section_bin)
    target_pe.pe.FILE_HEADER.NumberOfSections = target_pe.pe.FILE_HEADER.NumberOfSections + 1
    target_pe.pe.OPTIONAL_HEADER.SizeOfImage = target_pe.pe.OPTIONAL_HEADER.SizeOfImage + new_section_hdr.VirtualSize


img_base = target_pe.pe.OPTIONAL_HEADER.ImageBase
ep_rva = target_pe.pe.OPTIONAL_HEADER.AddressOfEntryPoint
ep_delta = ep_rva - target_pe.get_section_header_by_name(".text").VirtualAddress
ep_offset = target_pe.get_section_header_by_name(".text").PointerToRawData + ep_delta

ep_routine = target_pe.pe.__data__[ep_offset:]

md = Cs(CS_ARCH_X86, CS_MODE_32)
first_call_op_offset = 0
origin_call_delata = 0
callee_offset = 0
CALL = b'\xe8'
for op in md.disasm(ep_routine, ep_offset):
    if op.mnemonic == "call":
        # find first call address
        origin_call_delata = struct.unpack("<I", op.bytes[len(CALL):])[0]
        call_operand_offset = len(CALL) + first_call_op_offset
        break
    first_call_op_offset = first_call_op_offset + op.size

first_call_op_rva = ep_rva + first_call_op_offset
first_call_oper_rva = first_call_op_rva + len(b"\xe8")

hook_offset = shellcode_addr["rva"] - first_call_op_rva - 5 + 0x480
target_pe.write_bytes_at_offset(offset=ep_offset + call_operand_offset, data=struct.pack("<I", hook_offset))
offset, _bin = shellcode.recov_origin_call_offset(va=first_call_oper_rva + img_base, origin_callee_addr=origin_call_delata)
target_pe.write_bytes_at_offset(offset=shellcode_addr["offset"]+offset, data=bytes(_bin))

# Recov Original Calling Offset

offset, _bin = shellcode.jump_to_origin_control_flow(va=first_call_op_rva + img_base)
target_pe.write_bytes_at_offset(offset=shellcode_addr["offset"]+offset, data=bytes(_bin))

shellcode.write()

# Remove DynamicBase
target_pe.pe.OPTIONAL_HEADER.DllCharacteristics = target_pe.pe.OPTIONAL_HEADER.DllCharacteristics ^ 0x0040
target_pe.pe.write("./bin/test.exe")