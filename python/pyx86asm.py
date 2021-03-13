from typing import List
import struct

def make_mov_eax_oper(oper:int)->bytearray:
    mov_eax = 0xb8
    mov_eax_inst = bytearray()
    mov_eax_inst.append(mov_eax)
    b_oper = struct.pack("<I", oper)
    mov_eax_inst += bytearray(b_oper)

    return mov_eax_inst

def make_push_op(oper:int)->bytearray:
    big_push = 0x68
    lit_push = 0x6A
    push_inst = bytearray()
    if oper > 0x7F:
        push_inst.append(big_push)
        b_oper = struct.pack("<I", oper)
        
    else:
        push_inst.append(lit_push)
        b_oper = struct.pack("B", oper)

    push_inst += bytearray(b_oper)

    return push_inst

def chage_pystr_to_dword_array(api_str:str)->List:
    str_arr = [api_str[i:i+4] for i in range(0, len(api_str), 4)]
    dw_arr = []
    for dwordStr in str_arr:
        dw_str = struct.unpack(">I", dwordStr.encode("ascii"))[0]
        dw_arr.append(dw_str)

    dw_arr.reverse()

    return dw_arr