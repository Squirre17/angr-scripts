# import nose.tools
import archinfo
import pyvex
from loguru import logger
from pwn import asm

def test_ud2():
    # On x86 and amd64, ud2 is a valid 2-byte instruction that means "undefined instruction". Upon decoding a basic
    # block that ends with ud2, we should treat it as an explicit NoDecode, instead of skipping the instruction and
    # resume lifting.
    # print(asm("add eax, 3"))
    b = pyvex.block.IRSB(asm("add eax, 3"), 0x20, archinfo.ArchAMD64())
    logger.debug(b)
    '''
    00 | ------ IMark(0x20, 3, 0) ------ # (指令地址, 指令长度, 0)
    01 | t4 = GET:I64(rax)
    02 | t3 = 64to32(t4)
    03 | t0 = Add32(t3,0x00000003)
    04 | PUT(cc_op) = 0x0000000000000003
    05 | t5 = 32Uto64(t3)
    06 | PUT(cc_dep1) = t5
    07 | PUT(cc_dep2) = 0x0000000000000003
    08 | t7 = 32Uto64(t0)
    09 | PUT(rax) = t7
    NEXT: PUT(rip) = 0x0000000000000023; Ijk_Boring
    
    这里cc是condition code 因为计算完了临时变量还需要改变条件寄存器状态 就是cc_dep1 cc_op cc_dep2
    Ijk_Boring就是直接跳转
    '''
    print("b.jumpkink:     :",b.jumpkind)
    print('b.next.con.value:',hex(b.next.con.value))
    # breakpoint()
    print('b.size          :',hex(b.size))

def statement_and_expression():
    pass

if __name__ == "__main__":
    test_ud2()