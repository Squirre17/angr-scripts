```python
In [2]: import angr

In [3]: proj=angr.Project('/bin/true')
WARNING  | 2023-07-24 13:42:11,180 | cle.loader     | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.

In [4]: block=proj.factory.block(proj.entry)

In [5]: block.capstone.pp()
0x402610:       endbr64
0x402614:       xor     ebp, ebp
0x402616:       mov     r9, rdx
0x402619:       pop     rsi
0x40261a:       mov     rdx, rsp
0x40261d:       and     rsp, 0xfffffffffffffff0
0x402621:       push    rax
0x402622:       push    rsp
0x402623:       lea     r8, [rip + 0x2f16]
0x40262a:       lea     rcx, [rip + 0x2e9f]
0x402631:       lea     rdi, [rip - 0xe8]
0x402638:       call    qword ptr [rip + 0x79a2]

In [6]: block.vex.pp()
IRSB {
   t0:Ity_I32 t1:Ity_I32 t2:Ity_I32 t3:Ity_I64 t4:Ity_I64 t5:Ity_I64 t6:Ity_I64 t7:Ity_I64 t8:Ity_I64 t9:Ity_I64 t10:Ity_I64 t11:Ity_I64 t12:Ity_I64 t13:Ity_I64 t14:Ity_I64 t15:Ity_I32 t16:Ity_I64 t17:Ity_I64 t18:Ity_I64 t19:Ity_I64 t20:Ity_I32 t21:Ity_I64 t22:Ity_I32 t23:Ity_I64 t24:Ity_I64 t25:Ity_I64 t26:Ity_I64 t27:Ity_I64 t28:Ity_I64 t29:Ity_I64 t30:Ity_I64 t31:Ity_I64 t32:Ity_I64 t33:Ity_I64 t34:Ity_I64 t35:Ity_I64 t36:Ity_I64

   00 | ------ IMark(0x402610, 4, 0) ------
   01 | ------ IMark(0x402614, 2, 0) ------
   02 | PUT(rbp) = 0x0000000000000000
   03 | ------ IMark(0x402616, 3, 0) ------
   04 | t26 = GET:I64(rdx)
   05 | PUT(r9) = t26
   06 | PUT(rip) = 0x0000000000402619
   07 | ------ IMark(0x402619, 1, 0) ------
   08 | t4 = GET:I64(rsp)
   09 | t3 = LDle:I64(t4)
   10 | t27 = Add64(t4,0x0000000000000008)
   11 | PUT(rsi) = t3
   12 | ------ IMark(0x40261a, 3, 0) ------
   13 | PUT(rdx) = t27
   14 | ------ IMark(0x40261d, 4, 0) ------
   15 | t5 = And64(t27,0xfffffffffffffff0)
   16 | PUT(cc_op) = 0x0000000000000014
   17 | PUT(cc_dep1) = t5
   18 | PUT(cc_dep2) = 0x0000000000000000
   19 | PUT(rip) = 0x0000000000402621
   20 | ------ IMark(0x402621, 1, 0) ------
   21 | t8 = GET:I64(rax)
   22 | t29 = Sub64(t5,0x0000000000000008)
   23 | PUT(rsp) = t29
   24 | STle(t29) = t8
   25 | PUT(rip) = 0x0000000000402622
   26 | ------ IMark(0x402622, 1, 0) ------
   27 | t31 = Sub64(t29,0x0000000000000008)
   28 | PUT(rsp) = t31
   29 | STle(t31) = t29
   30 | ------ IMark(0x402623, 7, 0) ------
   31 | PUT(r8) = 0x0000000000405540
   32 | ------ IMark(0x40262a, 7, 0) ------
   33 | PUT(rcx) = 0x00000000004054d0
   34 | ------ IMark(0x402631, 7, 0) ------
   35 | PUT(rdi) = 0x0000000000402550
   36 | PUT(rip) = 0x0000000000402638
   37 | ------ IMark(0x402638, 6, 0) ------
   38 | t17 = LDle:I64(0x0000000000409fe0)
   39 | t33 = Sub64(t31,0x0000000000000008)
   40 | PUT(rsp) = t33
   41 | STle(t33) = 0x000000000040263e
   42 | t35 = Sub64(t33,0x0000000000000080)
   43 | ====== AbiHint(0xt35, 128, t17) ======
   NEXT: PUT(rip) = t17; Ijk_Call
}
```