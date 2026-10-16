/* DIAGNOSTIC ABLATION, semantics deliberately changed; NOT a replacement implementation. */

void simd_15b310(uint param_1,undefined8 param_2,uint param_3)

{
  bool bVar1;
  uint uVar2;
  uint in_x6;
  int *in_x8;
  uint uVar3;
  
  if (param_3 == 0) goto LAB_0015b3e8;
  uVar2 = param_1 & 0x1f;
  uVar3 = param_3 & 0x1f;
  if (uVar2 == 0) {
code_r0x0015b378:
    do {
      bVar1 = param_3 < 0x20;
      param_3 = param_3 - 0x20;
      if (bVar1 || param_3 == 0) break;
    } while (in_x6 == 0);
    if (bVar1) {
LAB_0015b3b0:
      uVar2 = ((uVar3 + uVar2 & 0x1f) - 0x20) * -2;
      in_x6 = (in_x6 << (uVar2 & 0x3f)) >> (uVar2 & 0x3f);
    }
  }
  else {
    bVar1 = CARRY8(param_3,uVar2 - 0x20);
    param_3 = param_3 + (uVar2 - 0x20);
    in_x6 = (in_x6 >> (uVar2 << 1)) << (uVar2 << 1);
    if (!bVar1 || param_3 == 0) goto LAB_0015b3b0;
    if (in_x6 == 0) goto code_r0x0015b378;
  }
  if (in_x6 != 0) {
    uVar2 = (in_x6 & 0xaaaaaaaaaaaaaaaa) >> 1 | (in_x6 & 0x5555555555555555) << 1;
    uVar2 = (uVar2 & 0xcccccccccccccccc) >> 2 | (uVar2 & 0x3333333333333333) << 2;
    uVar2 = (uVar2 & 0xf0f0f0f0f0f0f0f0) >> 4 | (uVar2 & 0xf0f0f0f0f0f0f0f) << 4;
    uVar2 = (uVar2 & 0xff00ff00ff00ff00) >> 8 | (uVar2 & 0xff00ff00ff00ff) << 8;
    uVar2 = (uVar2 & 0xffff0000ffff0000) >> 0x10 | (uVar2 & 0xffff0000ffff) << 0x10;
    *in_x8 = (((param_1 & 0xffffffffffffffe0) - 0x20) +
             ((uint)LZCOUNT(uVar2 >> 0x20 | uVar2 << 0x20) >> 1)) - param_1;
    return;
  }
LAB_0015b3e8:
  *in_x8 = -1;
  return;
}


