/* DIAGNOSTIC ABLATION, semantics deliberately changed; NOT a replacement implementation. */

void simd_15ae90(byte *param_1,uint param_2,uint param_3)

{
  byte *pbVar1;
  uint uVar2;
  int in_x6;
  int *in_x8;
  int iVar3;
  
  iVar3 = 0;
  if (param_3 != 0) {
    if (0x1f < param_3) {
      if (((uint)param_1 & 0x1f) != 0) {
        uVar2 = (uint)param_1 & 0xffffffffffffffe0;
        pbVar1 = param_1;
        do {
          param_1 = pbVar1 + 1;
          if (param_2 == *pbVar1) {
            iVar3 = iVar3 + 1;
          }
          param_3 = param_3 - 1;
          pbVar1 = param_1;
        } while ((byte *)(uVar2 + 0x20) != param_1);
      }
      uVar2 = param_3 & 0xffffffffffffffe0;
      if (uVar2 != 0) {
        param_3 = param_3 - uVar2;
        do {
        } while (param_1 + uVar2 != param_1);
        iVar3 = iVar3 + in_x6;
        if (param_3 == 0) goto LAB_0015af34;
      }
    }
    do {
      param_3 = param_3 - 1;
      if (param_2 == *param_1) {
        iVar3 = iVar3 + 1;
      }
      param_1 = param_1 + 1;
    } while (param_3 != 0);
  }
LAB_0015af34:
  *in_x8 = iVar3;
  return;
}


