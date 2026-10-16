/* Diagnostic Ghidra C from explicitly documented LD1-to-LDP normalization. Not original source, not the compiled replacement implementation. */

void simd_15ae90(byte *param_1,uint param_2,uint param_3)

{
  ushort uVar1;
  byte *pbVar2;
  byte bVar4;
  uint uVar5;
  int *in_x8;
  int iVar6;
  undefined1 auVar7 [16];
  int iVar8;
  byte *pbVar3;
  
  bVar4 = (byte)param_2;
  iVar6 = 0;
  if (param_3 != 0) {
    if (0x1f < param_3) {
      if (((uint)param_1 & 0x1f) != 0) {
        uVar5 = (uint)param_1 & 0xffffffffffffffe0;
        pbVar3 = param_1;
        do {
          param_1 = pbVar3 + 1;
          if (param_2 == *pbVar3) {
            iVar6 = iVar6 + 1;
          }
          param_3 = param_3 - 1;
          pbVar3 = param_1;
        } while ((byte *)(uVar5 + 0x20) != param_1);
      }
      uVar5 = param_3 & 0xffffffffffffffe0;
      if (uVar5 != 0) {
        param_3 = param_3 - uVar5;
        iVar8 = 0;
        pbVar3 = param_1;
        do {
          pbVar2 = pbVar3 + 0x20;
          auVar7[0] = (-(*pbVar3 == bVar4) & 1U) + (-(pbVar3[1] == bVar4) & 1U);
          auVar7[1] = (-(pbVar3[2] == bVar4) & 1U) + (-(pbVar3[3] == bVar4) & 1U);
          auVar7[2] = (-(pbVar3[4] == bVar4) & 1U) + (-(pbVar3[5] == bVar4) & 1U);
          auVar7[3] = (-(pbVar3[6] == bVar4) & 1U) + (-(pbVar3[7] == bVar4) & 1U);
          auVar7[4] = (-(pbVar3[8] == bVar4) & 1U) + (-(pbVar3[9] == bVar4) & 1U);
          auVar7[5] = (-(pbVar3[10] == bVar4) & 1U) + (-(pbVar3[0xb] == bVar4) & 1U);
          auVar7[6] = (-(pbVar3[0xc] == bVar4) & 1U) + (-(pbVar3[0xd] == bVar4) & 1U);
          auVar7[7] = (-(pbVar3[0xe] == bVar4) & 1U) + (-(pbVar3[0xf] == bVar4) & 1U);
          auVar7[8] = (-(pbVar3[0x10] == bVar4) & 1U) + (-(pbVar3[0x11] == bVar4) & 1U);
          auVar7[9] = (-(pbVar3[0x12] == bVar4) & 1U) + (-(pbVar3[0x13] == bVar4) & 1U);
          auVar7[10] = (-(pbVar3[0x14] == bVar4) & 1U) + (-(pbVar3[0x15] == bVar4) & 1U);
          auVar7[0xb] = (-(pbVar3[0x16] == bVar4) & 1U) + (-(pbVar3[0x17] == bVar4) & 1U);
          auVar7[0xc] = (-(pbVar3[0x18] == bVar4) & 1U) + (-(pbVar3[0x19] == bVar4) & 1U);
          auVar7[0xd] = (-(pbVar3[0x1a] == bVar4) & 1U) + (-(pbVar3[0x1b] == bVar4) & 1U);
          auVar7[0xe] = (-(pbVar3[0x1c] == bVar4) & 1U) + (-(pbVar3[0x1d] == bVar4) & 1U);
          auVar7[0xf] = (-(pbVar3[0x1e] == bVar4) & 1U) + (-(pbVar3[0x1f] == bVar4) & 1U);
          uVar1 = NEON_uaddlv(auVar7,1);
          iVar8 = iVar8 + (uint)uVar1;
          pbVar3 = pbVar2;
        } while (param_1 + uVar5 != pbVar2);
        iVar6 = iVar6 + iVar8;
        param_1 = pbVar2;
        if (param_3 == 0) goto LAB_0015af34;
      }
    }
    do {
      param_3 = param_3 - 1;
      if (param_2 == *param_1) {
        iVar6 = iVar6 + 1;
      }
      param_1 = param_1 + 1;
    } while (param_3 != 0);
  }
LAB_0015af34:
  *in_x8 = iVar6;
  return;
}


