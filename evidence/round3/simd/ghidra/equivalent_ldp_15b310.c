/* Diagnostic Ghidra C from explicitly documented LD1-to-LDP normalization. Not original source, not the compiled replacement implementation. */

void simd_15b310(uint param_1,char param_2,uint param_3)

{
  char *pcVar1;
  char *pcVar2;
  char *pcVar3;
  char *pcVar4;
  char *pcVar5;
  char *pcVar6;
  char *pcVar7;
  char *pcVar8;
  char *pcVar9;
  char *pcVar10;
  char *pcVar11;
  char *pcVar12;
  char *pcVar13;
  char *pcVar14;
  char *pcVar15;
  char *pcVar16;
  char *pcVar17;
  char *pcVar18;
  char *pcVar19;
  char *pcVar20;
  char *pcVar21;
  char *pcVar22;
  char *pcVar23;
  char *pcVar24;
  char *pcVar25;
  char *pcVar26;
  char *pcVar27;
  char *pcVar28;
  char *pcVar29;
  char *pcVar30;
  char *pcVar31;
  bool bVar32;
  char *pcVar33;
  char *pcVar34;
  uint uVar35;
  uint uVar36;
  int *in_x8;
  uint uVar37;
  char cVar38;
  undefined1 auVar39 [16];
  
  if (param_3 == 0) goto LAB_0015b3e8;
  pcVar33 = (char *)(param_1 & 0xffffffffffffffe0);
  uVar35 = param_1 & 0x1f;
  uVar37 = param_3 & 0x1f;
  if (uVar35 == 0) {
LAB_0015b374:
    do {
      pcVar34 = pcVar33 + 0x20;
      cVar38 = *pcVar33;
      pcVar2 = pcVar33 + 1;
      pcVar3 = pcVar33 + 2;
      pcVar4 = pcVar33 + 3;
      pcVar5 = pcVar33 + 4;
      pcVar6 = pcVar33 + 5;
      pcVar7 = pcVar33 + 6;
      pcVar8 = pcVar33 + 7;
      pcVar9 = pcVar33 + 8;
      pcVar10 = pcVar33 + 9;
      pcVar11 = pcVar33 + 10;
      pcVar12 = pcVar33 + 0xb;
      pcVar13 = pcVar33 + 0xc;
      pcVar14 = pcVar33 + 0xd;
      pcVar15 = pcVar33 + 0xe;
      pcVar16 = pcVar33 + 0xf;
      pcVar1 = pcVar33 + 0x10;
      pcVar17 = pcVar33 + 0x11;
      pcVar18 = pcVar33 + 0x12;
      pcVar19 = pcVar33 + 0x13;
      pcVar20 = pcVar33 + 0x14;
      pcVar21 = pcVar33 + 0x15;
      pcVar22 = pcVar33 + 0x16;
      pcVar23 = pcVar33 + 0x17;
      pcVar24 = pcVar33 + 0x18;
      pcVar25 = pcVar33 + 0x19;
      pcVar26 = pcVar33 + 0x1a;
      pcVar27 = pcVar33 + 0x1b;
      pcVar28 = pcVar33 + 0x1c;
      pcVar29 = pcVar33 + 0x1d;
      pcVar30 = pcVar33 + 0x1e;
      pcVar31 = pcVar33 + 0x1f;
      bVar32 = param_3 < 0x20;
      param_3 = param_3 - 0x20;
      if (bVar32 || param_3 == 0) break;
      auVar39._0_8_ =
           CONCAT17(-(*pcVar8 == param_2) | -(*pcVar23 == param_2),
                    CONCAT16(-(*pcVar7 == param_2) | -(*pcVar22 == param_2),
                             CONCAT15(-(*pcVar6 == param_2) | -(*pcVar21 == param_2),
                                      CONCAT14(-(*pcVar5 == param_2) | -(*pcVar20 == param_2),
                                               CONCAT13(-(*pcVar4 == param_2) |
                                                        -(*pcVar19 == param_2),
                                                        CONCAT12(-(*pcVar3 == param_2) |
                                                                 -(*pcVar18 == param_2),
                                                                 CONCAT11(-(*pcVar2 == param_2) |
                                                                          -(*pcVar17 == param_2),
                                                                          -(cVar38 == param_2) |
                                                                          -(*pcVar1 == param_2))))))
                            ));
      auVar39[8] = -(*pcVar9 == param_2) | -(*pcVar24 == param_2);
      auVar39[9] = -(*pcVar10 == param_2) | -(*pcVar25 == param_2);
      auVar39[10] = -(*pcVar11 == param_2) | -(*pcVar26 == param_2);
      auVar39[0xb] = -(*pcVar12 == param_2) | -(*pcVar27 == param_2);
      auVar39[0xc] = -(*pcVar13 == param_2) | -(*pcVar28 == param_2);
      auVar39[0xd] = -(*pcVar14 == param_2) | -(*pcVar29 == param_2);
      auVar39[0xe] = -(*pcVar15 == param_2) | -(*pcVar30 == param_2);
      auVar39[0xf] = -(*pcVar16 == param_2) | -(*pcVar31 == param_2);
      pcVar33 = pcVar34;
    } while (auVar39._0_8_ + auVar39._8_8_ == 0);
    uVar36 = CONCAT17((-(*pcVar28 == param_2) & 1U) + (-(*pcVar29 == param_2) & 4U) +
                      (-(*pcVar30 == param_2) & 0x10U) + (-(*pcVar31 == param_2) & 0x40U),
                      CONCAT16((-(*pcVar24 == param_2) & 1U) + (-(*pcVar25 == param_2) & 4U) +
                               (-(*pcVar26 == param_2) & 0x10U) + (-(*pcVar27 == param_2) & 0x40U),
                               CONCAT15((-(*pcVar20 == param_2) & 1U) +
                                        (-(*pcVar21 == param_2) & 4U) +
                                        (-(*pcVar22 == param_2) & 0x10U) +
                                        (-(*pcVar23 == param_2) & 0x40U),
                                        CONCAT14((-(*pcVar1 == param_2) & 1U) +
                                                 (-(*pcVar17 == param_2) & 4U) +
                                                 (-(*pcVar18 == param_2) & 0x10U) +
                                                 (-(*pcVar19 == param_2) & 0x40U),
                                                 CONCAT13((-(*pcVar13 == param_2) & 1U) +
                                                          (-(*pcVar14 == param_2) & 4U) +
                                                          (-(*pcVar15 == param_2) & 0x10U) +
                                                          (-(*pcVar16 == param_2) & 0x40U),
                                                          CONCAT12((-(*pcVar9 == param_2) & 1U) +
                                                                   (-(*pcVar10 == param_2) & 4U) +
                                                                   (-(*pcVar11 == param_2) & 0x10U)
                                                                   + (-(*pcVar12 == param_2) & 0x40U
                                                                     ),CONCAT11((-(*pcVar5 ==
                                                                                  param_2) & 1U) +
                                                                                (-(*pcVar6 ==
                                                                                  param_2) & 4U) +
                                                                                (-(*pcVar7 ==
                                                                                  param_2) & 0x10U)
                                                                                + (-(*pcVar8 ==
                                                                                    param_2) & 0x40U
                                                                                  ),(-(cVar38 ==
                                                                                      param_2) & 1U)
                                                                                    + (-(*pcVar2 ==
                                                                                        param_2) &
                                                                                      4U) + (-(*
                                                  pcVar3 == param_2) & 0x10U) +
                                                  (-(*pcVar4 == param_2) & 0x40U))))))));
    if (bVar32) {
LAB_0015b3b0:
      uVar35 = ((uVar37 + uVar35 & 0x1f) - 0x20) * -2;
      uVar36 = (uVar36 << (uVar35 & 0x3f)) >> (uVar35 & 0x3f);
    }
  }
  else {
    pcVar34 = pcVar33 + 0x20;
    bVar32 = CARRY8(param_3,uVar35 - 0x20);
    param_3 = param_3 + (uVar35 - 0x20);
    uVar36 = (CONCAT17((-(pcVar33[0x1c] == param_2) & 1U) + (-(pcVar33[0x1d] == param_2) & 4U) +
                       (-(pcVar33[0x1e] == param_2) & 0x10U) + (-(pcVar33[0x1f] == param_2) & 0x40U)
                       ,CONCAT16((-(pcVar33[0x18] == param_2) & 1U) +
                                 (-(pcVar33[0x19] == param_2) & 4U) +
                                 (-(pcVar33[0x1a] == param_2) & 0x10U) +
                                 (-(pcVar33[0x1b] == param_2) & 0x40U),
                                 CONCAT15((-(pcVar33[0x14] == param_2) & 1U) +
                                          (-(pcVar33[0x15] == param_2) & 4U) +
                                          (-(pcVar33[0x16] == param_2) & 0x10U) +
                                          (-(pcVar33[0x17] == param_2) & 0x40U),
                                          CONCAT14((-(pcVar33[0x10] == param_2) & 1U) +
                                                   (-(pcVar33[0x11] == param_2) & 4U) +
                                                   (-(pcVar33[0x12] == param_2) & 0x10U) +
                                                   (-(pcVar33[0x13] == param_2) & 0x40U),
                                                   CONCAT13((-(pcVar33[0xc] == param_2) & 1U) +
                                                            (-(pcVar33[0xd] == param_2) & 4U) +
                                                            (-(pcVar33[0xe] == param_2) & 0x10U) +
                                                            (-(pcVar33[0xf] == param_2) & 0x40U),
                                                            CONCAT12((-(pcVar33[8] == param_2) & 1U)
                                                                     + (-(pcVar33[9] == param_2) &
                                                                       4U) + (-(pcVar33[10] ==
                                                                               param_2) & 0x10U) +
                                                                             (-(pcVar33[0xb] ==
                                                                               param_2) & 0x40U),
                                                                     CONCAT11((-(pcVar33[4] ==
                                                                                param_2) & 1U) +
                                                                              (-(pcVar33[5] ==
                                                                                param_2) & 4U) +
                                                                              (-(pcVar33[6] ==
                                                                                param_2) & 0x10U) +
                                                                              (-(pcVar33[7] ==
                                                                                param_2) & 0x40U),
                                                                              (-(*pcVar33 == param_2
                                                                                ) & 1U) +
                                                                              (-(pcVar33[1] ==
                                                                                param_2) & 4U) +
                                                                              (-(pcVar33[2] ==
                                                                                param_2) & 0x10U) +
                                                                              (-(pcVar33[3] ==
                                                                                param_2) & 0x40U))))
                                                  )))) >> (uVar35 << 1)) << (uVar35 << 1);
    if (!bVar32 || param_3 == 0) goto LAB_0015b3b0;
    pcVar33 = pcVar34;
    if (uVar36 == 0) goto LAB_0015b374;
  }
  if (uVar36 != 0) {
    uVar35 = (uVar36 & 0xaaaaaaaaaaaaaaaa) >> 1 | (uVar36 & 0x5555555555555555) << 1;
    uVar35 = (uVar35 & 0xcccccccccccccccc) >> 2 | (uVar35 & 0x3333333333333333) << 2;
    uVar35 = (uVar35 & 0xf0f0f0f0f0f0f0f0) >> 4 | (uVar35 & 0xf0f0f0f0f0f0f0f) << 4;
    uVar35 = (uVar35 & 0xff00ff00ff00ff00) >> 8 | (uVar35 & 0xff00ff00ff00ff) << 8;
    uVar35 = (uVar35 & 0xffff0000ffff0000) >> 0x10 | (uVar35 & 0xffff0000ffff) << 0x10;
    *in_x8 = (int)(pcVar34 +
                  ((((uint)LZCOUNT(uVar35 >> 0x20 | uVar35 << 0x20) >> 1) - 0x20) - param_1));
    return;
  }
LAB_0015b3e8:
  *in_x8 = -1;
  return;
}


