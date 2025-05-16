package com.example;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class SafeMulTest {
    public static void main(String[] args) {
        // 向量长度
        int n = 5;
        // PA持有的向量组a，每个向量长度为5
        int[][] a = {
                { 3, 2, 5, 1, 4 },
                { 2, 3, 4, 1, 6 },
                { 1, 5, 3, 2, 4 },
                { 4, 2, 1, 5, 3 },
                { 3, 4, 5, 2, 1 }
        };
        // PB持有的向量b
        int[] b = { 6, 1, 2, 3, 5 };

        // 安全参数
        int k1 = 128; // p的比特长度 建议128以上
        int k2 = 40; // alpha的比特长度取 40-64之间
        int k3 = 32; // c_i的比特长度
        int k4 = 32; // r_i的比特长度
        SecureRandom random = new SecureRandom();

        // Step1: PA生成参数
        BigInteger p = BigInteger.probablePrime(k1, random);
        BigInteger alpha = BigInteger.probablePrime(k2, random);
        BigInteger s = new BigInteger(k1 - 2, random).add(BigInteger.ONE); // s ∈ Z_p
        BigInteger s_inv = s.modInverse(p);

        // PA为每个向量生成密文
        BigInteger[][] C = new BigInteger[a.length][n + 2];
        BigInteger[][] c = new BigInteger[a.length][n + 2];

        for (int vecIndex = 0; vecIndex < a.length; vecIndex++) {
            int[] a_ext = Arrays.copyOf(a[vecIndex], n + 2); // 每个向量扩展两位
            for (int i = 0; i < n + 2; i++) {
                c[vecIndex][i] = new BigInteger(k3, random);
                if (a_ext[i] != 0) {
                    C[vecIndex][i] = s.multiply(BigInteger.valueOf(a_ext[i]).multiply(alpha).add(c[vecIndex][i]))
                            .mod(p);
                } else {
                    C[vecIndex][i] = s.multiply(c[vecIndex][i]).mod(p);
                }
            }
        }

        // PA发送(alpha, p, C[0..a.length-1][0..n+1])给PB
        System.out.println("p: " + p);
        System.out.println("alpha: " + alpha);
        System.out.println("s: " + s);
        System.out.println("s_inv: " + s_inv);
        for (BigInteger[] c2 : C) {
            for (BigInteger c22 : c2) {
                System.out.print(c22 + " ");
            }
            System.out.println("");
        }

        // Step2: PB处理
        int[] b_ext = Arrays.copyOf(b, n + 2); // b扩展两位
        BigInteger[] D_sums = new BigInteger[a.length];

        for (int vecIndex = 0; vecIndex < a.length; vecIndex++) {
            BigInteger[] D = new BigInteger[n + 2];
            for (int i = 0; i < n + 2; i++) {
                if (b_ext[i] != 0) {
                    D[i] = BigInteger.valueOf(b_ext[i]).multiply(alpha).multiply(C[vecIndex][i]).mod(p);
                } else {
                    BigInteger r = new BigInteger(k4, random);
                    D[i] = r.multiply(C[vecIndex][i]).mod(p);
                }
            }
            BigInteger D_sum = BigInteger.ZERO;
            for (int i = 0; i < n + 2; i++) {
                D_sum = D_sum.add(D[i]);
            }
            D_sums[vecIndex] = D_sum.mod(p);

        }
        // PB发送所有D_sum给PA

        // Step3: PA计算所有向量的点积
        BigInteger[] results = new BigInteger[a.length];
        BigInteger alpha2 = alpha.multiply(alpha);

        for (int vecIndex = 0; vecIndex < a.length; vecIndex++) {
            BigInteger E = s_inv.multiply(D_sums[vecIndex]).mod(p);
            BigInteger inner = E.subtract(E.mod(alpha2)).divide(alpha2);
            results[vecIndex] = inner;

            // 验证正确性
            int plainInner = 0;
            for (int i = 0; i < n; i++) {
                plainInner += a[vecIndex][i] * b[i];
            }

            System.out.println("\n向量 " + (vecIndex + 1) + " 的计算结果:");
            System.out.println("D_sum: " + D_sums[vecIndex]);
            System.out.println("E: " + E);
            System.out.println("点积结果: " + inner);
            System.out.println("明文点积结果: " + plainInner);
        }

        // 输出所有向量的点积结果
        System.out.println("\n所有向量的点积结果汇总:");
        for (int i = 0; i < results.length; i++) {
            System.out.println("向量 " + (i + 1) + " 的点积: " + results[i]);
        }
    }
}
