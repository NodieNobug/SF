package com.example;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class SafeMulTest {
    public static void main(String[] args) {
        long startTime = System.currentTimeMillis();
        // 向量长度
        int n = 10000;
        int numVectors = 1024;
        // PA持有的向量组a，每个向量长度为10000，值为-100.000~100.000的随机数
        SecureRandom random = new SecureRandom();
        double[][] a = new double[numVectors][n];
        for (int i = 0; i < numVectors; i++) {
            for (int j = 0; j < n; j++) {
                a[i][j] = -100.0 + 200.0 * random.nextDouble();
            }
        }
        // PB持有的向量b，长度为10000，值为-100.000~100.000的随机数
        double[] b = new double[n];
        for (int i = 0; i < n; i++) {
            b[i] = -100.0 + 200.0 * random.nextDouble();
        }

        // 精度放大因子

        long PRECISION_FACTOR = 1000000;

        // 安全参数
        int k1 = 1024; // p的比特长度 建议128以上
        int k2 = 128; // alpha的比特长度取 40-64之间
        int k3 = 64; // c_i的比特长度
        int k4 = 64; // r_i的比特长度

        // Step1: PA生成参数
        BigInteger p = BigInteger.probablePrime(k1, random);
        BigInteger alpha = BigInteger.probablePrime(k2, random);
        BigInteger s = new BigInteger(k1 - 2, random).add(BigInteger.ONE); // s ∈ Z_p
        BigInteger s_inv = s.modInverse(p);

        // PA为每个向量生成密文
        BigInteger[][] C = new BigInteger[a.length][n + 2];
        BigInteger[][] c = new BigInteger[a.length][n + 2];

        for (int vecIndex = 0; vecIndex < a.length; vecIndex++) {
            double[] a_temp = Arrays.copyOf(a[vecIndex], n + 2); // 每个向量扩展两位
            for (int i = 0; i < n + 2; i++) {
                c[vecIndex][i] = new BigInteger(k3, random);
                if (i < n) { // 只处理原始向量部分
                    BigInteger scaledValue = BigInteger.valueOf((long) (a_temp[i] * PRECISION_FACTOR));
                    C[vecIndex][i] = s.multiply(scaledValue.multiply(alpha).add(c[vecIndex][i])).mod(p);
                } else {
                    C[vecIndex][i] = s.multiply(c[vecIndex][i]).mod(p);
                }
            }
        }

        // PA发送(alpha, p, C[0..a.length-1][0..n+1])给PB
        // System.out.println("p: " + p);
        // System.out.println("alpha: " + alpha);
        // System.out.println("s: " + s);
        // System.out.println("s_inv: " + s_inv);
        // for (BigInteger[] c2 : C) {
        // for (BigInteger c22 : c2) {
        // System.out.print(c22 + " ");
        // }
        // System.out.println("");
        // }

        // Step2: PB处理
        double[] b_ext = Arrays.copyOf(b, n + 2); // b扩展两位
        BigInteger[] D_sums = new BigInteger[a.length];

        for (int vecIndex = 0; vecIndex < a.length; vecIndex++) {
            BigInteger[] D = new BigInteger[n + 2];
            for (int i = 0; i < n + 2; i++) {
                if (i < n) { // 只处理原始向量部分
                    BigInteger scaledValue = BigInteger.valueOf((long) (b_ext[i] * PRECISION_FACTOR));
                    D[i] = scaledValue.multiply(alpha).multiply(C[vecIndex][i]).mod(p);
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
        Double[] results = new Double[a.length];
        BigInteger alpha2 = alpha.multiply(alpha);

        // PA计算结果时需要考虑精度还原
        for (int vecIndex = 0; vecIndex < a.length; vecIndex++) {
            BigInteger E = s_inv.multiply(D_sums[vecIndex]).mod(p);
            // 处理负数情况
            if (E.compareTo(p.divide(BigInteger.TWO)) > 0) {
                System.out.println("第一轮结果溢出，进行修正.....");
                E = E.subtract(p);
            }
            BigInteger inner = E.subtract(E.mod(alpha2)).divide(alpha2);
            // 还原精度
            double actualResult = inner.doubleValue() / (PRECISION_FACTOR * PRECISION_FACTOR);
            results[vecIndex] = actualResult;

            // 验证正确性
            double plainInner = 0.0;
            for (int i = 0; i < n; i++) {
                plainInner += a[vecIndex][i] * b[i];
            }

            // System.out.println("\n向量 " + (vecIndex + 1) + " 的计算结果:");
            System.out.println("安全点积结果: " + actualResult);
            System.out.println("明文点积结果: " + plainInner);
            System.out.println("相对误差: " + Math.abs((actualResult - plainInner) / plainInner));
        }

        // 输出所有向量的点积结果
        // System.out.println("\n所有向量的点积结果汇总:");
        // for (int i = 0; i < results.length; i++) {
        // System.out.println("向量 " + (i + 1) + " 的点积: " + results[i]);
        // }
        long endTime = System.currentTimeMillis();
        System.out.println("程序运行时间：" + (endTime - startTime) + "ms");
    }
}
