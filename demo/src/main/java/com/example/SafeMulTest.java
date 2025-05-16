package com.example;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

public class SafeMulTest {
    public static void main(String[] args) {
        // 向量长度
        int n = 5;
        // PA持有的向量a
        int[] a = { 3, 2, 5, 1, 4 };
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
        int[] a_ext = Arrays.copyOf(a, n + 2); // a_{n+1}, a_{n+2} = 0
        BigInteger s = new BigInteger(k1 - 2, random).add(BigInteger.ONE); // s ∈ Z_p
        BigInteger[] c = new BigInteger[n + 2];
        for (int i = 0; i < n + 2; i++) {
            c[i] = new BigInteger(k3, random);
        }
        BigInteger[] C = new BigInteger[n + 2];
        for (int i = 0; i < n + 2; i++) {
            if (a_ext[i] != 0) {
                C[i] = s.multiply(BigInteger.valueOf(a_ext[i]).multiply(alpha).add(c[i])).mod(p);
            } else {
                C[i] = s.multiply(c[i]).mod(p);
            }
        }
        BigInteger A = BigInteger.ZERO;
        for (int i = 0; i < n; i++) {
            A = A.add(BigInteger.valueOf(a[i]).pow(2));
        }
        BigInteger s_inv = s.modInverse(p);
        // PA发送(alpha, p, C[0..n+1])给PB

        System.out.println("p: " + p);
        System.out.println("alpha: " + alpha);
        System.out.println("s: " + s);
        System.out.println("s_inv: " + s_inv);
        System.out.println("a_ext: " + Arrays.toString(a_ext));
        System.out.println("c: " + Arrays.toString(c));
        System.out.println("C: " + Arrays.toString(C));

        // Step2: PB处理
        int[] b_ext = Arrays.copyOf(b, n + 2); // b_{n+1}, b_{n+2} = 0
        BigInteger[] D = new BigInteger[n + 2];
        for (int i = 0; i < n + 2; i++) {
            if (b_ext[i] != 0) {
                D[i] = BigInteger.valueOf(b_ext[i]).multiply(alpha).multiply(C[i]).mod(p);
            } else {
                BigInteger r = new BigInteger(k4, random);
                D[i] = r.multiply(C[i]).mod(p);
            }
        }
        BigInteger B = BigInteger.ZERO;
        for (int i = 0; i < n; i++) {
            B = B.add(BigInteger.valueOf(b[i]).pow(2));
        }
        BigInteger D_sum = BigInteger.ZERO;
        for (int i = 0; i < n + 2; i++) {
            D_sum = D_sum.add(D[i]);
        }
        D_sum = D_sum.mod(p);
        // PB发送(B, D_sum)给PA

        System.out.println("b_ext: " + Arrays.toString(b_ext));
        System.out.println("D: " + Arrays.toString(D));
        System.out.println("D_sum: " + D_sum);

        // Step3: PA计算
        BigInteger E = s_inv.multiply(D_sum).mod(p);
        // 点积结果
        BigInteger alpha2 = alpha.multiply(alpha);
        BigInteger inner = E.subtract(E.mod(alpha2)).divide(alpha2);
        System.out.println("E: " + E);
        System.out.println("alpha^2: " + alpha2);
        System.out.println("E mod alpha^2: " + E.mod(alpha2));
        System.out.println("E - (E mod alpha^2): " + E.subtract(E.mod(alpha2)));
        System.out.println("inner: " + inner);
        // 验证正确性
        int plainInner = 0;
        for (int i = 0; i < n; i++) {
            plainInner += a[i] * b[i];
        }
        System.out.println("明文点积结果: " + plainInner);
    }
}
