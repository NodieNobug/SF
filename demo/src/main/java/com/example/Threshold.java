package com.example;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

// 工具类：实现简单的秘密共享和拉格朗日插值（仅为示例，生产环境中应采用更安全的实现）
class Threshold {
    private static SecureRandom random = new SecureRandom();

    /**
     * 将秘密 secret 按随机多项式方式分成 totalShares 份，其中至少需要 threshold 份才能恢复秘密。
     * primeModulus 为模数，确保分片值计算时使用正确的模数。
     */
    public static Map<Integer, BigInteger> splitSecret(BigInteger secret, int totalShares, int threshold,
            BigInteger primeModulus) {
        if (threshold > totalShares) {
            throw new IllegalArgumentException("门限值不能大于总分片数");
        }
        BigInteger[] coefficients = new BigInteger[threshold];
        coefficients[0] = secret.mod(primeModulus); // 确保秘密在 primeModulus 下
        for (int i = 1; i < threshold; i++) {
            coefficients[i] = new BigInteger(primeModulus.bitLength(), random).mod(primeModulus);
        }
        Map<Integer, BigInteger> shares = new HashMap<>();
        for (int i = 1; i <= totalShares; i++) {
            BigInteger x = BigInteger.valueOf(i);
            BigInteger y = BigInteger.ZERO;
            for (int j = 0; j < threshold; j++) {
                y = y.add(coefficients[j].multiply(x.pow(j))).mod(primeModulus);
            }
            shares.put(i, y.mod(primeModulus)); // 确保分片值在模数范围内
        }
        return shares;
    }

    /**
     * 利用拉格朗日插值法恢复秘密。参数 shares 为映射：x -> f(x) 的值，
     * 其中 x 的值必须唯一且至少有 threshold 个点。
     */
    public static BigInteger reconstructSecret(Map<Integer, BigInteger> shares, BigInteger primeModulus) {
        BigInteger secret = BigInteger.ZERO;
        for (Map.Entry<Integer, BigInteger> entry_i : shares.entrySet()) {
            // 求基元
            BigInteger xi = BigInteger.valueOf(entry_i.getKey());
            BigInteger yi = entry_i.getValue();
            BigInteger numerator = BigInteger.ONE;
            BigInteger denominator = BigInteger.ONE;
            // 计算拉格朗日基多项式的分子和分母:-xj/(xi-xj)
            for (Map.Entry<Integer, BigInteger> entry_j : shares.entrySet()) {
                if (!entry_i.getKey().equals(entry_j.getKey())) {
                    BigInteger xj = BigInteger.valueOf(entry_j.getKey());
                    numerator = numerator.multiply(xj.negate().mod(primeModulus)).mod(primeModulus);
                    denominator = denominator.multiply(xi.subtract(xj).mod(primeModulus)).mod(primeModulus);
                }
            }
            BigInteger denominatorInverse = denominator.modInverse(primeModulus); // 确保分母逆元计算正确

            // 计算拉格朗日基多项式的值：L(x) = yi * (分子 / 分母)
            BigInteger term = yi.multiply(numerator).mod(primeModulus)
                    .multiply(denominatorInverse).mod(primeModulus);
            secret = secret.add(term).mod(primeModulus);
        }
        return secret.mod(primeModulus); // 确保最终结果在模数范围内
    }
}