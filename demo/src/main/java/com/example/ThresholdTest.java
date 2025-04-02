package com.example;

import java.math.BigInteger;
import java.util.Map;

public class ThresholdTest {
    public static void main(String[] args) {
        // 定义秘密和模数
        BigInteger secret = new BigInteger("12345678901234567890");
        BigInteger primeModulus = new BigInteger("340282366920938463463374607431768211507"); // 一个大素数

        // 分片参数
        int totalShares = 5;
        int threshold = 3;

        // 生成分片
        Map<Integer, BigInteger> shares = Threshold.splitSecret(secret, totalShares, threshold, primeModulus);
        System.out.println("生成的分片: " + shares);

        // 验证分片索引和模数一致性
        System.out.println("验证分片索引和模数一致性...");
        for (Map.Entry<Integer, BigInteger> entry : shares.entrySet()) {
            System.out.println("分片索引: " + entry.getKey() + ", 分片值: " + entry.getValue());
        }
        System.out.println("模数: " + primeModulus);

        // 恢复秘密（使用前 threshold 个分片）
        Map<Integer, BigInteger> partialShares = Map.of(
                1, shares.get(1),
                2, shares.get(2),
                3, shares.get(3));
        BigInteger recoveredSecret = Threshold.reconstructSecret(partialShares, primeModulus);
        System.out.println("恢复的秘密: " + recoveredSecret);

        // 验证恢复的秘密是否正确
        System.out.println("恢复是否正确: " + secret.equals(recoveredSecret));
    }
}
