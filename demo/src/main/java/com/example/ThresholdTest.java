package com.example;

import java.math.BigInteger;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;

public class ThresholdTest {
    public static void main(String[] args) {
        // 运行原始测试
        testBasicThreshold();
        System.out.println("\n=== 运行新的门限密码学测试 ===\n");
        testThresholdCryptography();
    }

    private static void testBasicThreshold() {
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

    private static void testThresholdCryptography() {
        // 模拟实际场景中的参数
        BigInteger secret = new BigInteger("98765432109876543210");
        BigInteger primeModulus = new BigInteger("340282366920938463463374607431768211507");

        // 设置门限参数：总共7个参与者，需要至少4个才能恢复秘密
        int totalShares = 7;
        int threshold = 4;

        System.out.println("1. 生成秘密分片");
        Map<Integer, BigInteger> shares = Threshold.splitSecret(secret, totalShares, threshold, primeModulus);

        // 模拟部分参与者掉线的情况
        System.out.println("\n2. 模拟部分参与者掉线");
        List<Integer> availableParticipants = new ArrayList<>();
        availableParticipants.add(1);
        availableParticipants.add(3);
        availableParticipants.add(5);
        availableParticipants.add(7);

        System.out.println("可用的参与者ID: " + availableParticipants);

        // 收集可用的分片
        Map<Integer, BigInteger> availableShares = new HashMap<>();
        for (Integer id : availableParticipants) {
            availableShares.put(id, shares.get(id));
            System.out.println("参与者 " + id + " 的分片: " + shares.get(id));
        }

        // 验证是否满足门限要求
        if (availableShares.size() >= threshold) {
            System.out.println("\n3. 满足门限要求，开始恢复秘密");
            BigInteger recoveredSecret = Threshold.reconstructSecret(availableShares, primeModulus);
            System.out.println("恢复的秘密: " + recoveredSecret);
            System.out.println("恢复是否正确: " + secret.equals(recoveredSecret));
        } else {
            System.out.println("\n3. 错误：可用分片数量不足，无法恢复秘密");
            System.out.println("需要至少 " + threshold + " 个分片，但只有 " + availableShares.size() + " 个可用");
        }

        // 测试使用不足门限数量的分片
        System.out.println("\n4. 测试使用不足门限数量的分片");
        Map<Integer, BigInteger> insufficientShares = new HashMap<>();
        insufficientShares.put(1, shares.get(1));
        insufficientShares.put(2, shares.get(2));

        try {
            BigInteger invalidRecovery = Threshold.reconstructSecret(insufficientShares, primeModulus);
            System.out.println("使用不足门限数量的分片恢复结果: " + invalidRecovery);
        } catch (Exception e) {
            System.out.println("预期错误：使用不足门限数量的分片无法恢复秘密");
        }
    }
}
