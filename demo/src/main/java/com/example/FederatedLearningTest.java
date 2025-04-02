package com.example;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

// 测试类：包含两种场景的测试
public class FederatedLearningTest {
    public static void main(String[] args) {
        System.out.println("Federated Learning Test 测试git是否可用");
        System.out.println("------------------------");

        int numDO = 8;
        // 模拟每个 DO 的模型参数字符串（保持不变）
        String[] modelParamStrings = {
                Arrays.toString(new double[] { 0.1, -0.3, 0.7, 0.0, 5.0 }),
                Arrays.toString(new double[] { 0.1, -0.3, 0.7, 0.0, 5.0 }),
                Arrays.toString(new double[] { 0.1, -0.3, 0.7, 0.0, 5.0 }),
                Arrays.toString(new double[] { 0.1, -0.3, 0.7, 0.0, 5.0 }),
                Arrays.toString(new double[] { 0.1, -0.3, 0.7, 0.0, 5.0 }),
                Arrays.toString(new double[] { 0.1, -0.3, 0.7, 0.0, 5.0 }),
                Arrays.toString(new double[] { 0.1, -0.3, 0.7, 0.0, 5.0 }),
                Arrays.toString(new double[] { 0.1, -0.3, 0.7, 0.0, 5.0 })
        };
        BigInteger[] modelParamHashes = new BigInteger[numDO];
        // 计算每个模型参数字符串的哈希值
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (int i = 0; i < numDO; i++) {
                byte[] hashBytes = digest.digest(modelParamStrings[i].getBytes(StandardCharsets.UTF_8));
                modelParamHashes[i] = new BigInteger(1, hashBytes);
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return;
        }

        // ---------------- 场景1：正常流程测试 ----------------
        System.out.println("----- 正常流程测试 -----");
        runTestScenario(numDO, modelParamHashes, new ArrayList<>());

        // ---------------- 场景2：模拟单个 DO 掉线 ----------------
        System.out.println("\n----- 掉线场景测试 -----");
        System.out.println("总DO数量: " + numDO);
        System.out.println("门限值: 5");
        runTestScenario(numDO, modelParamHashes, Arrays.asList(1));

        // ---------------- 场景3：模拟多个 DO 掉线 ----------------
        System.out.println("\n----- 多 DO 掉线场景测试 -----");
        System.out.println("总DO数量: " + numDO);
        System.out.println("门限值: 5");
        System.out.println("掉线DO数量: 2");
        runTestScenario(numDO, modelParamHashes, Arrays.asList(2, 3));

        // 三个DO掉线测试
        // System.out.println("\n----- 多 DO 掉线场景测试 -----");
        // System.out.println("总DO数量: " + numDO);
        // System.out.println("门限值: 5");
        // System.out.println("掉线DO数量: 2");
        // runTestScenario(numDO, modelParamHashes, Arrays.asList(1, 2, 3));

    }

    private static void runTestScenario(int numDO, BigInteger[] modelParamHashes, List<Integer> missingDOIds) {
        // TA 生成全局参数和每个 DO 的私钥及密钥分片
        TA ta = new TA(numDO, modelParamHashes); // 恢复传入modelParamHashes

        // 创建 DO 对象列表
        List<DO> doList = new ArrayList<>();
        for (int i = 0; i < numDO; i++) {
            doList.add(new DO(i, ta));
        }

        // 创建 CSP 对象
        CSP csp = new CSP(ta, numDO);

        // 模拟 DO 加密并上传密文
        for (int i = 0; i < numDO; i++) {
            if (missingDOIds.contains(i)) {
                continue; // 模拟掉线
            }
            DO doObj = doList.get(i);
            doObj.trainModel();
            doObj.encryptData(modelParamHashes[i], ta.getN(), ta.getG(), ta.getH());
            csp.receiveData(i, doObj.getEncryptedModelParams());
        }

        // 检测掉线并恢复私钥
        List<DO> availableDOs = new ArrayList<>();
        for (int i = 0; i < numDO; i++) {
            if (!missingDOIds.contains(i)) {
                availableDOs.add(doList.get(i));
            }
        }
        Map<Integer, BigInteger> recoveredKeys = csp.recoverMissingPrivateKeys(missingDOIds, availableDOs);

        // 验证恢复的私钥
        for (int missingDOId : missingDOIds) {
            BigInteger recoveredKey = recoveredKeys.get(missingDOId);
            System.out.println("恢复的 DO" + missingDOId + " 私钥: " + recoveredKey);
            System.out.println("与原始私钥一致: " + recoveredKey.equals(ta.doPrivateKeys.get(missingDOId))); // 验证一致性
        }

        // 模拟掉线 DO 的密文为加密的全 0 数据
        for (int missingDOId : missingDOIds) {
            // 创建全0模型参数数组
            BigInteger[] zeroCiphertext = new BigInteger[5];
            for (int i = 0; i < 5; i++) {
                zeroCiphertext[i] = csp.encryptZeroData(recoveredKeys.get(missingDOId), ta.getN(), ta.getG(),
                        ta.getH());
            }
            csp.receiveData(missingDOId, zeroCiphertext);
        }

        // 聚合所有密文并解密
        BigInteger[] aggregated = csp.aggregate(ta.getN());
        List<BigInteger> allPrivateKeys = new ArrayList<>();
        for (int i = 0; i < numDO; i++) {
            if (missingDOIds.contains(i)) {
                allPrivateKeys.add(recoveredKeys.get(i)); // 使用恢复的私钥
            } else {
                allPrivateKeys.add(ta.doPrivateKeys.get(i)); // 使用原始私钥
            }
        }
        double[] decryptedParams = csp.decrypt(aggregated, ta.getLambda(), ta.getN(), ta.getU(), ta.y, allPrivateKeys);
        // 计算在线DO数量（总数减去掉线数量）
        int activeCount = numDO - missingDOIds.size();
        double[] averagedParams = csp.calculateAverage(decryptedParams, activeCount);

        System.out.println("解密后的聚合模型参数: " + Arrays.toString(decryptedParams));
        System.out.println("平均后的全局模型参数: " + Arrays.toString(averagedParams));
    }
}