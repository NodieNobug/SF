package com.example;

import javax.swing.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

public class All_Test {
    public static void main(String[] args) {
        int numDO = 4; // DO数量
        int numRounds = 10; // 联邦学习轮次
        List<DO> doList = new ArrayList<>();
        CSP csp = null;

        // 初始化全局模型参数（初始为零向量）
        double[] globalModelParams = new double[5];
        Arrays.fill(globalModelParams, 0.0);

        // 用于记录每一轮的模型参数值
        List<double[]> globalModelHistory = new ArrayList<>();

        for (int round = 1; round <= numRounds; round++) {
            System.out.println("\n===== 联邦学习第 " + round + " 轮 =====");

            // 1. TA生成全局参数和正交矩阵
            BigInteger[] modelParamHashes = generateModelParamHashes(globalModelParams);
            TA ta = new TA(numDO, modelParamHashes);

            // 2. 初始化DO和CSP（第一轮）或更新TA参数（后续轮次）
            if (round == 1) {
                for (int i = 0; i < numDO; i++) {
                    doList.add(new DO(i, ta));
                }
                csp = new CSP(ta, numDO);
            } else {
                for (DO doObj : doList) {
                    doObj.updateTA(ta); // 更新TA参数
                }
                csp.updateTA(ta); // 更新CSP的TA参数
            }

            // 3. DO接收全局模型参数并进行本地训练
            for (DO doObj : doList) {
                doObj.updateGlobalModelParams(globalModelParams); // 接收全局模型参数
                System.out.println("DO " + doObj.getId() + " 更新后的全局模型参数: " + Arrays.toString(globalModelParams));
                doObj.trainModel(); // 本地训练
                doObj.encryptData(ta.getN(), ta.getG(), ta.getH()); // 加密模型参数
                csp.receiveData(doObj.getId(), doObj.getEncryptedModelParams()); // 上传加密模型参数

                doObj.calculateProjections(); // 计算投影结果
                csp.receiveProjections(doObj.getId(), doObj.getProjectionResults()); // 上传投影结果
            }

            // 4. CSP聚合模型参数并解密
            BigInteger[] aggregatedParams = csp.aggregate(ta.getN());
            double[] decryptedParams = csp.decrypt(aggregatedParams, ta.getLambda(), ta.getN(), ta.getU(), ta.getY());
            System.out.println("CSP 解密得到的聚合模型参数: " + Arrays.toString(decryptedParams));

            // 5. CSP进行投毒检测
            List<Integer> suspectedDOs = csp.detectPoisoning(decryptedParams);
            if (!suspectedDOs.isEmpty()) {
                System.out.println("检测到可疑的DO: " + suspectedDOs);
            } else {
                System.out.println("未检测到投毒行为");
            }

            // 6. 计算全局模型参数并分发给DO
            globalModelParams = csp.calculateAverage(decryptedParams, numDO); // 基于在线DO数量求均值
            System.out.println("CSP 分发的全局模型参数: " + Arrays.toString(globalModelParams));

            // 记录当前轮次的模型参数
            globalModelHistory.add(Arrays.copyOf(globalModelParams, globalModelParams.length));

            // 7. 清理CSP状态
            csp.clearState();
        }
        for (double[] globalModelHistory2 : globalModelHistory) {
            System.out.println("轮次 " + (globalModelHistory.indexOf(globalModelHistory2) + 1) + ": "
                    + Arrays.toString(globalModelHistory2));
        }

    }

    /**
     * 使用全局模型参数生成模型参数哈希值
     */
    private static BigInteger[] generateModelParamHashes(double[] globalModelParams) {
        BigInteger[] modelParamHashes = new BigInteger[globalModelParams.length];
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String modelParams = Arrays.toString(globalModelParams);
            byte[] hashBytes = digest.digest(modelParams.getBytes(StandardCharsets.UTF_8));
            for (int i = 0; i < globalModelParams.length; i++) {
                modelParamHashes[i] = new BigInteger(1, hashBytes);
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return modelParamHashes;
    }

    /**
     * 可视化模型参数变化
     */

}
