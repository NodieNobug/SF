package com.example;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

public class dot_mul {
    private static final int NUM_DO = 5;
    private static final int MODEL_SIZE = 5;
    private static final int ORTHOGONAL_VECTOR_COUNT = 5;

    public static void main(String[] args) {
        // 初始化测试数据 - 模拟DO的localModelParams
        double[][] doModelParams = new double[NUM_DO][MODEL_SIZE];
        for (int i = 0; i < NUM_DO; i++) {
            doModelParams[i] = new double[] { 6.28, 1.73, 2.51, 3.14, 5.92 };
        }

        // 初始化TA
        BigInteger[] initialHashes = new BigInteger[NUM_DO];
        Arrays.fill(initialHashes, BigInteger.ONE);
        TA ta = new TA(NUM_DO, initialHashes);

        // 初始化CSP - CSP将获得完整的正交向量组和一半分解的向量组
        CSP csp = new CSP(ta, NUM_DO);

        // 初始化多个DO - 每个DO获得另一半分解的向量组
        List<DO> doList = new ArrayList<>();
        for (int i = 0; i < NUM_DO; i++) {
            DO doObj = new DO(i, ta);
            // 设置DO的本地模型参数
            try {
                java.lang.reflect.Field field = DO.class.getDeclaredField("localModelParams");
                field.setAccessible(true);
                field.set(doObj, doModelParams[i]);
            } catch (Exception e) {
                e.printStackTrace();
            }
            doList.add(doObj);
        }

        System.out.println("\n=== 开始安全向量点积测试 ===\n");

        // 1. CSP加密自己的一半正交向量组
        BigInteger[][] encryptedCspVectors = csp.encryptCspVectors();
        BigInteger csp_p = csp.getCspP();
        BigInteger csp_alpha = csp.getCspAlpha();

        System.out.println("CSP加密的正交向量组：");
        for (BigInteger[] vector : encryptedCspVectors) {
            System.out.println(Arrays.toString(vector));
        }
        System.out.println("p: " + csp_p);
        System.out.println("alpha: " + csp_alpha);

        // 2. 每个DO先生成随机数r，再进行第一轮计算
        for (DO doObj : doList) {
            // 先生成随机数dot_r
            doObj.getDot_r();
            // DO计算第一轮结果
            BigInteger[] firstRoundResult = doObj.calculateFirstRound(encryptedCspVectors, csp_p, csp_alpha);
            // DO将第一轮结果发送给CSP
            csp.receiveFirstRoundResult(doObj.getId(), firstRoundResult);
        }

        // 3. 每个DO进行第二轮计算
        for (DO doObj : doList) {
            // DO计算第二轮结果
            BigInteger[] secondRoundResult = doObj.calculateSecondRound(csp_p);
            // DO将第二轮结果发送给CSP
            csp.receiveSecondRoundResult(doObj.getId(), secondRoundResult);
        }

        // 4. CSP计算最终点积结果并验证
        System.out.println("\n=== CSP计算最终点积结果 ===\n");
        Map<Integer, BigInteger[]> allDotProducts = new HashMap<>();

        for (DO doObj : doList) {
            BigInteger[] finalResult = csp.calculateFinalDotProduct(doObj.getId(), csp_p);
            allDotProducts.put(doObj.getId(), finalResult);
            System.out.println("DO " + doObj.getId() + " 的最终安全点积结果：");

            for (int i = 0; i < finalResult.length; i++) {
                BigInteger value = finalResult[i];
                // 负数还原
                if (value.compareTo(csp_p.shiftRight(1)) > 0) { // value > p/2
                    value = value.subtract(csp_p);
                }
                double actualValue = value.doubleValue() / (1_000_000.0 * 1_000_000.0);
                System.out.printf("向量 %d 的点积: %.6f\n", i, actualValue);
            }
        }

        // 验证CSP计算结果的正确性
        System.out.println("\n=== 验证计算结果 ===\n");
        for (DO doObj : doList) {
            // 获取DO的本地模型参数
            double[] localParams = doObj.getLocalModelParams();
            // 获取DO的投影结果（通过正常点积计算）
            doObj.calculateProjections();
            double[] projectionResults = doObj.getProjectionResults();

            System.out.println("DO " + doObj.getId() + " 验证结果：");
            System.out.println("原始投影结果：" + Arrays.toString(projectionResults));

            // 比较安全计算结果与原始结果
            BigInteger[] secureResults = allDotProducts.get(doObj.getId());
            System.out.println("安全计算结果：");
            for (int i = 0; i < secureResults.length; i++) {
                BigInteger value = secureResults[i];
                if (value.compareTo(csp_p.shiftRight(1)) > 0) {
                    value = value.subtract(csp_p);
                }
                double secureValue = value.doubleValue() / (1_000_000.0 * 1_000_000.0);
                System.out.printf("向量 %d - 原始值: %.6f, 安全计算值: %.6f, 误差: %.6f\n",
                        i, projectionResults[i], secureValue,
                        Math.abs(projectionResults[i] - secureValue));
            }
            System.out.println();
        }

        // 在main函数中，计算所有原始点积的绝对值最大值
        double maxAbs = 0;
        for (DO doObj : doList) {
            doObj.calculateProjections();
            double[] projectionResults = doObj.getProjectionResults();
            for (double v : projectionResults) {
                double abs = Math.abs(v * 1_000_000.0 * 1_000_000.0);
                if (abs > maxAbs)
                    maxAbs = abs;
            }
        }
        System.out.println("放大后点积最大绝对值: " + maxAbs);
        System.out.println("p: " + csp_p);
    }
}
