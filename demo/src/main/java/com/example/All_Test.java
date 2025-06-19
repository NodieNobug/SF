package com.example;

import java.math.BigInteger;
import java.util.*;

public class All_Test {
    // 记录时间
    private static long startTime;
    private static long endTime;

    // 添加常量定义
    private static final int MODEL_PARAM_LENGTH = 5; // 模型参数维度
    private static final int numDO = 7; // 可以设置更大的DO数量
    private static final int numRounds = 1;// 联邦学习轮次

    // 记录时间
    public static void main(String[] args) {
        startTime = System.currentTimeMillis();
        List<DO> doList = new ArrayList<>();
        CSP csp = null;

        // 初始化全局模型参数（初始为零向量）
        int modelParamLength = MODEL_PARAM_LENGTH;
        double[] globalModelParams = new double[modelParamLength];
        Arrays.fill(globalModelParams, 0.0);

        for (int round = 1; round <= numRounds; round++) {
            System.out.println("\n===== 联邦学习第 " + round + " 轮 =====");

            // 1. TA生成全局参数和正交矩阵

            TA ta = new TA(numDO);

            // 2. 初始化DO和CSP（第一轮）或更新TA参数（后续轮次）
            if (round == 1) {
                for (int i = 0; i < numDO; i++) {
                    doList.add(new DO(i, ta));
                }
                csp = new CSP(ta, numDO);
            } else {
                for (DO doObj : doList) {
                    if (doObj != null) { // 添加null检查
                        doObj.updateTA(ta); // 只有当DO不为null时才更新TA参数
                    }
                }
                csp.updateTA(ta); // 更新CSP的TA参数
            }

            // 3. DO接收全局模型参数并进行本地训练
            for (int i = 0; i < doList.size(); i++) {
                DO doObj = doList.get(i);
                if (round == 3 && Arrays.asList(1, 2).contains(i)) {
                    // 第三轮次：将掉线的DO设置为null
                    doList.set(i, null);
                    System.out.println("DO " + i + " 掉线");
                    continue;
                } else if (round == 4 && doList.get(i) == null) {
                    // 第四轮：恢复掉线的DO
                    doList.set(i, new DO(i, ta));
                    doObj = doList.get(i);
                    System.out.println("DO " + i + " 恢复在线");
                }
                if (doObj == null)
                    continue;

                doObj.updateGlobalModelParams(globalModelParams); // 接收全局模型参数

                doObj.trainModel(); // 本地训练

                // 第四轮和第七轮：模拟一致性投毒（在训练后投毒）
                if ((round == 4 || round == 7) && doObj.getId() == 3) {
                    try {
                        java.lang.reflect.Field field = DO.class.getDeclaredField("localModelParams");
                        field.setAccessible(true);
                        double[] params = (double[]) field.get(doObj);
                        // 将参数方向反转并放大，作为投毒参数
                        for (int j = 0; j < params.length; j++) {
                            params[j] = -params[j] * 5; // 放大5倍并反转方向
                        }
                        // 保存修改后的参数到DO对象中
                        field.set(doObj, params);
                        System.out.println("DO 3 投毒后的参数: " + Arrays.toString(params));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }

                doObj.encryptData(ta.getN(), ta.getG(), ta.getH()); // 加密模型参数
                csp.receiveData(doObj.getId(), doObj.getEncryptedModelParams()); // 获取加密模型参数

                // 第七轮：DO 3在计算点积时使用精心构建的参数
                if (round == 7 && doObj.getId() == 2) {
                    try {
                        java.lang.reflect.Field field = DO.class.getDeclaredField("localModelParams");
                        field.setAccessible(true);
                        // 使用与全局模型参数方向一致的参数
                        double[] fakeParams = new double[5];
                        for (int j = 0; j < fakeParams.length; j++) {
                            // 保持与全局模型参数相同的方向，但稍微调整大小
                            fakeParams[j] = globalModelParams[j] * 0.9;
                        }
                        field.set(doObj, fakeParams);
                        System.out.println("DO 3 使用精心构建的点积参数: " + Arrays.toString(fakeParams));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }

                // 使用新的安全向量点积算法
                // 1. CSP加密自己的正交向量组
                BigInteger[][] encryptedCspVectors = csp.encryptCspVectors();
                BigInteger cspP = csp.getCspP();
                BigInteger cspAlpha = csp.getCspAlpha();

                // 2. DO计算第一轮结果
                BigInteger[] firstRoundResult = doObj.calculateFirstRound(encryptedCspVectors, cspP, cspAlpha);
                csp.receiveFirstRoundResult(doObj.getId(), firstRoundResult);

                // 3. DO计算第二轮结果
                BigInteger[] secondRoundResult = doObj.calculateSecondRound(cspP);
                csp.receiveSecondRoundResult(doObj.getId(), secondRoundResult);

                // 4. CSP计算最终点积结果
                BigInteger[] finalDotProduct = csp.calculateFinalDotProduct(doObj.getId(), cspP);
                System.out.println("DO " + doObj.getId() + " 的最终点积结果: " + Arrays.toString(finalDotProduct));

                // 保存最终点积结果用于后续比较
                csp.receiveProjections(doObj.getId(), finalDotProduct);
            }

            // 4. CSP聚合模型参数并解密
            BigInteger[] aggregatedParams = csp.aggregate(ta.getN());
            double[] decryptedParams = null;
            boolean decryptionFailed = false;
            try {
                decryptedParams = csp.decrypt(aggregatedParams, ta.getLambda(), ta.getN(), ta.getU(), ta.getY());
                System.out.println("CSP 解密得到的聚合模型参数: " + Arrays.toString(decryptedParams));
            } catch (Exception e) {
                System.err.println("解密失败，可能是由于第一轮次的随机哈希值导致的错误");
                decryptionFailed = true;
            }

            if (decryptionFailed) {
                System.out.println("由于解密失败，本轮次的训练结果将被忽略，继续使用上一轮的全局模型参数");
                continue;
            }

            // 5. CSP进行投毒检测
            List<Integer> suspectedDOs = csp.detectPoisoning(decryptedParams);
            if (!suspectedDOs.isEmpty()) {
                System.out.println("检测到可疑的DO: " + suspectedDOs);
            } else {
                System.out.println("未检测到投毒行为");
            }

            // 6. 只在第7轮检测到不一致时使用二分查找
            if (round == 7 && !isAggregationConsistent(decryptedParams)) {
                System.out.println("\n第7轮检测到聚合结果不一致，开始二分查找恶意DO...");
                List<Integer> allDOIds = new ArrayList<>();
                for (int i = 0; i < numDO; i++) {
                    if (!(round == 3 && Arrays.asList(1, 2).contains(i))) { // 排除掉线的DO
                        allDOIds.add(i);
                    }
                }
                int maliciousDOId = csp.findMaliciousDO(allDOIds, ta);
                System.out.println("找到恶意DO: " + maliciousDOId);

                // 从聚合中移除恶意DO的贡献
                BigInteger[] maliciousDOParams = csp.receivedModelParams.get(maliciousDOId);
                for (int i = 0; i < MODEL_PARAM_LENGTH; i++) {
                    aggregatedParams[i] = aggregatedParams[i]
                            .multiply(maliciousDOParams[i].modInverse(ta.getN().multiply(ta.getN())))
                            .mod(ta.getN().multiply(ta.getN()));
                }
            }

            // 7. 计算全局模型参数并分发给DO
            if (round == 3) {
                // 让CSP检测掉线的DO
                List<Integer> droppedDOs = csp.detectDroppedDOs(doList);
                System.out.println("CSP检测到掉线的DO: " + droppedDOs);

                List<DO> availableDOs = new ArrayList<>();
                for (DO doObj : doList) {
                    if (doObj != null) {
                        availableDOs.add(doObj);
                    }
                }

                // 恢复掉线DO的n_i值
                Map<Integer, BigInteger> recoveredNiValues = csp.recoverMissingPrivateKeys(droppedDOs, availableDOs);
                for (int droppedDO : droppedDOs) {
                    System.out.println("恢复的 DO " + droppedDO + " 的n_i值: " + recoveredNiValues.get(droppedDO));
                }

                // 聚合所有DO的数据
                aggregatedParams = csp.aggregate(ta.getN());
                // 使用恢复的n_i值进行解密
                decryptedParams = csp.decryptWithRecovery(aggregatedParams, ta.getLambda(), ta.getN(), ta.getU(),
                        ta.getY());

                // 计算在线DO数量并更新全局模型参数
                globalModelParams = csp.calculateAverage(decryptedParams, numDO - droppedDOs.size()); // 使用在线DO数量计算均值
            } else {
                globalModelParams = csp.calculateAverage(decryptedParams, numDO); // 基于总DO数量求均值
            }

            System.out.println("CSP 分发的全局模型参数: " + Arrays.toString(globalModelParams));

            // 7. 清理CSP状态（移到二分查找之后）
            csp.clearState();

        }

        endTime = System.currentTimeMillis();
        System.out.println("程序运行时间：" + (endTime - startTime) + "ms");
    }

    /**
     * 检查聚合值是否一致
     */
    private static boolean isAggregationConsistent(double[] params) {
        // 计算与预期值的差异
        double threshold = 1e-3;
        for (int i = 0; i < params.length; i++) {
            if (Math.abs(params[i]) > threshold) {
                return false;
            }
        }
        return true;
    }
}
