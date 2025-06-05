package com.example;

import java.math.BigInteger;
import java.security.SecureRandom;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Arrays;
import java.util.Set;
import java.util.HashSet;

// CSP 类：负责聚合各个 DO 上传的密文、判断是否有 DO 掉线、请求备用分片恢复私钥，并进行解密
class CSP {
    private TA ta;
    private int totalDO;
    private static final int MODEL_SIZE = 5;
    private static final double CLUSTER_DISTANCE_THRESHOLD = 0.3;
    public Map<Integer, BigInteger> receivedCiphertexts = new HashMap<>();
    public Map<Integer, BigInteger[]> receivedModelParams = new HashMap<>();
    public Map<Integer, double[]> receivedProjections = new HashMap<>();
    public BigInteger aggregatedCiphertext;
    public BigInteger[] aggregatedModelParams;
    private double[][] orthogonalVectors;
    public double[][] orthogonalVectorsForCSP; // 存储分给CSP的向量组部分
    private BigInteger[] currentModelParamHashes; // 添加字段存储当前轮次的模型参数哈希值
    private Map<Integer, BigInteger[]> firstRoundResults = new HashMap<>(); // 存储第一轮结果
    private Map<Integer, BigInteger[]> secondRoundResults = new HashMap<>(); // 存储第二轮结果
    private Map<Integer, BigInteger> recoveredNiValues = new HashMap<>(); // 存储恢复的n_i值

    public CSP(TA ta, int totalDO) {
        this.ta = ta;
        this.totalDO = totalDO;
        this.orthogonalVectors = ta.getOrthogonalVectors();
        this.orthogonalVectorsForCSP = ta.getOrthogonalVectorsForCSP();
    }

    // 写一个get方法获取orthogonalVectorsForCSP
    public double[][] getOrthogonalVectorsForCSP() {
        return orthogonalVectorsForCSP;
    }

    // 写一个get方法获取orthogonalVectors
    public double[][] getOrthogonalVectors() {
        return orthogonalVectors;
    }

    /**
     * 接收来自 DO 的加密数据
     */
    public void receiveData(int doId, BigInteger ciphertext) {
        receivedCiphertexts.put(doId, ciphertext);
    }

    /**
     * 接收来自DO的加密模型参数
     */
    public void receiveData(int doId, BigInteger[] encryptedParams) {
        receivedModelParams.put(doId, encryptedParams);
    }

    /**
     * 接收来自DO的投影结果
     */
    public void receiveProjections(int doId, double[] projections) {
        receivedProjections.put(doId, projections);
    }

    /**
     * 聚合所有DO的加密模型参数
     */

    public BigInteger[] aggregate(BigInteger N) {
        aggregatedModelParams = new BigInteger[MODEL_SIZE];
        for (int i = 0; i < MODEL_SIZE; i++) {
            aggregatedModelParams[i] = BigInteger.ONE;
            for (BigInteger[] params : receivedModelParams.values()) {
                // 连乘，得到了聚合的模型参数[[X]]
                aggregatedModelParams[i] = aggregatedModelParams[i].multiply(params[i]).mod(N.multiply(N));
            }
        }
        return aggregatedModelParams;
    }

    /**
     * 正常情况下的解密方法
     */
    public double[] decrypt(BigInteger[] aggregated, BigInteger lambda, BigInteger N,
            BigInteger u, BigInteger y) {
        double[] decryptedParams = new double[MODEL_SIZE];
        BigInteger N2 = N.multiply(N);

        for (int i = 0; i < MODEL_SIZE; i++) {
            BigInteger L = aggregated[i].modPow(lambda, N2)
                    .subtract(BigInteger.ONE).divide(N);

            BigInteger decrypted = L.multiply(u).mod(N).mod(y);

            // 在BigInteger阶段处理负数情况
            if (decrypted.compareTo(y.divide(BigInteger.TWO)) > 0) {
                System.out.println("" + i + " 号参数溢出，进行修正.....");
                decrypted = decrypted.subtract(y);
            }

            // 将处理后的BigInteger转换为double（除以10^6恢复精度）
            decryptedParams[i] = decrypted.doubleValue() / 1000000.0;
        }
        return decryptedParams;
    }

    /**
     * DO掉线情况下的解密方法
     */
    public double[] decryptWithRecovery(BigInteger[] aggregated, BigInteger lambda, BigInteger N,
            BigInteger u, BigInteger y) {
        double[] decryptedParams = new double[MODEL_SIZE];
        BigInteger N2 = N.multiply(N);

        // 计算所有恢复的n_i值的和
        BigInteger sumNi = BigInteger.ZERO;
        for (BigInteger ni : recoveredNiValues.values()) {
            sumNi = sumNi.add(ni);
        }

        // 计算R_t^sumNi
        BigInteger R_t = ta.getR_t();
        BigInteger R_t_pow_sumNi = R_t.modPow(sumNi, N2);

        for (int i = 0; i < MODEL_SIZE; i++) {
            // 在密文上乘以R_t^sumNi
            BigInteger modifiedCiphertext = aggregated[i].multiply(R_t_pow_sumNi).mod(N2);
            System.out.println("\n在密文上乘以R_t^sumNi后的密文: " + modifiedCiphertext);

            BigInteger L = modifiedCiphertext.modPow(lambda, N2)
                    .subtract(BigInteger.ONE).divide(N);

            BigInteger decrypted = L.multiply(u).mod(N).mod(y);
            System.out.println("\n有DO掉线时解密的结果： " + decrypted);

            // 在BigInteger阶段处理负数情况
            if (decrypted.compareTo(y.divide(BigInteger.TWO)) > 0) {
                System.out.println("" + i + " 号参数溢出，进行修正.....");
                decrypted = decrypted.subtract(y);
            }

            // 将处理后的BigInteger转换为double（除以10^6恢复精度）
            decryptedParams[i] = decrypted.doubleValue() / 1000000.0;
        }
        return decryptedParams;
    }

    /**
     * 计算模型参数的平均值
     * 
     * @param aggregatedParams 聚合后的参数
     * @param activeCount      在线的DO数量
     */
    public double[] calculateAverage(double[] aggregatedParams, int activeCount) {
        double[] averagedParams = new double[MODEL_SIZE];
        for (int i = 0; i < MODEL_SIZE; i++) {
            averagedParams[i] = aggregatedParams[i] / activeCount;
        }
        return averagedParams;
    }

    /**
     * 判断是否有 DO 掉线：即收到的密文数量是否少于 totalDO。
     */
    public boolean hasDropout() {
        return receivedCiphertexts.size() < totalDO;
    }

    /**
     * 如果检测到某个 DO 掉线，则向在线 DO 请求 TA 分发的该 DO 的私钥分片，
     * 并利用拉格朗日插值恢复出掉线 DO 的私钥。
     *
     * availableDOs：在线的 DO 列表（不包含掉线 DO）。
     */
    // public BigInteger recoverMissingPrivateKey(int missingDOId, List<DO>
    // availableDOs) {
    // Map<Integer, BigInteger> shares = new HashMap<>();
    // for (DO doObj : availableDOs) {
    // int xValue = doObj.getId() + 1; // 确保 x 值唯一且与 DO ID 对应
    // BigInteger share = doObj.uploadKeyShare(missingDOId);
    // shares.put(xValue, share);
    // }
    // // 使用TA的门限值
    // if (shares.size() < ta.getThreshold()) {
    // throw new IllegalStateException("分片数量不足" + ta.getThreshold() + "个，无法恢复私钥");
    // }
    // BigInteger recoveredKey = Threshold.reconstructSecret(shares, ta.getN()); //
    // 确保模数一致
    // System.out.println("收集到 " + shares.size() + " 个分片");
    // // System.out.println("恢复掉线 DO " + missingDOId + " 的私钥为: " + recoveredKey);
    // return recoveredKey;
    // }

    /**
     * 恢复多个掉线 DO 的n_i值
     */
    public Map<Integer, BigInteger> recoverMissingPrivateKeys(List<Integer> missingDOIds, List<DO> availableDOs) {
        recoveredNiValues.clear(); // 清空之前的值
        BigInteger modulus = ta.getN(); // 使用N作为模数，因为n_i是在模N下的值

        for (int missingDOId : missingDOIds) {
            System.out.println("\n开始恢复 DO " + missingDOId + " 的n_i值\n");
            Map<Integer, BigInteger> shares = new HashMap<>();

            for (DO doObj : availableDOs) {
                int xValue = doObj.getId() + 1;
                BigInteger share = doObj.uploadKeyShare(missingDOId);
                if (share != null) {
                    shares.put(xValue, share);
                }
            }

            if (shares.size() < ta.getThreshold()) {
                throw new IllegalStateException("分片数量不足" + ta.getThreshold() + "个，当前只有: " + shares.size() + "个");
            }

            BigInteger recoveredNi = Threshold.reconstructSecret(shares, modulus); // 使用N作为模数
            recoveredNiValues.put(missingDOId, recoveredNi);
        }
        return recoveredNiValues;
    }

    /**
     * 计算聚合参数与正交向量组的点积结果
     * 
     * @param aggregatedParams 解密后的聚合参数
     * @return 点积结果数组
     */
    private double[] calculateDotProductsWithOrthogonalVectors(double[] aggregatedParams) {
        double[] cspDotProducts = new double[orthogonalVectors.length];
        for (int i = 0; i < orthogonalVectors.length; i++) {
            double dotProduct = 0;
            for (int j = 0; j < MODEL_SIZE; j++) {
                dotProduct += orthogonalVectors[i][j] * aggregatedParams[j];
            }
            cspDotProducts[i] = dotProduct;
        }
        return cspDotProducts;
    }

    /**
     * 基于点积结果比较和聚类分析进行投毒检测，接收解密得到的聚合后的模型参数值。
     */
    public List<Integer> detectPoisoning(double[] aggregatedParams) {
        List<Integer> suspectedDOs = new ArrayList<>();

        // 1. 计算聚合参数与正交向量组的点积
        double[] cspDotProducts = calculateDotProductsWithOrthogonalVectors(aggregatedParams);

        // 2. 获取DO上传的点积结果聚合
        double[] doDotProducts = calculateAggregatedProjections();

        // 3. 比较两个结果是否一致（考虑浮点数误差）
        double threshold = 1e-3;
        System.out.println("\n第一轮聚合参数计算的点积结果: " + Arrays.toString(cspDotProducts));
        System.out.println("第二轮DO上传的点积结果聚合: " + Arrays.toString(doDotProducts));

        // 计算相对误差
        boolean consistent = true;
        for (int i = 0; i < cspDotProducts.length; i++) {
            double absoluteError = Math.abs(cspDotProducts[i] - doDotProducts[i]);
            double relativeError = 0;

            if (Math.abs(cspDotProducts[i]) > 1e-10) {
                relativeError = absoluteError / Math.abs(cspDotProducts[i]);
            } else if (Math.abs(doDotProducts[i]) > 1e-10) {
                relativeError = absoluteError / Math.abs(doDotProducts[i]);
            } else {
                relativeError = absoluteError;
            }

            if (relativeError > threshold) {
                consistent = false;
                System.out.printf("索引 %d 的相对误差: %.10f\n", i, relativeError);
                break;
            }
        }

        // 4. 进行聚类分析
        Map<Integer, double[]> normalizedProjections = new HashMap<>();
        List<Integer> doIds = new ArrayList<>(receivedProjections.keySet());
        for (int doId : doIds) {
            normalizedProjections.put(doId, normalizeVector(receivedProjections.get(doId)));
        }
        List<List<Integer>> clusters = clusterProjections(normalizedProjections, doIds);
        List<Integer> largestCluster = findLargestCluster(clusters);

        // 5. 根据结果综合判断
        if (!consistent) {
            System.out.println("警告：检测到DO在两轮中使用了不同的参数！");
            for (int doId : doIds) {
                if (!largestCluster.contains(doId)) {
                    suspectedDOs.add(doId);
                }
            }
        } else if (clusters.size() > 1) {
            System.out.println("DO在两轮使用了相同的参数，但通过聚类分析发现异常模式");
            for (int doId : doIds) {
                if (!largestCluster.contains(doId)) {
                    suspectedDOs.add(doId);
                }
            }
        }

        // 6. 输出分析结果
        System.out.println("\n检测分析结果：");
        System.out.println("参数一致性检查: " + (consistent ? "通过" : "未通过"));
        System.out.println("聚类数量: " + clusters.size());
        System.out.println("最大聚类大小: " + largestCluster.size());
        if (!suspectedDOs.isEmpty()) {
            System.out.println("可疑的DO: " + suspectedDOs);
        }

        return suspectedDOs;
    }

    // 聚合来自DO的点积结果
    private double[] calculateAggregatedProjections() {
        double[] aggregatedProjections = new double[orthogonalVectors.length];
        for (double[] projections : receivedProjections.values()) {
            for (int i = 0; i < orthogonalVectors.length; i++) {
                aggregatedProjections[i] += projections[i];
            }
        }
        return aggregatedProjections;
    }

    private List<List<Integer>> clusterProjections(Map<Integer, double[]> normalizedProjections, List<Integer> doIds) {
        List<List<Integer>> clusters = new ArrayList<>();
        Set<Integer> visitedDOs = new HashSet<>();

        for (int doId : doIds) {
            if (visitedDOs.contains(doId))
                continue;

            List<Integer> currentCluster = new ArrayList<>();
            expandCluster(doId, normalizedProjections, visitedDOs, currentCluster, doIds);

            if (!currentCluster.isEmpty()) {
                clusters.add(currentCluster);
            }
        }
        return clusters;
    }

    private List<Integer> findLargestCluster(List<List<Integer>> clusters) {
        return clusters.stream()
                .max((c1, c2) -> Integer.compare(c1.size(), c2.size()))
                .orElse(new ArrayList<>());
    }

    private void expandCluster(int currentDoId,
            Map<Integer, double[]> normalizedProjections,
            Set<Integer> visitedDOs,
            List<Integer> currentCluster,
            List<Integer> allDoIds) {

        visitedDOs.add(currentDoId);
        currentCluster.add(currentDoId);

        for (int neighborId : allDoIds) {
            if (visitedDOs.contains(neighborId))
                continue;

            double similarity = calculateCosineSimilarity(
                    normalizedProjections.get(currentDoId),
                    normalizedProjections.get(neighborId));

            if (similarity > (1 - CLUSTER_DISTANCE_THRESHOLD)) {
                expandCluster(neighborId, normalizedProjections, visitedDOs, currentCluster, allDoIds);
            }
        }
    }

    private double[] normalizeVector(double[] vector) {
        double[] normalized = new double[vector.length];
        double norm = 0;
        for (double val : vector) {
            norm += val * val;
        }
        norm = Math.sqrt(norm);
        if (norm > 0) {
            for (int i = 0; i < vector.length; i++) {
                normalized[i] = vector[i] / norm;
            }
        }
        return normalized;
    }

    private double calculateCosineSimilarity(double[] vector1, double[] vector2) {
        double dotProduct = 0;
        double norm1 = 0;
        double norm2 = 0;
        for (int i = 0; i < vector1.length; i++) {
            dotProduct += vector1[i] * vector2[i];
            norm1 += vector1[i] * vector1[i];
            norm2 += vector2[i] * vector2[i];
        }
        double norm = Math.sqrt(norm1) * Math.sqrt(norm2);
        return norm == 0 ? 0 : dotProduct / norm;
    }

    /**
     * 更新TA参数
     */
    public void updateTA(TA newTA) {
        this.ta = newTA;
        this.orthogonalVectors = newTA.getOrthogonalVectors();

        System.out.println("CSP 更新了TA的全局参数和正交向量");
    }

    /**
     * 清理CSP的状态
     */
    public void clearState() {
        receivedModelParams.clear();
        receivedProjections.clear();
        firstRoundResults.clear(); // 清理第一轮结果
        secondRoundResults.clear(); // 清理第二轮结果
        recoveredNiValues.clear(); // 清理恢复的n_i值
        System.out.println("CSP 状态已清理，准备进入下一轮联邦学习");
    }

    /**
     * 二分查找恶意DO
     * 
     * @param doIds 当前需要检查的DO ID列表
     * @param ta    当前轮次的TA对象
     * @return 恶意DO的ID
     */
    public int findMaliciousDO(List<Integer> doIds, TA ta) {
        // 基本情况：如果只剩一个DO，就是恶意DO
        if (doIds.size() == 1) {
            return doIds.get(0);
        }

        // 将DO列表分成两半
        int mid = doIds.size() / 2;
        List<Integer> firstHalf = doIds.subList(0, mid);
        List<Integer> secondHalf = doIds.subList(mid, doIds.size());

        System.out.println("检查前半部分DO: " + firstHalf);
        System.out.println("检查后半部分DO: " + secondHalf);

        // 计算前半部分DO的聚合值
        BigInteger[] firstHalfAggregated = aggregatePartialDOs(firstHalf, ta);
        double[] firstHalfDecrypted = decryptPartialAggregation(firstHalfAggregated, firstHalf, ta);

        // 计算后半部分DO的聚合值
        BigInteger[] secondHalfAggregated = aggregatePartialDOs(secondHalf, ta);
        double[] secondHalfDecrypted = decryptPartialAggregation(secondHalfAggregated, secondHalf, ta);

        // 检查哪一部分的聚合值不一致
        if (isAggregationConsistent(firstHalfDecrypted, firstHalf)) {
            System.out.println("前半部分DO的聚合值一致，恶意DO在后半部分");
            return findMaliciousDO(secondHalf, ta);
        } else {
            System.out.println("前半部分DO的聚合值不一致，恶意DO在前半部分");
            return findMaliciousDO(firstHalf, ta);
        }
    }

    /**
     * 聚合部分DO的加密模型参数
     */
    private BigInteger[] aggregatePartialDOs(List<Integer> doIds, TA ta) {
        BigInteger N = ta.getN();
        BigInteger N2 = N.multiply(N);
        BigInteger R_t = ta.getR_t();
        BigInteger[] aggregated = new BigInteger[MODEL_SIZE];
        Arrays.fill(aggregated, BigInteger.ONE);

        // 计算当前要计算的DO的n_i之和
        BigInteger sumNi = BigInteger.ZERO;
        for (int doId : doIds) {
            BigInteger n_i = ta.getNi(doId);
            sumNi = sumNi.add(n_i);
        }
        sumNi = N.subtract(sumNi); // 计算N - sumNi

        // 计算R_t^sumNi
        BigInteger R_t_pow_sumNi = R_t.modPow(sumNi, N2);

        // 聚合目标DO的加密参数
        for (int doId : doIds) {
            BigInteger[] encryptedParams = receivedModelParams.get(doId);
            for (int i = 0; i < MODEL_SIZE; i++) {
                aggregated[i] = aggregated[i].multiply(encryptedParams[i]).mod(N2);
            }
        }

        // 在密文上乘以R_t^sumNi
        for (int i = 0; i < MODEL_SIZE; i++) {
            aggregated[i] = aggregated[i].multiply(R_t_pow_sumNi).mod(N2);
        }

        return aggregated;
    }

    /**
     * 解密部分DO的聚合值
     */
    private double[] decryptPartialAggregation(BigInteger[] aggregated, List<Integer> doIds, TA ta) {
        BigInteger N = ta.getN();
        BigInteger N2 = N.multiply(N);
        BigInteger lambda = ta.getLambda();
        BigInteger u = ta.getU();
        BigInteger y = ta.getY();

        double[] decryptedParams = new double[MODEL_SIZE];

        System.out.println("\n当前检查的DO: " + doIds);
        System.out.println("部分DO聚合后的加密模型参数:");

        for (int i = 0; i < MODEL_SIZE; i++) {
            // 解密过程
            BigInteger L = aggregated[i].modPow(lambda, N2)
                    .subtract(BigInteger.ONE).divide(N);

            // 修改：只使用mod(y)，移除mod(N)
            BigInteger decrypted = L.multiply(u).mod(N).mod(y);

            // 处理负数情况
            if (decrypted.compareTo(y.divide(BigInteger.TWO)) > 0) {
                decrypted = decrypted.subtract(y);
            }

            decryptedParams[i] = decrypted.doubleValue() / 1000000.0;
            System.out.println("解密后的模型参数 " + i + ": " + decryptedParams[i]);
        }

        return decryptedParams;
    }

    /**
     * 检查聚合值是否一致
     */
    private boolean isAggregationConsistent(double[] params, List<Integer> doIds) {
        // 1. 使用参数与正交向量组计算点积
        double[] cspDotProducts = new double[orthogonalVectors.length];
        for (int i = 0; i < orthogonalVectors.length; i++) {
            double dotProduct = 0;
            for (int j = 0; j < MODEL_SIZE; j++) {
                dotProduct += orthogonalVectors[i][j] * params[j];
            }
            cspDotProducts[i] = dotProduct;
        }

        // 2. 计算选定DO的投影结果聚合
        double[] doDotProducts = new double[orthogonalVectors.length];
        for (int i = 0; i < orthogonalVectors.length; i++) {
            doDotProducts[i] = 0;
            // 只计算当前检查的DO的投影结果
            for (int doId : doIds) {
                if (receivedProjections.containsKey(doId)) {
                    doDotProducts[i] += receivedProjections.get(doId)[i];
                }
            }
        }

        // 3. 比较两个结果是否一致（考虑浮点数误差）
        double threshold = 1e-3;
        System.out.println("\n当前部分DO聚合参数计算的点积结果: " + Arrays.toString(cspDotProducts));
        System.out.println("当前部分DO上传的点积结果聚合: " + Arrays.toString(doDotProducts));

        // 计算相对误差
        for (int i = 0; i < cspDotProducts.length; i++) {
            double absoluteError = Math.abs(cspDotProducts[i] - doDotProducts[i]);
            double relativeError = 0;

            if (Math.abs(cspDotProducts[i]) > 1e-10) {
                relativeError = absoluteError / Math.abs(cspDotProducts[i]);
            } else if (Math.abs(doDotProducts[i]) > 1e-10) {
                relativeError = absoluteError / Math.abs(doDotProducts[i]);
            } else {
                relativeError = absoluteError;
            }

            if (relativeError > threshold) {
                System.out.printf("索引 %d 的相对误差: %.10f\n", i, relativeError);
                return false;
            }
        }
        return true;
    }

    /**
     * 检测掉线的DO
     * 
     * @param doList DO列表
     * @return 掉线DO的ID列表
     */
    public List<Integer> detectDroppedDOs(List<DO> doList) {
        List<Integer> droppedDOs = new ArrayList<>();
        for (int i = 0; i < doList.size(); i++) {
            if (doList.get(i) == null) {
                droppedDOs.add(i);
            }
        }
        return droppedDOs;
    }

    /**
     * 安全向量点积
     */

    int k1 = 1024; // p的比特长度 建议128以上
    int k2 = 64; // alpha的比特长度取 40-64之间
    int k3 = 32; // c_i的比特长度
    int k4 = 32; // r_i的比特长度
    SecureRandom random = new SecureRandom();
    BigInteger csp_p = BigInteger.probablePrime(k1, random);
    BigInteger csp_alpha = BigInteger.probablePrime(k2, random);
    BigInteger csp_s = new BigInteger(k1 - 2, random).add(BigInteger.ONE); // s ∈ Z_p
    BigInteger csp_sinv = csp_s.modInverse(csp_p);

    // 加密CSP的一半正交向量组
    public BigInteger[][] encryptCspVectors() {
        int csp_n = orthogonalVectorsForCSP[0].length; // 维度
        BigInteger[][] C = new BigInteger[orthogonalVectorsForCSP.length][csp_n + 2];
        BigInteger[][] c = new BigInteger[orthogonalVectorsForCSP.length][csp_n + 2];

        for (int vecIndex = 0; vecIndex < orthogonalVectorsForCSP.length; vecIndex++) {
            double[] a_ext = Arrays.copyOf(orthogonalVectorsForCSP[vecIndex], csp_n + 2); // 每个向量扩展两位
            for (int i = 0; i < csp_n + 2; i++) {
                c[vecIndex][i] = new BigInteger(k3, random);
                if (a_ext[i] != 0) {
                    BigInteger value = BigInteger.valueOf((long) (a_ext[i] * 1000000)); // 放大精度
                    C[vecIndex][i] = csp_s.multiply(value.multiply(csp_alpha).add(c[vecIndex][i])).mod(csp_p);
                } else {
                    C[vecIndex][i] = csp_s.multiply(c[vecIndex][i]).mod(csp_p);
                }
            }
        }

        return C;
    }

    // 加密的正交向量，alpha,p。用于给DO发送
    public BigInteger[][] getCspEncryptedVectors() {
        return encryptCspVectors();
    }

    public BigInteger getCspP() {
        return csp_p;
    }

    public BigInteger getCspAlpha() {
        return csp_alpha;
    }

    // 接收DO的第一轮结果以及DO的第二轮结果。
    public void receiveFirstRoundResult(int doId, BigInteger[] result) {
        if (result == null || result.length != orthogonalVectorsForCSP.length) {
            throw new IllegalArgumentException("第一轮结果的长度与CSP持有的正交向量组长度不匹配");
        }
        firstRoundResults.put(doId, result);
        // System.out.println("CSP 接收到 DO " + doId + " 的第一轮结果: " +
        // Arrays.toString(result));
    }

    public void receiveSecondRoundResult(int doId, BigInteger[] result) {
        if (result == null || result.length != orthogonalVectorsForCSP.length) {
            throw new IllegalArgumentException("第二轮结果的长度与CSP持有的正交向量组长度不匹配");
        }
        secondRoundResults.put(doId, result);
        // System.out.println("CSP 接收到 DO " + doId + " 的第二轮结果: " +
        // Arrays.toString(result));
    }

    // 计算最终的点积结果
    public BigInteger[] calculateFinalDotProduct(int doId, BigInteger p) {
        BigInteger[] finalResults = new BigInteger[orthogonalVectorsForCSP.length];
        BigInteger[] firstRound = firstRoundResults.get(doId);
        BigInteger[] secondRound = secondRoundResults.get(doId);
        BigInteger alpha2 = csp_alpha.multiply(csp_alpha);
        BigInteger halfP = p.divide(BigInteger.valueOf(2));

        // 第一轮结果解密
        BigInteger[] defirstRound = new BigInteger[orthogonalVectorsForCSP.length];
        for (int vecIndex = 0; vecIndex < orthogonalVectorsForCSP.length; vecIndex++) {
            // 解密第一轮结果
            BigInteger E = csp_sinv.multiply(firstRound[vecIndex]).mod(p);

            // 处理负数情况
            if (E.compareTo(halfP) > 0) {
                E = E.subtract(p);
            }

            // 计算内积结果
            BigInteger inner = E.subtract(E.mod(alpha2)).divide(alpha2);
            defirstRound[vecIndex] = inner;
            System.out.println("CSP 第一轮结果解密: " + defirstRound[vecIndex]);
        }

        // 计算最终结果
        for (int i = 0; i < orthogonalVectorsForCSP.length; i++) {
            // 处理第二轮结果的负数
            BigInteger second = secondRound[i];
            if (second.compareTo(halfP) > 0) {
                second = second.subtract(p);
            }
            System.out.println("CSP 第二轮结果: " + second);

            // 将两轮结果相加
            BigInteger result = defirstRound[i].add(second);

            // 将结果调整到[-p/2, p/2]范围内
            while (result.compareTo(p) >= 0) {
                result = result.subtract(p);
            }
            while (result.compareTo(p.negate()) < 0) {
                result = result.add(p);
            }

            // 最终负数调整
            if (result.compareTo(halfP) > 0) {
                result = result.subtract(p);
            }

            finalResults[i] = result;
        }

        return finalResults;
    }

}