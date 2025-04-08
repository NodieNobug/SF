package com.example;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

// DO 类：负责本地数据处理、模型训练、数据加密，以及存储 TA 分发来的其它 DO 的密钥分片
class DO {
    private int id;
    private TA ta; // 用于获取全局参数及自己的主私钥
    private CSP csp; // 模拟与 CSP 通信（在部分场景下可通过调用方法实现）
    private static final int MODEL_SIZE = 5; // 模型参数大小：4个权重 + 1个偏置
    private double[] localModelParams; // 存储本地模型参数
    private BigInteger[] encryptedModelParams; // 存储加密后的模型参数数组
    private double[][] localData; // 本地训练数据
    private double[] localLabels; // 本地训练标签
    public BigInteger localDataValue; // 模拟本地数据（例如训练后的梯度或参数）
    public BigInteger encryptedData; // 加密后的数据
    // 本 DO 的主私钥，由 TA 生成
    public BigInteger myPrivateKey;
    private BigInteger basePrivateKey; // 新增：存储TA分发的基础私钥
    private BigInteger modelParamHash; // 新增：存储模型参数哈希值
    // 存储 TA 分发来的其它 DO 对本 DO 私钥的备用分片，用于恢复掉线时的私钥（key: 来源 DO id, value: 分片值）
    public Map<Integer, BigInteger> receivedKeyShares = new HashMap<>();
    // 存储 TA 分发的哈希算法类型
    public String hashAlgorithm;
    private double[] projectionResults;
    private double[][] orthogonalVectors;

    public DO(int id, TA ta) {
        this.id = id;
        this.ta = ta;
        this.basePrivateKey = ta.doPrivateKeys.get(id);
        this.myPrivateKey = this.basePrivateKey; // 初始化为基础私钥
        this.hashAlgorithm = ta.getHashAlgorithm();
        this.localModelParams = new double[MODEL_SIZE];
        this.encryptedModelParams = new BigInteger[MODEL_SIZE];
        this.orthogonalVectors = ta.getOrthogonalVectors();
        this.projectionResults = new double[orthogonalVectors.length]; // 长度为5，对应5个正交向量

        // 存储分给本DO的所有其他DO的私钥分片
        for (Map.Entry<Integer, Map<Integer, BigInteger>> entry : ta.doKeyShares.entrySet()) {
            int sourceDOId = entry.getKey();
            Map<Integer, BigInteger> shares = entry.getValue();
            if (shares.containsKey(this.id)) {
                receivedKeyShares.put(sourceDOId, shares.get(this.id));
            }
        }
        // System.out.println("DO " + id + " 收到的分片: " + receivedKeyShares);
    }

    public int getId() {
        return id;
    }

    /**
     * 生成模拟训练数据
     */
    private void generateTrainingData() {
        int dataSize = 100; // 每个DO生成100条训练数据
        SecureRandom random = new SecureRandom();
        localData = new double[dataSize][MODEL_SIZE - 1]; // 特征维度为MODEL_SIZE-1
        localLabels = new double[dataSize];

        for (int i = 0; i < dataSize; i++) {
            for (int j = 0; j < MODEL_SIZE - 1; j++) {
                localData[i][j] = random.nextDouble() * 2 - 1; // 生成[-1,1]之间的随机数
            }
            // 根据特征生成标签，添加一些随机性
            double sum = 0;
            for (double feature : localData[i]) {
                sum += feature;
            }
            localLabels[i] = sum > 0 ? 1 : 0;
            if (random.nextDouble() < 0.1) { // 10%的噪声
                localLabels[i] = 1 - localLabels[i];
            }
        }
    }

    /**
     * 训练逻辑回归模型
     */
    public void trainModel() {
        generateTrainingData();
        // 初始化模型参数
        for (int i = 0; i < MODEL_SIZE; i++) {
            localModelParams[i] = 0.0;
        }

        double learningRate = 0.01;
        int epochs = 50;

        // 训练过程
        for (int epoch = 0; epoch < epochs; epoch++) {
            for (int i = 0; i < localData.length; i++) {
                // 计算预测值
                double prediction = predict(localData[i]);
                double error = prediction - localLabels[i];

                // 更新权重
                for (int j = 0; j < MODEL_SIZE - 1; j++) {
                    localModelParams[j] -= learningRate * error * localData[i][j];
                }
                // 更新偏置
                localModelParams[MODEL_SIZE - 1] -= learningRate * error;
            }
        }

        System.out.println("DO " + id + " 本地模型参数: " + Arrays.toString(localModelParams));
    }

    private double predict(double[] features) {
        double sum = localModelParams[MODEL_SIZE - 1]; // 偏置项
        for (int i = 0; i < features.length; i++) {
            sum += features[i] * localModelParams[i];
        }
        return sigmoid(sum);
    }

    private double sigmoid(double x) {
        return 1.0 / (1.0 + Math.exp(-x));
    }

    /**
     * 加密模型参数
     */
    public void encryptData(BigInteger modelParamHash, BigInteger N, BigInteger g, BigInteger h) {
        BigInteger R_t = ta.getR_t();
        BigInteger N2 = N.multiply(N);
        SecureRandom random = new SecureRandom();

        for (int i = 0; i < MODEL_SIZE; i++) {
            // 将double转换为BigInteger（乘以10^6以保持精度）
            BigInteger paramValue = BigInteger.valueOf((long) (localModelParams[i] * 1000000));
            BigInteger r = new BigInteger(N.bitLength() / 2, random);

            BigInteger part1 = g.modPow(paramValue, N2);
            BigInteger part2 = h.modPow(r, N2);
            encryptedModelParams[i] = part1.multiply(part2).mod(N2)
                    .multiply(myPrivateKey).mod(N2);
        }
    }

    public BigInteger[] getEncryptedModelParams() {
        return encryptedModelParams;
    }

    /**
     * 响应 CSP 的请求，上传 TA 分发给本 DO、来源于 sourceDOId 的私钥分片。
     */
    public BigInteger uploadKeyShare(int sourceDOId) {
        BigInteger share = receivedKeyShares.get(sourceDOId);
        // System.out.println("DO " + id + " 上传 DO " + sourceDOId + " 的分片: " + share);
        return share;
    }

    /**
     * 计算点积结果
     */
    public void calculateProjections() {
        projectionResults = new double[orthogonalVectors.length]; // 修改为正确长度5
        // 计算模型参数与每个正交向量的点积
        for (int i = 0; i < orthogonalVectors.length; i++) {
            double dotProduct = 0;
            for (int j = 0; j < MODEL_SIZE; j++) {
                dotProduct += orthogonalVectors[i][j] * localModelParams[j];
            }
            projectionResults[i] = dotProduct;
        }
        System.out.println("DO " + id + " 的点积结果（模型参数在各正交向量上的投影）: " + Arrays.toString(projectionResults));
    }

    public double[] getProjectionResults() {
        return projectionResults;
    }

    public double[] getLocalModelParams() {
        return Arrays.copyOf(localModelParams, localModelParams.length);
    }
}