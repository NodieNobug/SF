package com.example;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;

class DO {
    private int id;
    private TA ta; // 用于获取全局参数及私钥
    private BigInteger myPrivateKey; // 存储自己的私钥
    private Map<Integer, BigInteger> receivedKeyShares = new HashMap<>(); // 存储其他DO的私钥分片
    private double[][] orthogonalVectors; // 正交向量组
    private double[][] orthogonalVectorsForDo; // 存储分给CSP的向量组部分
    private static int MODEL_SIZE = 5; // 模型参数大小：4个权重 + 1个偏置
    private double[] localModelParams; // 存储本地模型参数
    private BigInteger[] encryptedModelParams; // 存储加密后的模型参数数组
    private double[] projectionResults;
    private BigInteger dot_r; // 新增：安全点积随机数r

    // 新增用于数据处理的成员变量
    private List<double[]> processedData = new ArrayList<>();
    private List<Integer> labels = new ArrayList<>();
    private Map<String, Integer> categoricalMaps = new HashMap<>();
    private static final String DATA_PATH = "d:\\Java_project\\SafeFl\\demo\\src\\main\\data\\adult.csv";

    private double lastAverageLoss; // 储最近一轮的平均损失值,用于可视化

    public DO(int id, TA ta) {
        this.id = id;
        this.ta = ta;
        this.myPrivateKey = ta.doPrivateKeys.get(id); // 获取自己的私钥
        this.orthogonalVectors = ta.getOrthogonalVectors(); // 获取正交向量组
        this.orthogonalVectorsForDo = ta.getOrthogonalVectorsForDO(); // 获取分给DO的向量组部分

        // 存储分给本DO的所有其他DO的私钥分片
        for (Map.Entry<Integer, Map<Integer, BigInteger>> entry : ta.doKeyShares.entrySet()) {
            int sourceDOId = entry.getKey();
            Map<Integer, BigInteger> shares = entry.getValue();
            if (shares.containsKey(this.id)) {
                receivedKeyShares.put(sourceDOId, shares.get(this.id));
            }
        }
        this.localModelParams = new double[MODEL_SIZE];
        this.encryptedModelParams = new BigInteger[MODEL_SIZE];
        this.projectionResults = new double[orthogonalVectors.length];

        loadAndProcessData(); // 在构造函数中加载数据
    }

    /**
     * 加载并处理UCI Adult数据集
     * 随机选择20000条数据
     */
    private void loadAndProcessData() {
        List<String> allLines = new ArrayList<>();

        // 首先读取所有数据
        try (BufferedReader br = new BufferedReader(new FileReader(DATA_PATH))) {
            String line;
            while ((line = br.readLine()) != null) {
                allLines.add(line);
            }
        } catch (IOException e) {
            System.err.println("读取数据文件失败: " + e.getMessage());
            e.printStackTrace();
            return;
        }

        // 随机选择20000条数据
        int totalSize = allLines.size();
        int targetSize = Math.min(20000, totalSize);
        Set<Integer> selectedIndices = new HashSet<>();
        Random random = new Random();

        while (selectedIndices.size() < targetSize) {
            selectedIndices.add(random.nextInt(totalSize));
        }

        // 处理选中的数据
        int processedCount = 0;
        for (int index : selectedIndices) {
            try {
                String line = allLines.get(index);
                String[] values = line.split(", ");
                if (values.length < 15) {
                    continue;
                }
                double[] features = processRow(values);
                processedData.add(features);
                labels.add(values[14].contains(">50K") ? 1 : 0);
                processedCount++;
            } catch (Exception e) {
                System.err.println("处理数据行时出错，跳过此行");
                continue;
            }
        }

        // System.out.println("DO " + id + " 已随机加载 " + processedCount + " 条训练数据");

        // 验证正负样本比例
        int positiveCount = 0;
        for (int label : labels) {
            if (label == 1)
                positiveCount++;
        }
        // System.out.println("DO " + id + " 正样本比例: " +
        // String.format("%.2f%%", (positiveCount * 100.0 / processedCount)));
    }

    /**
     * 处理单行数据 - 由于方案中将模型参数长度统一设置为5{4个特征值+1个偏置值}
     */
    private double[] processRow(String[] values) {
        double[] result = new double[4]; // 固定使用4个特征

        try {
            // 1. 年龄特征
            result[0] = normalizeAge(parseDoubleOrDefault(values[0], 0.0));

            // 2. 教育程度特征
            result[1] = parseDoubleOrDefault(values[4], 0.0) / 16.0; // 归一化教育年限

            // 3. 工作时长特征
            result[2] = parseDoubleOrDefault(values[12], 0.0) / 100.0; // 归一化每周工作时长

            // 4. 资本收益特征
            double capitalGain = parseDoubleOrDefault(values[10], 0.0);
            double capitalLoss = parseDoubleOrDefault(values[11], 0.0);
            result[3] = normalizeCapital(capitalGain - capitalLoss);

        } catch (Exception e) {
            System.err.println("处理数据行出错: " + Arrays.toString(values));
            Arrays.fill(result, 0.0);
        }

        return result;
    }

    /**
     * 归一化年龄特征到[0,1]范围
     */
    private double normalizeAge(double age) {
        return (age - 17) / (90 - 17); // 数据集中年龄范围大约在17-90之间
    }

    /**
     * 归一化资本收益特征
     */
    private double normalizeCapital(double capital) {
        double maxCapital = 100000.0; // 设定一个合理的最大值
        return Math.tanh(capital / maxCapital); // 使用tanh将值压缩到[-1,1]范围
    }

    /**
     * 安全地解析double值，处理异常情况
     */
    private double parseDoubleOrDefault(String value, double defaultValue) {
        if (value == null || value.trim().isEmpty() || value.equals("?")) {
            return defaultValue;
        }
        try {
            return Double.parseDouble(value.trim());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * 训练逻辑回归模型 - 使用固定的5个参数
     * 训练后更新localModelParams。
     */
    public void trainModel() {
        System.out.println("DO " + id + " 开始本地训练...");
        double learningRate = 0.005;
        int epochs = 100;
        int dataSize = processedData.size();
        double totalEpochLoss = 0;

        for (int epoch = 0; epoch < epochs; epoch++) {
            double totalLoss = 0;
            for (int i = 0; i < dataSize; i++) {
                double[] features = processedData.get(i);
                double label = labels.get(i);

                // 计算预测值
                double prediction = predict(features);
                double error = prediction - label;
                totalLoss += error * error;

                // 更新权重 (前4个参数)
                for (int j = 0; j < MODEL_SIZE - 1; j++) {
                    localModelParams[j] -= learningRate * error * features[j];
                }
                // 更新偏置 (第5个参数)
                localModelParams[MODEL_SIZE - 1] -= learningRate * error;
            }

            // if (epoch % 10 == 0) {
            // System.out.println("DO " + id + " Epoch " + epoch +
            // " 平均损失: " + totalLoss / dataSize);
            // }
            totalEpochLoss = totalLoss / dataSize;
        }

        lastAverageLoss = totalEpochLoss; // 保存最后一轮的平均损失
        System.out.println("DO " + id + " 本地训练完成，最终平均损失: " + lastAverageLoss);
        System.out.println("DO " + id + " 本地训练完成，更新后的模型参数: " +
                Arrays.toString(localModelParams));
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

    public double getLastAverageLoss() {
        return lastAverageLoss;
    }

    /**
     * 加密本地训练后的模型参数
     */
    public void encryptData(BigInteger N, BigInteger g, BigInteger h) {
        BigInteger N2 = N.multiply(N);
        SecureRandom random = new SecureRandom();

        for (int i = 0; i < MODEL_SIZE; i++) {
            BigInteger paramValue = BigInteger.valueOf((long) (localModelParams[i] * 1000000));
            BigInteger r = new BigInteger(N.bitLength() / 2, random);

            BigInteger part1 = g.modPow(paramValue, N2);
            BigInteger part2 = h.modPow(r, N2);
            encryptedModelParams[i] = part1.multiply(part2).mod(N2).multiply(ta.doPrivateKeys.get(id)).mod(N2);
        }
    }

    public BigInteger[] getEncryptedModelParams() {
        return encryptedModelParams;
    }

    /**
     * 响应 CSP 的请求，上传 TA 分发给本 DO、来源于 sourceDOId 的私钥分片。
     */
    public BigInteger uploadKeyShare(int sourceDOId) {
        return receivedKeyShares.get(sourceDOId); // 上传其他DO的私钥分片
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

    /**
     * 安全点积
     */

    // 生成getdot_r方法
    public BigInteger getDot_r() {
        int k4 = 32;
        SecureRandom random = new SecureRandom();
        dot_r = new BigInteger(k4, random);
        return dot_r;
    }

    public BigInteger[] calculateFirstRound(BigInteger[][] encryptedVectors, BigInteger p, BigInteger alpha) {
        int k4 = 32;
        SecureRandom random = new SecureRandom();
        double[] b_ext = Arrays.copyOf(localModelParams, MODEL_SIZE + 2); // b扩展两位

        BigInteger[] D_sums = new BigInteger[orthogonalVectorsForDo.length];

        for (int vecIndex = 0; vecIndex < orthogonalVectorsForDo.length; vecIndex++) {
            BigInteger[] D = new BigInteger[MODEL_SIZE + 2];
            for (int i = 0; i < MODEL_SIZE + 2; i++) {
                if (b_ext[i] != 0) {
                    BigInteger value = BigInteger.valueOf((long) (b_ext[i] * 1000000)); // 放大精度
                    D[i] = value.multiply(alpha).multiply(encryptedVectors[vecIndex][i]).mod(p);
                } else {
                    BigInteger r = new BigInteger(k4, random);
                    D[i] = r.multiply(encryptedVectors[vecIndex][i]).mod(p);
                }
            }
            BigInteger D_sum = BigInteger.ZERO;
            for (int i = 0; i < MODEL_SIZE + 2; i++) {
                D_sum = D_sum.add(D[i]);
            }
            D_sums[vecIndex] = D_sum.mod(p);
        }

        // for (int i = 0; i < orthogonalVectorsForDo.length; i++) {
        // System.out.println("DO" + id + "点积第一轮加的随机数:" + dot_r);
        // D_sums[i] = D_sums[i].mod(p);
        // }

        // System.out.println("DO " + id + " 计算第一轮结果: " + Arrays.toString(D_sums));
        return D_sums;
    }

    // 计算第二轮结果
    // 直接用自己训练后的全局模型参数点积自己的这一半正交向量组
    public BigInteger[] calculateSecondRound(BigInteger p) {
        BigInteger[] secondRoundResults = new BigInteger[orthogonalVectorsForDo.length];
        BigInteger halfP = p.divide(BigInteger.valueOf(2));

        for (int i = 0; i < orthogonalVectorsForDo.length; i++) {
            // 存储每一项乘积的和
            BigInteger dotProduct = BigInteger.ZERO;

            // 计算点积
            for (int j = 0; j < MODEL_SIZE; j++) {
                // 转换为BigInteger并放大精度
                BigInteger modelParam = BigInteger.valueOf((long) (localModelParams[j] * 1000000));
                BigInteger vectorValue = BigInteger.valueOf((long) (orthogonalVectorsForDo[i][j] * 1000000));

                // 处理负数 - 将负数转换为模p意义下的等价值
                if (modelParam.signum() < 0) {
                    modelParam = p.add(modelParam);
                }
                if (vectorValue.signum() < 0) {
                    vectorValue = p.add(vectorValue);
                }

                // 计算乘积并累加
                BigInteger product = modelParam.multiply(vectorValue);
                dotProduct = dotProduct.add(product);
            }

            // 将结果调整到[-p/2, p/2]范围内
            if (dotProduct.compareTo(halfP) > 0) {
                dotProduct = dotProduct.subtract(p);
            }

            // 减去随机数
            BigInteger result = dotProduct.mod(p);

            if (result.compareTo(halfP) > 0) {
                result = result.subtract(p);
            }

            secondRoundResults[i] = result;
        }

        return secondRoundResults;
    }

    public double[][] getOrthogonalVectorsForDO() {
        return orthogonalVectorsForDo;
    }

    public double[] getProjectionResults() {
        return projectionResults;
    }

    public int getId() {
        return id;
    }

    public double[] getLocalModelParams() {
        return Arrays.copyOf(localModelParams, localModelParams.length);
    }

    /**
     * 更新全局模型参数
     * 接收CSP分发的全局模型参数，并将其作为初始模型参数。
     */
    public void updateGlobalModelParams(double[] globalModelParams) {
        System.out.println("DO " + id + " 接收到全局模型参数: " + Arrays.toString(globalModelParams));
        this.localModelParams = Arrays.copyOf(globalModelParams, globalModelParams.length); // 初始化模型参数
    }

    /**
     * 更新TA参数
     */
    public void updateTA(TA ta) {
        this.ta = ta;
        this.myPrivateKey = ta.doPrivateKeys.get(id); // 更新自己的私钥
        this.orthogonalVectors = ta.getOrthogonalVectors(); // 更新正交向量组

        // 清空并重新存储分片
        receivedKeyShares.clear();
        for (Map.Entry<Integer, Map<Integer, BigInteger>> entry : ta.doKeyShares.entrySet()) {
            int sourceDOId = entry.getKey();
            Map<Integer, BigInteger> shares = entry.getValue();
            if (shares.containsKey(this.id)) {
                receivedKeyShares.put(sourceDOId, shares.get(this.id));
            }
        }

        System.out.println("DO " + id + " 更新了TA参数和私钥分片");
    }
}