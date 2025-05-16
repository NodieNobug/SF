package com.example;

import javax.swing.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.xy.XYLineAndShapeRenderer;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;

import java.awt.Color;
import java.awt.BasicStroke;
import java.awt.Font;
import org.jfree.chart.StandardChartTheme;

public class All_Test {
    // 记录时间
    private static long startTime;
    private static long endTime;

    // 添加常量定义
    private static final int MODEL_PARAM_LENGTH = 5; // 模型参数维度
    private static final int numDO = 7; // 可以设置更大的DO数量
    private static final int numRounds = 9;// 联邦学习轮次
    private static final Color[] COLORS = {
            Color.RED, Color.BLUE, Color.GREEN, Color.ORANGE,
            Color.MAGENTA
    };

    // 记录时间
    public static void main(String[] args) {
        startTime = System.currentTimeMillis();
        List<DO> doList = new ArrayList<>();
        CSP csp = null;

        // 初始化全局模型参数（初始为零向量）
        int modelParamLength = MODEL_PARAM_LENGTH;
        double[] globalModelParams = new double[modelParamLength];
        Arrays.fill(globalModelParams, 0.0);

        // 用于记录每一轮的模型参数值
        List<double[]> globalModelHistory = new ArrayList<>();

        // 用于存储每个DO在每轮的损失值
        Map<Integer, List<Double>> doLossHistory = new HashMap<>();
        for (int i = 0; i < numDO; i++) {
            doLossHistory.put(i, new ArrayList<>());
        }

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
                if (round == 3 && Arrays.asList(1, 2).contains(doObj.getId())) {
                    // 第三轮次：跳过掉线的 DO
                    System.out.println("DO " + doObj.getId() + " 掉线，跳过训练和上传");
                    continue;
                }
                doObj.updateGlobalModelParams(globalModelParams); // 接收全局模型参数
                System.out.println("DO " + doObj.getId() + " 更新后的全局模型参数: " + Arrays.toString(globalModelParams));

                doObj.trainModel(); // 本地训练
                // 记录损失值
                doLossHistory.get(doObj.getId()).add(doObj.getLastAverageLoss());

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
                csp.receiveData(doObj.getId(), doObj.getEncryptedModelParams()); // 上传加密模型参数

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

                doObj.calculateProjections(); // 计算投影结果
                csp.receiveProjections(doObj.getId(), doObj.getProjectionResults()); // 上传投影结果
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
                // 第三轮次：模拟两个DO掉线
                List<Integer> droppedDOs = Arrays.asList(1, 2); // 假设DO 1和DO 2掉线
                System.out.println("第三轮次：模拟 DO " + droppedDOs + " 掉线");
                List<DO> availableDOs = new ArrayList<>();
                for (DO doObj : doList) {
                    if (!droppedDOs.contains(doObj.getId())) {
                        availableDOs.add(doObj);
                    }
                }

                // 恢复掉线DO的私钥
                Map<Integer, BigInteger> recoveredKeys = csp.recoverMissingPrivateKeys(droppedDOs, availableDOs);
                for (int droppedDO : droppedDOs) {
                    System.out.println("恢复的 DO " + droppedDO + " 私钥: " + recoveredKeys.get(droppedDO));
                }

                // 使用恢复的私钥对全0数据进行加密并上传
                for (int droppedDO : droppedDOs) {
                    BigInteger[] zeroCiphertext = new BigInteger[MODEL_PARAM_LENGTH];
                    for (int i = 0; i < MODEL_PARAM_LENGTH; i++) {
                        zeroCiphertext[i] = csp.encryptZeroData(recoveredKeys.get(droppedDO), ta.getN(), ta.getG(),
                                ta.getH());
                    }
                    csp.receiveData(droppedDO, zeroCiphertext);
                    System.out.println("DO " + droppedDO + " 上传了全0加密数据");
                }

                // 聚合所有DO的数据（包括掉线DO的全0数据）
                aggregatedParams = csp.aggregate(ta.getN());
                decryptedParams = csp.decrypt(aggregatedParams, ta.getLambda(), ta.getN(), ta.getU(),
                        ta.getY());

                // 计算在线DO数量并更新全局模型参数
                globalModelParams = csp.calculateAverage(decryptedParams, numDO - droppedDOs.size()); // 使用在线DO数量计算均值
            } else {
                globalModelParams = csp.calculateAverage(decryptedParams, numDO); // 基于总DO数量求均值
            }

            System.out.println("CSP 分发的全局模型参数: " + Arrays.toString(globalModelParams));
            // 记录当前轮次的模型参数
            globalModelHistory.add(Arrays.copyOf(globalModelParams, globalModelParams.length));

            // 7. 清理CSP状态
            csp.clearState();
        }

        // 仅为了输出结果，方便查看
        for (double[] globalModelHistory2 : globalModelHistory) {
            System.out.println("轮次 " + (globalModelHistory.indexOf(globalModelHistory2) + 1) + ": "
                    + Arrays.toString(globalModelHistory2));
        }

        // 可视化损失曲线
        visualizeLossHistory(doLossHistory, numRounds);
        endTime = System.currentTimeMillis();
        System.out.println("程序运行时间：" + (endTime - startTime) + "ms");
    }

    /**
     * 使用全局模型参数生成模型参数哈希值
     */
    private static BigInteger[] generateModelParamHashes(double[] globalModelParams) {
        BigInteger[] modelParamHashes = new BigInteger[numDO];
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            String modelParams = Arrays.toString(globalModelParams);
            byte[] hashBytes = digest.digest(modelParams.getBytes(StandardCharsets.UTF_8));
            for (int i = 0; i < numDO; i++) {
                modelParamHashes[i] = new BigInteger(1, hashBytes);

            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return modelParamHashes;
    }

    /**
     * 可视化每个DO的损失曲线
     */
    private static void visualizeLossHistory(Map<Integer, List<Double>> doLossHistory, int numRounds) {
        // 设置中文主题
        StandardChartTheme chartTheme = new StandardChartTheme("CN");
        // 设置图表标题字体
        chartTheme.setExtraLargeFont(new Font("黑体", Font.BOLD, 20));
        // 设置轴标签字体
        chartTheme.setLargeFont(new Font("黑体", Font.BOLD, 16));
        // 设置图例字体
        chartTheme.setRegularFont(new Font("宋体", Font.PLAIN, 12));
        // 应用主题
        ChartFactory.setChartTheme(chartTheme);

        XYSeriesCollection dataset = new XYSeriesCollection();

        // 为每个DO创建一个数据系列
        for (Map.Entry<Integer, List<Double>> entry : doLossHistory.entrySet()) {
            XYSeries series = new XYSeries("DO " + entry.getKey());
            List<Double> losses = entry.getValue();
            for (int round = 0; round < losses.size(); round++) {
                series.add(round + 1, losses.get(round));
            }
            dataset.addSeries(series);
        }

        // 创建图表
        JFreeChart chart = ChartFactory.createXYLineChart(
                "联邦学习训练损失曲线",
                "训练轮次",
                "训练损失值",
                dataset,
                PlotOrientation.VERTICAL,
                true,
                true,
                false);

        // 自定义图表外观
        XYPlot plot = chart.getXYPlot();
        XYLineAndShapeRenderer renderer = new XYLineAndShapeRenderer();

        // 为每个DO设置不同的颜色
        for (int i = 0; i < dataset.getSeriesCount(); i++) {
            renderer.setSeriesPaint(i, COLORS[i % COLORS.length]);
            renderer.setSeriesStroke(i, new BasicStroke(2.0f));
        }

        plot.setRenderer(renderer);
        plot.setBackgroundPaint(Color.WHITE);
        plot.setRangeGridlinesVisible(true);
        plot.setRangeGridlinePaint(Color.LIGHT_GRAY);
        plot.setDomainGridlinesVisible(true);
        plot.setDomainGridlinePaint(Color.LIGHT_GRAY);

        // 显示图表
        JFrame frame = new JFrame("损失曲线");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        ChartPanel chartPanel = new ChartPanel(chart);
        chartPanel.setPreferredSize(new java.awt.Dimension(800, 600));
        frame.setContentPane(chartPanel);
        frame.pack();
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
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
