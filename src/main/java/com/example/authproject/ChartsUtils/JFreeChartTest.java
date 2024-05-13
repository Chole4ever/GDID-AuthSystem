package com.example.authproject.ChartsUtils;

import org.jfree.chart.*;
import org.jfree.chart.block.BlockBorder;
import org.jfree.chart.labels.StandardPieSectionLabelGenerator;
import org.jfree.chart.plot.*;
import org.jfree.chart.plot.dial.*;
import org.jfree.chart.title.LegendTitle;
import org.jfree.chart.title.TextTitle;
import org.jfree.chart.ui.GradientPaintTransformType;
import org.jfree.chart.ui.RectangleEdge;
import org.jfree.chart.ui.StandardGradientPaintTransformer;
import org.jfree.data.Range;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.general.DefaultPieDataset;
import org.jfree.data.general.DefaultValueDataset;
import org.jfree.data.general.PieDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;

import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * @author tqf
 * @Description
 * @Version 1.0
 * @since 2022-06-07 09:46
 */
public class JFreeChartTest {
    /**
     * 生成的图片存放地址
     */
    public static String imagePath = "/Users/wangyike/authProject/src/main/java/com/example/authproject";

    public static void main(String[] args) throws Exception {
        // 生成饼图
        testPie();
        // 生成3D饼图
        testPie3D();
        // 生成柱状图
        testBarChart();
        // 层叠柱状图
        stackedBarChart();
        // 生成折线图
        lineChart();
        // 生成散点图
        scatterPlot();
        // 生成雷达图
        radar();
        // 生成环形图
        ringChart();
        // 生成仪表盘
        meter();
        meter2();
        // 生成XY图
        xyImage();
    }


    /**
     * 生成饼图
     */
    public static void testPie() throws Exception {
        //图例名称列表
        List<String> legendNameList = new ArrayList<>(Arrays.asList("一级", "二级", "三级", "四级", "五级"));
        //数据列表
        List<Object> dataList = new ArrayList<>(Arrays.asList(1, 3, 5, 6, 2));
        //图例背景颜色列表
        List<Color> legendColorList = new ArrayList<>(Arrays.asList(Color.YELLOW, Color.GRAY, Color.green, Color.cyan, Color.ORANGE));
        //偏离百分比数据
        List<Double> explodePercentList = new ArrayList<>(Arrays.asList(0.1, 0.1, 0.1, 0.1, 0.1));
        JFreeChart chart = GeneratePieChartUtil.createPieChart("各级占比情况", legendNameList, dataList
                ,JFreeChartUtil.createChartTheme("宋体"), legendColorList, explodePercentList);
        //在D盘目录下生成图片
        File p = new File(imagePath);
        if (!p.exists()) {
            p.mkdirs();
        }
        String imageName = System.currentTimeMillis() + "_饼图" + ".jpeg";
        File file = new File(p.getPath() + "/" + imageName);
        try {
            if(file.exists()) {
                file.delete();
            }
            ChartUtils.saveChartAsJPEG(file, chart, 800, 600);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成3D饼图
     * @throws Exception
     */
    public static void testPie3D() throws Exception {
        //图例名称列表
        List<String> legendNameList = new ArrayList<>(Arrays.asList("一级", "二级", "三级", "四级", "五级"));
        //数据列表
        List<Object> dataList = new ArrayList<>(Arrays.asList(1, 3, 5, 6, 2));
        //图例背景颜色列表
        List<Color> legendColorList = new ArrayList<>(Arrays.asList(Color.YELLOW, Color.GRAY, Color.green, Color.cyan, Color.ORANGE));
        JFreeChart chart = GeneratePieChartUtil.create3DPieChart("各级占比情况", legendNameList, dataList
                , JFreeChartUtil.createChartTheme("宋体"), 1f, legendColorList);
        //在D盘目录下生成图片
        File p = new File(imagePath);
        if (!p.exists()) {
            p.mkdirs();
        }
        String imageName = System.currentTimeMillis() + "_3D饼图" + ".jpeg";
        File file = new File(p.getPath() + "/" + imageName);
        try {
            if(file.exists()) {
                file.delete();
            }
            ChartUtils.saveChartAsJPEG(file, chart, 800, 600);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    /*
    exp2
     */

    public static void testBarChart2(List<String> xAxisNameList,List<String> legendNameList,List<List<Object>> dataList) throws Exception{


        //图例背景颜色
        List<Color> legendColorList = new ArrayList<>(List.of(new Color(65, 105, 225)));
        JFreeChart chart = GenerateChartUtil.createBarChart("Experiment II\nTime Taken During  Group-type Credential Issuance(ms)\n\nDifferent Number of UAV", legendNameList, xAxisNameList
                , dataList, JFreeChartUtil.createChartTheme("宋体"), "Computation Time(ms)", "Threshold",
                0d, 160d, legendColorList, true, "{2}");
        //在D盘目录下生成图片
        File p = new File(imagePath);
        if (!p.exists()) {
            p.mkdirs();
        }
        String imageName = System.currentTimeMillis() + "_柱状图" + ".jpeg";
        File file = new File(p.getPath() + "/" + imageName);
        try {
            if(file.exists()) {
                file.delete();
            }
            ChartUtils.saveChartAsJPEG(file, chart, 800, 600);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
    /*
        exp3
     */
    public static void testBarChart3(List<String> xAxisNameList,List<String> legendNameList,List<List<Object>> dataList) throws Exception{


        //图例背景颜色
        List<Color> legendColorList = new ArrayList<>(List.of(new Color(65, 105, 225)));
        JFreeChart chart = GenerateChartUtil.createBarChart("Experiment III\nTime Taken During Group Identity Verification(s)", legendNameList, xAxisNameList
                , dataList, JFreeChartUtil.createChartTheme("宋体"), "Computation Time(s)", "Number of UAV",
                0d, 9d, legendColorList, true, "{2}");
        //在D盘目录下生成图片
        File p = new File(imagePath);
        if (!p.exists()) {
            p.mkdirs();
        }
        String imageName = System.currentTimeMillis() + "_柱状图" + ".jpeg";
        File file = new File(p.getPath() + "/" + imageName);
        try {
            if(file.exists()) {
                file.delete();
            }
            ChartUtils.saveChartAsJPEG(file, chart, 800, 600);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }


    /**
     * 生成柱状图
     */
    public static void testBarChart() throws Exception {
        //x轴名称列表
        List<String> xAxisNameList = new ArrayList<>(Arrays.asList("一级", "二级", "三级", "四级", "五级"));
        //图例名称列表
        List<String> legendNameList = new ArrayList<>(Arrays.asList("李四", "张三"));
        //数据列表
        List<List<Object>> dataList = new ArrayList<>();
        dataList.add(new ArrayList<>(Arrays.asList(100, 90, 5, 6, 2)));
        dataList.add(new ArrayList<>(Arrays.asList(2, 0, 3, 4, 5)));

        //图例背景颜色
        List<Color> legendColorList = new ArrayList<>(List.of(new Color(65, 105, 225)));
        JFreeChart chart = GenerateChartUtil.createBarChart("各级变化图", legendNameList, xAxisNameList
                , dataList, JFreeChartUtil.createChartTheme("宋体"), "y轴", "x轴",
                0d, 100d, legendColorList, true, "{2}%");
        //在D盘目录下生成图片
        File p = new File(imagePath);
        if (!p.exists()) {
            p.mkdirs();
        }
        String imageName = System.currentTimeMillis() + "_柱状图" + ".jpeg";
        File file = new File(p.getPath() + "/" + imageName);
        try {
            if(file.exists()) {
                file.delete();
            }
            ChartUtils.saveChartAsJPEG(file, chart, 800, 600);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 层叠柱状图
     */
    public static void stackedBarChart() throws Exception {
        //x轴名称列表
        List<String> xAxisNameList = new ArrayList<>(Arrays.asList("一级", "二级", "三级", "四级", "五级"));
        //图例名称列表
        List<String> legendNameList = new ArrayList<>(Arrays.asList("李四", "张三"));
        //数据列表
        List<List<Object>> dataList = new ArrayList<>();
        dataList.add(new ArrayList<>(Arrays.asList(1, 3, 5, 6, 2)));
        dataList.add(new ArrayList<>(Arrays.asList(2, 1, 3, 4, 5)));
        // 返回outputStream
        //GenerateChartUtil.createStackedBarChart(response.getOutputStream(), "各级变化图", legendNameList, xAxisNameList
        // , dataList, JFreeChartUtil.createChartTheme("宋体"), "y轴", "x轴", 600, 400);

        // 返回JFreeChart
        JFreeChart chart = GenerateChartUtil.createStackedBarChart("各级变化图", legendNameList, xAxisNameList
                , dataList, JFreeChartUtil.createChartTheme("宋体"), "y轴", "x轴");
        //在D盘目录下生成图片
        File p = new File(imagePath);
        if (!p.exists()) {
            p.mkdirs();
        }
        String imageName = System.currentTimeMillis() + "_层叠柱状图" + ".jpeg";
        File file = new File(p.getPath() + "/" + imageName);
        try {
            if(file.exists()) {
                file.delete();
            }
            ChartUtils.saveChartAsJPEG(file, chart, 800, 600);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static void lineChart1(List<String> xAxisNameList,List<String> legendNameList,List<List<Object>> dataList) throws Exception{

        JFreeChart chart = GenerateChartUtil.createLineChart("Experiment I\n Time Taken During GDID Generation\n Different Threshold", legendNameList, xAxisNameList
                , dataList, JFreeChartUtil.createChartTheme("宋体"), "computation time(ms)", "Number of UAV");


        //在D盘目录下生成图片
        File p = new File(imagePath);
        if (!p.exists()) {
            p.mkdirs();
        }
        String imageName = System.currentTimeMillis() + "_折线图" + ".jpeg";
        File file = new File(p.getPath() + "/" + imageName);
        try {
            if(file.exists()) {
                file.delete();
            }
            ChartUtils.saveChartAsJPEG(file, chart, 800, 600);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成折线图
     */
    public static void lineChart() throws Exception {
        //x轴名称列表
        List<String> xAxisNameList = new ArrayList<>(Arrays.asList("一级", "二级", "三级", "四级", "五级"));
        //图例名称列表
        List<String> legendNameList = new ArrayList<>(Arrays.asList("李四", "张三","王五"));
        //数据列表
        List<List<Object>> dataList = new ArrayList<>();
        dataList.add(new ArrayList<>(Arrays.asList(1, 3, 5, 6, 2)));
        dataList.add(new ArrayList<>(Arrays.asList(2, 1, 3, 4, 5)));
        dataList.add(new ArrayList<>(Arrays.asList(5, 8, 4, 6, 4)));

        // 返回outputStream
        //GenerateChartUtil.createLineChart(response.getOutputStream(), "各级变化图", legendNameList, xAxisNameList
        // , dataList, JFreeChartUtil.createChartTheme("宋体"), "y轴", "x轴", 600, 400);

        JFreeChart chart = GenerateChartUtil.createLineChart("各级变化图", legendNameList, xAxisNameList
                , dataList, JFreeChartUtil.createChartTheme("宋体"), "y轴", "x轴");
        //在D盘目录下生成图片
        File p = new File(imagePath);
        if (!p.exists()) {
            p.mkdirs();
        }
        String imageName = System.currentTimeMillis() + "_折线图" + ".jpeg";
        File file = new File(p.getPath() + "/" + imageName);
        try {
            if(file.exists()) {
                file.delete();
            }
            ChartUtils.saveChartAsJPEG(file, chart, 800, 600);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成散点图
     */
    public static void scatterPlot() throws Exception {
        //设置散点图数据集
        //设置第一个
        /*XYSeries firefox = new XYSeries("火狐浏览器");
        firefox.add(1.0, 1.0);
        firefox.add(2.0, 4.0);
        firefox.add(3.0, 3.0);
        //设置第二个
        XYSeries chrome = new XYSeries("谷歌浏览器");
        chrome.add(1.0, 4.0);
        chrome.add(2.0, 5.0);
        chrome.add(3.0, 6.0);
        //设置第三个
        XYSeries ie = new XYSeries("IE刘浏览器");
        ie.add(3.0, 4.0);
        ie.add(4.0, 5.0);
        ie.add(5.0, 4.0);
        //添加到数据集
        XYSeriesCollection dataset = new XYSeriesCollection();
        dataset.addSeries(firefox);
        dataset.addSeries(chrome);
        dataset.addSeries(ie);*/

        XYSeriesCollection dataset = new XYSeriesCollection();
        String nameArray[] = {"火狐","谷歌","IE","360浏览器"};
        double value[][] = {{1,2},{2,4},{3,5},{1,4},{2,5},{3,6},{3,4},{4,5},{5,4},{3,6},{4,6},{5,9}};
        int data =0;
        for (int i=0; i<nameArray.length;i++) {
            XYSeries firefox = new XYSeries(nameArray[i]);
            for (int j=0;j<3;j++) {
                firefox.add(value[data][0],value[data][1]);
                data++;
            }
            dataset.addSeries(firefox);
        }

        // 返回outputStream
        // GenerateChartUtil.createScatterPlot(response.getOutputStream(), "各级变化图", dataset
        // , JFreeChartUtil.createChartTheme("宋体"), "y轴", "x轴", 600, 400);

        JFreeChart chart = GenerateChartUtil.createScatterPlot("各级变化图", dataset
                , JFreeChartUtil.createChartTheme("宋体"), "y轴", "x轴");
        //在D盘目录下生成图片
        File p = new File(imagePath);
        if (!p.exists()) {
            p.mkdirs();
        }
        String imageName = System.currentTimeMillis() + "_散点图" + ".jpeg";
        File file = new File(p.getPath() + "/" + imageName);
        try {
            if(file.exists()) {
                file.delete();
            }
            ChartUtils.saveChartAsJPEG(file, chart, 800, 600);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成雷达图
     */
    public static void radar() throws IOException {
       /* DefaultCategoryDataset dataset = new DefaultCategoryDataset();
        String group1 = "华为";
        dataset.addValue(5, group1, "w1");
        dataset.addValue(6, group1, "w2");
        dataset.addValue(4, group1, "w3");
        dataset.addValue(2, group1, "w4");
        dataset.addValue(5, group1, "w5");
        dataset.addValue(5, group1, "w6");
        dataset.addValue(5, group1, "w7");
        dataset.addValue(8, group1, "w8");
        group1 = "苹果 ";
        dataset.addValue(2, group1, "w1");
        dataset.addValue(4, group1, "w2");
        dataset.addValue(4, group1, "w3");
        dataset.addValue(5, group1, "w4");
        dataset.addValue(5, group1, "w5");
        dataset.addValue(8, group1, "w6");
        dataset.addValue(9, group1, "w7");
        dataset.addValue(8, group1, "w8");*/

        DefaultCategoryDataset dataset = new DefaultCategoryDataset();
        String nameArray[]= {"华为","苹果","小米"};
        Random r = new Random();
        for (int i=0;i<nameArray.length;i++) {
            for (int j=1;j<9;j++){
                // 生成[0,10]区间的整数
                int value = r.nextInt(10) * 2;
                dataset.addValue(value, nameArray[i], "w"+j);
            }
        }

        SpiderWebPlot spiderwebplot = new SpiderWebPlot(dataset);

        JFreeChart chart = new JFreeChart("Test", TextTitle.DEFAULT_FONT, spiderwebplot, false);
        LegendTitle legendtitle = new LegendTitle(spiderwebplot);
        legendtitle.setPosition(RectangleEdge.TOP);
        chart.addSubtitle(legendtitle);

        //在D盘目录下生成图片
        File p = new File(imagePath);
        if (!p.exists()) {
            p.mkdirs();
        }
        String imageName = System.currentTimeMillis() + "_雷达图" + ".jpeg";
        File file = new File(p.getPath() + "/" + imageName);
        try {
            if(file.exists()) {
                file.delete();
            }
            ChartUtils.saveChartAsJPEG(file, chart, 800, 600);
        } catch (IOException e) {
            e.printStackTrace();
        }
//        // 下方是生成的图片插入到excel文件中
//        // excel2003工作表
//        HSSFWorkbook wb = new HSSFWorkbook();
//        // 创建工作表
//        HSSFSheet sheet = wb.createSheet("Sheet 1");
//        // 创建字节输出流
//        ByteArrayOutputStream byteArrayOut = new ByteArrayOutputStream();
//
//        // 读取chart信息至字节输出流
//        ChartUtils.writeChartAsPNG(byteArrayOut, chart, 600, 300);
//        // 画图的顶级管理器，一个sheet只能获取一个（一定要注意这点）
//        HSSFPatriarch patriarch = sheet.createDrawingPatriarch();
//        // anchor主要用于设置图片的属性
//        HSSFClientAnchor anchor = new HSSFClientAnchor(0, 0, 0, 0, (short) 2, (short) 1, (short) 12, (short) 15);
//        // anchor.setAnchorType(3);
//        // 插入图片
//        patriarch.createPicture(anchor, wb.addPicture(byteArrayOut.toByteArray(), HSSFWorkbook.PICTURE_TYPE_PNG));
//        // excel2003后缀
//        FileOutputStream fileOut = new FileOutputStream("D://雷达图.xls");
//        wb.write(fileOut);
//        fileOut.close();
    }

    /**
     * 生成环形图
     */
    public static void ringChart() {
        DefaultPieDataset dataSet = new DefaultPieDataset();
        //使用循环向数据集合中添加数据
        int i,j;
        String []a={"Java","VC","C++","数据结构","计算机网络"};
        int []b={1964,820,825,960,1000};
        for(i=0,j=0;i<a.length&&j<b.length;i++,j++){
            dataSet.setValue(a[i],b[j]);
        }

        StandardChartTheme mChartTheme = new StandardChartTheme("CN");
        mChartTheme.setLargeFont(new Font("黑体", Font.BOLD, 14)); // Y柱标签字体（浓度(单位：ppm)）
        mChartTheme.setExtraLargeFont(new Font("宋体", Font.PLAIN, 20)); //标题 （二氧化碳浓度趋势分析图）
        //应用主题样式
        ChartFactory.setChartTheme(mChartTheme);
        //定义图标对象
        JFreeChart chart = ChartFactory.createRingChart ("环形图",// 报表题目，字符串类型
                dataSet, // 获得数据集
                true, // 显示图例
                false, // 不用生成工具
                false // 不用生成URL地址
        );
        //图表
        RingPlot ringplot=(RingPlot) chart.getPlot();
        ringplot.setLabelFont(new Font("宋体", Font.BOLD, 14));
        //用来显示标注的注解，{0}:{1}用来设置显示的格式
        ringplot.setLabelGenerator(new StandardPieSectionLabelGenerator("{0}:{1}"));
        // ringplot.setBackgroundPaint(Color.gray);//设置背景色
        //设置简单标签
        ringplot.setSimpleLabels(true);
        //标题
        TextTitle texttitle=chart.getTitle();
        texttitle.setFont(new Font("宋体", Font.BOLD, 30));
        //图示
        LegendTitle legendtitle =chart.getLegend();
        legendtitle.setItemFont(new Font("宋体", Font.BOLD, 14));
        /*ChartFrame mChartFrame = new ChartFrame("环形图", chart);
        mChartFrame.pack();
        mChartFrame.setVisible(true);*/

        //在D盘目录下生成图片
        File p = new File(imagePath);
        if (!p.exists()) {
            p.mkdirs();
        }
        String imageName = System.currentTimeMillis() + "_环形图" + ".jpeg";
        File file = new File(p.getPath() + "/" + imageName);
        try {
            if(file.exists()) {
                file.delete();
            }
            ChartUtils.saveChartAsJPEG(file, chart, 800, 600);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成仪表盘图
     */
    public static void meter(){
        DefaultValueDataset data = new DefaultValueDataset(32.0);
        MeterPlot plot = new MeterPlot(data);
        plot.setDialShape(DialShape.CHORD);
        plot.setDialBackgroundPaint(Color.WHITE);
        plot.setRange(new Range(0, 120));
        plot.setDialOutlinePaint(Color.GRAY);
        plot.setNeedlePaint(Color.BLACK);
        plot.setTickLabelsVisible(true);
        plot.setTickLabelPaint(Color.BLACK);
        plot.setTickPaint(Color.GRAY);
        plot.setTickLabelFormat(NumberFormat.getNumberInstance());
        plot.setTickSize(10);
        plot.setValuePaint(Color.BLACK);
        plot.addInterval(new MeterInterval("Low", new Range(0, 70), null, null,new Color(128, 255, 128,90) ));
        plot.addInterval(new MeterInterval("Normal", new Range(70, 100), null, null, new Color(255, 255, 128,90)));
        plot.addInterval(new MeterInterval("High", new Range(100, 120), null, null, new Color(255, 128, 128,90)));

        //创建chart，最后一个参数决定是否显示图例
        final JFreeChart chart = new JFreeChart("Meter Chart", JFreeChart.DEFAULT_TITLE_FONT, plot, true);
        //在D盘目录下生成图片
        File p = new File(imagePath);
        if (!p.exists()) {
            p.mkdirs();
        }
        String imageName = System.currentTimeMillis() + "_仪表盘" + ".jpeg";
        File file = new File(p.getPath() + "/" + imageName);
        try {
            if(file.exists()) {
                file.delete();
            }
            ChartUtils.saveChartAsJPEG(file, chart, 800, 600);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * 生成仪表盘
     */
    public static void meter2(){
        //1,数据集合对象 此处为DefaultValueDataset
        DefaultValueDataset dataset = new DefaultValueDataset();
        //  当前指针指向的位置，即：我们需要显示的数据
        dataset.setValue(12D);
        /**
         *  获取图表区域对象
         *
         * A. setDataSet(int index, DataSet dataSet);
         * 为表盘设定使用的数据集，通常一个表盘上可能存在多个指针，
         * 因此需要制定该数据集与哪个指针相互关联。
         * 可以将指针想象成数据集的一种体现方式。
         */
        DialPlot dialplot = new DialPlot();
        dialplot.setView(0.0D, 0.0D, 1.0D, 1.0D);
        dialplot.setDataset(0,dataset);
        /**
         * 开始设置显示框架结构
         * B. setDailFrame(DailFrame dailFrame);设置表盘的底层面板图像，通常表盘是整个仪表的最底层。
         */
        DialFrame dialframe =new StandardDialFrame();
        dialplot.setDialFrame(dialframe);
        /**
         * 结束设置显示框架结构DialCap
         * C. setBackground(Color color);设置表盘的颜色，可以采用Java内置的颜色控制方式来调用该方法。
         */
        GradientPaint gradientpaint = new GradientPaint(new Point(), new Color(255, 255, 255), new Point(), new Color(170, 170, 220));
        DialBackground dialbackground = new DialBackground(gradientpaint);
        dialbackground.setGradientPaintTransformer(new StandardGradientPaintTransformer(GradientPaintTransformType.VERTICAL));
        dialplot.setBackground(dialbackground);
        //  设置显示在表盘中央位置的信息
        DialTextAnnotation dialtextannotation = new DialTextAnnotation("温度");
        dialtextannotation.setFont(new Font("Dialog", 1, 14));
        dialtextannotation.setRadius(0.69999999999999996D);
        dialplot.addLayer(dialtextannotation);
        DialValueIndicator dialvalueindicator = new DialValueIndicator(0);
        dialplot.addLayer(dialvalueindicator);
        //  根据表盘的直径大小（0.75），设置总刻度范围
        /**
         * E. addScale(int index, DailScale dailScale);
         * 用于设定表盘上的量程，index指明该量程属于哪一个指针所指向的数据集，
         * DailScale指明该量程的样式，如量程的基本单位等信息。
         *
         * StandardDialScale(double lowerBound, double upperBound, double startAngle,
         * double extent, double majorTickIncrement, int minorTickCount)
         * new StandardDialScale(-40D, 60D, -120D, -300D,30D);
         */
        //
        StandardDialScale standarddialscale =new StandardDialScale();
        standarddialscale.setLowerBound(-40D);
        standarddialscale.setUpperBound(60D);
        standarddialscale.setStartAngle(-120D);
        standarddialscale.setExtent(-300D);
        standarddialscale.setTickRadius(0.88D);
        standarddialscale.setTickLabelOffset(0.14999999999999999D);
        standarddialscale.setTickLabelFont(new Font("Dialog", 0, 14));
        dialplot.addScale(0, standarddialscale);
        /**
         * F. addLayer(DailRange dailRange);
         * 用于设定某一特定量程的特殊表现，通常位于量程之下，如红色范围标注，绿色范围标注等。
         * 在调用该方法之前需要设定DailRange的一些信息，包括位置信息，颜色信息等等。
         */
        //设置刻度范围（红色）
        StandardDialRange standarddialrange = new StandardDialRange(40D, 60D, Color.red);
        standarddialrange.setInnerRadius(0.52000000000000002D);
        standarddialrange.setOuterRadius(0.55000000000000004D);
        dialplot.addLayer(standarddialrange);
        //设置刻度范围（橘黄色）
        StandardDialRange standarddialrange1 = new StandardDialRange(10D, 40D, Color.orange);
        standarddialrange1.setInnerRadius(0.52000000000000002D);
        standarddialrange1.setOuterRadius(0.55000000000000004D);
        dialplot.addLayer(standarddialrange1);
        //设置刻度范围（绿色）
        StandardDialRange standarddialrange2 = new StandardDialRange(-40D, 10D, Color.green);
        standarddialrange2.setInnerRadius(0.52000000000000002D);
        standarddialrange2.setOuterRadius(0.55000000000000004D);
        dialplot.addLayer(standarddialrange2);

        /**
         * 设置指针
         * G. addPointer(DailPointer dailPointer);
         * 用于设定表盘使用的指针样式，JFreeChart中有很多可供选择指针样式，
         * 用户可以根据使用需要，采用不同的DailPoint的实现类来调用该方法
         */
        DialPointer.Pointer pointer = new DialPointer.Pointer(); //内部内
        dialplot.addPointer(pointer); //addLayer(pointer);
        /**
         * 实例化DialCap
         * H. setCap(DailCap dailCap);设定指针上面的盖帽的样式。
         */
        DialCap dialcap = new DialCap();
        dialcap.setRadius(0.10000000000000001D);
        dialplot.setCap(dialcap);
        //生成chart对象
        JFreeChart jfreechart = new JFreeChart(dialplot);
        //设置标题
        jfreechart.setTitle("设备取水温度采样");
        //在D盘目录下生成图片
        File p = new File(imagePath);
        if (!p.exists()) {
            p.mkdirs();
        }
        String imageName = System.currentTimeMillis() + "_仪表盘2" + ".jpeg";
        File file = new File(p.getPath() + "/" + imageName);
        try {
            if(file.exists()) {
                file.delete();
            }
            ChartUtils.saveChartAsJPEG(file, jfreechart, 500, 500);
        } catch (IOException e) {
            e.printStackTrace();
        }
       /* ChartFrame frame = new ChartFrame("CityInfoPort公司组织架构图 ", jfreechart,true);
        frame.pack();
        //屏幕居中
        RefineryUtilities.centerFrameOnScreen(frame);
        frame.setVisible(true);*/

    }

    /**
     * 生成XY图
     */
    public static void xyImage() throws Exception {
        /*final XYSeries firefox = new XYSeries( "火狐" );
        firefox.add( 1.0 , 1.0 );
        firefox.add( 2.0 , 4.0 );
        firefox.add( 3.0 , 3.0 );
        final XYSeries chrome = new XYSeries( "谷歌" );
        chrome.add( 1.0 , 4.0 );
        chrome.add( 2.0 , 5.0 );
        chrome.add( 3.0 , 6.0 );
        final XYSeries iexplorer = new XYSeries( "IE" );
        iexplorer.add( 3.0 , 4.0 );
        iexplorer.add( 4.0 , 5.0 );
        iexplorer.add( 5.0 , 4.0 );

        final XYSeriesCollection dataset = new XYSeriesCollection( );
        dataset.addSeries( firefox );
        dataset.addSeries( chrome );
        dataset.addSeries( iexplorer );*/

        XYSeriesCollection dataset = new XYSeriesCollection();
        String nameArray[] = {"火狐","谷歌","IE","360浏览器"};
        double value[][] = {{1,2},{2,4},{3,5},{1,4},{2,5},{3,6},{3,4},{4,5},{5,4},{3,6},{4,6},{5,9}};
        int data =0;
        for (int i=0; i<nameArray.length;i++) {
            XYSeries firefox = new XYSeries(nameArray[i]);
            for (int j=0;j<3;j++) {
                firefox.add(value[data][0],value[data][1]);
                data++;
            }
            dataset.addSeries(firefox);
        }

        JFreeChart chart = ChartFactory.createXYLineChart(
                "浏览器使用情况统计",
                "类别",
                "分数",
                dataset,
                PlotOrientation.VERTICAL,
                true,
                true,
                false);
        chart.getTitle().setFont(JFreeChartUtil.getDefaultFont(0,15f));

        //设置提示条字体
        Font font = new Font("宋体", Font.BOLD, 15);
        chart.getLegend().setItemFont(font);
        // 标注位于上侧
        // chart.getLegend().setPosition(RectangleEdge.TOP);
        // 设置标注无边框
        chart.getLegend().setFrame(new BlockBorder(Color.WHITE));

        // 得到图块,准备设置标签的字体
        XYPlot plot = (XYPlot) chart.getPlot();
        //设置plot的背景色透明度
        plot.setBackgroundAlpha(0.0f);
        // 设置网格横线颜色
        plot.setRangeGridlinePaint(Color.gray);
        // 设置网格横线大小
        plot.setDomainGridlineStroke(new BasicStroke(0.2F));
        plot.setRangeGridlineStroke(new BasicStroke(0.2F));

        int width = 640;
        int height = 480;

        //在D盘目录下生成图片
        File p = new File(imagePath);
        if (!p.exists()) {
            p.mkdirs();
        }
        String imageName = System.currentTimeMillis() + "_XY图" + ".jpeg";
        File file = new File(p.getPath() + "/" + imageName);
        try {
            if(file.exists()) {
                file.delete();
            }
            ChartUtils.saveChartAsJPEG(file, chart, width, height);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
