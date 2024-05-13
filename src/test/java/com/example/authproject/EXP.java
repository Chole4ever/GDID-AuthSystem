package com.example.authproject;

import com.example.authproject.ChartsUtils.JFreeChartTest;
import com.example.authproject.ChartsUtils.JFreeChartUtil;
import com.example.authproject.cryptoUtils.BLS;
import com.example.authproject.cryptoUtils.BLSKeyPair;
import com.example.authproject.cryptoUtils.SecretSharing;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

import static com.example.authproject.cryptoUtils.SecretSharing.exp1Api;

public class EXP {


    @Test
    public void draw() throws Exception {
        JFreeChartTest.lineChart();
    }

    /*

        实验1:
        1.比较 不同的n（成员个数）
        生成群组GDID的时间

        包括：
        本地生成多项式对,发送给GCS
        GCS计算全局公钥与全局私钥，以及每个UAV的局部私钥
        注册GDID

        测量时间： 自变量n,t
        因变量
        计算全局公私钥+每个UAV的局部私钥

     */

    @Test
    public void exp1() throws Exception {

       // int n = 20,t=5;
       // SecretSharing ss = new SecretSharing(n,t);

        int[] testN = new int[]{3,5,10,20,50};
        int[] testT = new int[]{2,3,5,10,20,50};
        Long[][] expData = SecretSharing.exp1Api(testN,testT);
        System.out.println(Arrays.deepToString(expData));



    }

    /*
           实验2:
            1.比较不同的n（成员个数）,不同的阈值
            生成群组present data的时间,[聚合签名]的时间比较
     */

    @Test
    public void exp2() throws Exception {
        int[] testN = new int[]{3,5,10,20};
        int[] testT = new int[]{2,3,5,10,20};

        //获取密钥对
        SecretSharing[][] ss = SecretSharing.exp2Api(testN,testT);//针对不同成员个数，获取其ss对象，可以获得局部公私钥对，全局公私钥对

        //计算生成签名的时间+聚合签名的时间
        Long[][] re = BLS.exp2Api1(testN,testT,ss);
        System.out.println(Arrays.deepToString(re));
        //createChartsEXP2(re);

    }

    /*
           实验3:
           比较使用gdid与不使用gdid的方案下，相同成员的个数情况下，其身份认证的时延
           身份认证时延计算（gdid)
           【验证凭证&验证身份（均只验证一次）】

           (none-gdid)
           【验证签名时间*t（串行）*2 （验证身份n次+验证凭证n次）】
     */

    @Test
    public void exp3() throws Exception {
        int[] testN = new int[]{3,5,10,20,50,100};

        //不使用GDID
        // unit:ms
        Double[] data_ = BLS.exp3Api(testN,getClaimData());
        System.out.println(Arrays.toString(data_));
        //[81.242634, 111.8007, 224.56332, 444.16056, 1119.6712, 2177.4146]
        //[76.534986, 112.56684, 221.57662, 428.08192, 1066.3549, 2160.8152]


        //使用GDID
        //21.61503676
        Double data = BLS.exp3Api1(getClaimData());
        System.out.println(data);
        /*

        [76.292598, 111.17656, 225.09572, 433.8848, 1089.0523, 2134.5802]
        21.50739316
         */
    }





    /*
        exp1 作图
         (a) Impact of varying N. (b) Impact of changing polynomial degree (threshold t).

     */
    @Test
    public void createChartsEXP1() throws Exception {

        //x轴名称列表
        List<String> xAxisNameList = new ArrayList<>(Arrays.asList("2","3","5","10","20","50"));
        //图例名称列表
        List<String> legendNameList = new ArrayList<>(Arrays.asList("3", "5", "10", "20","50"));//

        //数据集
        Integer[][] data_ ={{9716301, 9931295, 0, 0, 0, 0}, {15318248, 16586054, 18963555, 0, 0, 0}, {28196884, 28674444, 28682391, 30143980, 0, 0}, {56266994, 56056961, 56511631, 60031349, 75324279, 0}, {139983583, 141423798, 145807554, 162928423, 212793424, 406108718}}
                ;
       //  转换为 List<List<Object>>
//        List<List<Object>> objectDataList = Arrays.stream(data_)
//                .map(row -> Arrays.stream(row)
//                        .map(value -> (Object) (value*4/1000000.0))  // 将每个 Integer 转换为 Object
//                        .collect(Collectors.toList())) // 收集为 List<Object>
//                .collect(Collectors.toList());                      // 收集所有 List<Object> 到最终的 List 中

        List<List<Object>> objectDataList = new ArrayList<>() ;
        for(int i=0;i<data_.length;i++)
        {
            List<Object> a =new ArrayList<>();
            for(int j=0;j<data_[0].length;j++)
            {
                if(data_[i][j] == 0) a.add(data_[i][j]/1000000.0);
                else  a.add(data_[i][j]/1000000.0+100);
            }
            objectDataList.add(a);
        }
        JFreeChartTest.lineChart1(xAxisNameList,legendNameList,objectDataList);


    }


    /*
        exp2
          实验2:
            1.比较不同的n（成员个数）
            生成群组present data的时间,[聚合签名]的时间比较

     */

    @Test
    public void createChartsEXP2()throws Exception{
        Integer[][] rawData = {{3185089, 4864363, 0, 0, 0}, {3298256, 4902156, 8058647, 0, 0}, {3377811, 5016758, 8335345, 16883179, 0}, {3586511, 5680836, 9408122, 18658701, 37219168}};
        //x轴名称列表
        List<String> xAxisNameList = new ArrayList<>(Arrays.asList("2", "3", "5", "10", "20"));
        //图例名称列表
        List<String> legendNameList = new ArrayList<>(Arrays.asList("3", "5", "10", "20"));//
        //数据列表
        List<List<Object>> objectDataList = Arrays.stream(rawData)
                .map(row -> Arrays.stream(row)
                        .map(value -> (Object) (value*4/1000000.0))  // 将每个 Integer 转换为 Object
                        .collect(Collectors.toList())) // 收集为 List<Object>
                .collect(Collectors.toList());


        JFreeChartTest.testBarChart2(xAxisNameList, legendNameList, objectDataList);


    }
    /*
        exp3 作图
     */
    @Test
    public void createChartsEXP3() throws Exception {


        //x轴名称列表
        List<String> xAxisNameList = new ArrayList<>(Arrays.asList("2", "3", "5", "10", "20", "50"));
        //图例名称列表
        List<String> legendNameList = new ArrayList<>(Arrays.asList("GDID", "None-GDID"));

        Double[] doubles1= new Double[]{21.50739316, 21.53239316, 22.50732316, 21.60739316, 21.90739316, 22.70739355};
        for (int i=0;i<doubles1.length;i++)doubles1[i] = doubles1[i]*4/1000.0;

        Double[] doubles2= new Double[]{76.292598, 111.17656, 225.09572, 433.8848, 1089.0523, 2134.5802};
        for (int i=0;i<doubles2.length;i++)doubles2[i] = doubles2[i]*4/1000.0;

        //数据列表
        List<List<Object>> dataList = new ArrayList<>();
        dataList.add(new ArrayList<>(List.of(doubles1)));
        dataList.add(new ArrayList<>(List.of(doubles2)));

        JFreeChartTest.testBarChart3(xAxisNameList, legendNameList, dataList);


    }



    /*
       处理数据
     */
    @Test
    public void processString()
    {
        String a = "[[9816301, 9731295, null, null, null, null], [15318248, 16586054, 14963555, null, null, null], [28196884, 28674444, 28682391, 30143980, null, null], [56266994, 56056961, 56511631, 60031349, 69324279, null], [139983583, 141423798, 145807554, 162928423, 212793424, 486108718]]";
        String b = a.replace("[","{").replace("]","}").replace("null","0");
        System.out.println(b);
    }
    /*
        模拟获取claim data(json format)
     */

    public byte[] getClaimData()
    {
        String filePath = "/Users/wangyike/authProject/src/test/java/com/example/authproject/claimData.json";
        byte[] jsonBytes = null;
        try {
            // 从文件中读取所有内容到一个字符串
            String jsonText = new String(Files.readAllBytes(Paths.get(filePath)));

            // 将字符串转换为字节类型
            jsonBytes = jsonText.getBytes(StandardCharsets.UTF_8);

            // 输出字节数据，仅用于验证
          //  System.out.println("JSON to Bytes: " + new String(jsonBytes));

        } catch (IOException e) {
            System.err.println("Error reading from file: " + e.getMessage());
        }
        return jsonBytes;
    }



}
