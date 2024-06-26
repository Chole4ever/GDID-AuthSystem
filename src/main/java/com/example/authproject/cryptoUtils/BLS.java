package com.example.authproject.cryptoUtils;
import org.apache.milagro.amcl.BLS381.*;
import org.apache.milagro.amcl.HASH512;
import org.apache.milagro.amcl.RAND;

import java.math.BigInteger;
import java.security.Signature;

public class BLS {
    private static final BIG CURVE_ORDER; // 阶
    private static BIG G;
    private static ECP G1;
    private static ECP2 G2;  // G2 群的生成元
    private final RAND rng;

    static {
        G = new BIG(ROM.CURVE_Gx);
        G1 = ECP.generator();
        G2 = ECP2.generator();
        CURVE_ORDER = new BIG(ROM.CURVE_Order);
    }

    public BLS(String randomSeed) {
        rng = new RAND();
        rng.clean();
        byte[] seed = randomSeed.getBytes();  // 可替换为更安全的随机种子
        rng.seed(seed.length, seed);
    }



    /*
           exp2实验接口2

           生成签名（并行）+聚合签名时间
     */
    public static Long[][] exp2Api1(int[] testN, int[] testT, SecretSharing[][] ss) throws Exception {
        Long[][] expData = new Long[testN.length][testT.length];

        for (int i=0;i<testN.length;i++)
        {
            for(int j=0;j<testT.length;j++)
            {
                int n = testN[i];
                int t = testT[j];
                if(n<t) {
                    continue;
                }

                //执行100次取avg time
                Long data = 0L;
                for(int x = 0;x<100;x++)
                {
                    SecretSharing cur = ss[i][j];
                    BLSKeyPair[] blsKeyPairs = cur.getBlsKeyPairs();
                    BLS bls = new BLS("haha so nice a day.");
                    String content = "for test,not for any other intention.Tell the world 2 fuck off";
                    ECP[] signatures = bls.generateSignatures(blsKeyPairs,content.getBytes());
                    int[] xValues = new int[n];
                    for(int m=0;m<xValues.length;m++)
                    {
                        xValues[m] = m+1;
                    }
                    //开始时间
                    long stime = System.nanoTime();

                    //聚合签名
                    bls.generateAggregatedSignature(signatures,xValues,t);

                    // 结束时间
                    long etime = System.nanoTime();
                    data+=etime-stime;

                    // 计算执行时间
                    if(x>=10) {
                        data+=etime-stime;
                    }
                }
                data/=90;
                expData[i][j] =data;

            }
        }
        return expData;
    }

    /*
          不使用GDID
          【验证签名时间*n（串行）*2 （验证身份n次+验证凭证n次）】
     */
    public static Double[] exp3Api(int[] testN,byte[] content) throws Exception {

        Double[] expData = new Double[testN.length];
        Long validationTime = 0L;
        //String content = "I am so honored to be here for my lord.";
        BLS bls = new BLS("Eat your crust");
        for(int i=0;i<testN.length;i++)
        {
            Long verifySignatureTime = 0L;
            for(int j=0;j<30;j++)
            {

                BLSKeyPair blsKeyPair = bls.generateKeyPair();
                ECP signature = bls.generateSignature(content,blsKeyPair.getPrivateKey());

                //开始时间
                long stime = System.nanoTime();

                //验证
                boolean isValid = bls.verifySignature(blsKeyPair.getPublicKey(),signature,content);
                // 结束时间
                long etime = System.nanoTime();

                if(!isValid) {
                    throw new Exception("???");
                }
                // 计算执行时间
                verifySignatureTime+=etime-stime;
            }

            verifySignatureTime/=30;

            expData[i] = verifySignatureTime*2*testN[i]/1000000.0;
        }
        return expData;

    }


    /*
        exp3Api2接口，
        身份认证时延计算（gdid)
           【验证凭证&验证身份（均只验证一次）】
           阈值 n/2+1
     */

    public static Double exp3Api1(byte[] content) {
        Double expData = 0.0;

        BLS bls = new BLS("How are you.");
        BLSKeyPair blsKeyPair = bls.generateKeyPair();
        //String content = "Just calm down";
        ECP signature = bls.generateSignature(content,blsKeyPair.getPrivateKey());

        for (int i=0;i<50;i++)
        {
            //开始时间
            long stime = System.nanoTime();

            //验证
            boolean isValid = bls.verifySignature(blsKeyPair.getPublicKey(),signature,content);

            // 结束时间
            long etime = System.nanoTime();
            expData+= etime-stime;
        }

        return expData*2/50000000.0;
    }



    /*
        模拟每个节点本地生成签名片段
     */

    public ECP[] generateSignatures(BLSKeyPair[] blsKeyPairs, byte[] msg) {
        ECP[] signatures = new ECP[blsKeyPairs.length];
        for (int i=0;i<blsKeyPairs.length;i++)
        {
            signatures[i] = generateSignature(msg,blsKeyPairs[i].getPrivateKey());
        }
        return signatures;
    }

    /*
          生成聚合签名
     */

    public ECP generateAggregatedSignature(ECP[] signatures,int[] xValues,int t) throws Exception {
        if(signatures.length<t) {
            throw new Exception("Less than threshold");
        }
        ECP aggregatedSignature = new ECP();


        // 遍历t个签名
        for (int i = 0; i < t; i++) {
            // 计算拉格朗日基函数值
            BIG Li = lagrangeBasis(i+1, xValues, BigInteger.ZERO);

            // 将当前签名乘以其权重
            ECP weightedSignature = new ECP(signatures[i]);
            weightedSignature = weightedSignature.mul(Li);

            // 将加权签名加到聚合签名上
            aggregatedSignature.add(weightedSignature);
        }

        return aggregatedSignature;


    }

    /*
         拉格朗日插值基函数计算
         接受当前索引 i，所有节点 xValues，计算点 x
     */

    public BIG lagrangeBasis(int i, int[] xValues, BigInteger x) {
        BigInteger numerator = BigInteger.ONE;//分子
        BigInteger denominator = BigInteger.ONE;//分母

        for (int j = 1; j <= xValues.length; j++) {
            if (j != i) {
                numerator = numerator.multiply(x.subtract(BigInteger.valueOf(xValues[j-1])));
                denominator = denominator.multiply(BigInteger.valueOf(xValues[i-1]-xValues[j-1]));
            }
        }
        BigInteger bigInteger = numerator.multiply(denominator.modInverse(bigToBigInteger(CURVE_ORDER)).mod(bigToBigInteger(CURVE_ORDER)));
        return bigIntegerToBig(bigInteger) ;
    }



    /*
            生成签名
     */
    public ECP generateSignature(byte[] message,BIG sk)
    {
        ECP hashPoint = hashToCurve(message);
        return hashPoint.mul(sk);  // 使用私钥乘以哈希点来生成签名
    }

    /*
          验证签名是否合法
     */
    public boolean verifySignature(ECP2 pk, ECP signature, byte[] message) {
        ECP hashPoint = hashToCurve(message);
        FP12 pair1 = PAIR.fexp(PAIR.ate(pk, hashPoint));
        FP12 pair2 = PAIR.fexp(PAIR.ate(G2, signature));
        return pair1.equals(pair2);
    }


    /*
         Hash函数
     */
    public ECP hashToCurve(byte[] data) {
        // 这个函数应当由使用者实现，散列并映射到ECP
        HASH512 hash = new HASH512();
        hash.process_array(data);
        byte[] hashBytes = hash.hash();

        // 将散列值转换为BIG整数
        BIG x = BIG.fromBytes(hashBytes);

        // 映射到曲线上（示意性方法）
        return ECP.mapit(hashBytes);
    }
    /*
        初始化密钥对
     */
    public BLSKeyPair generateKeyPair()
    {

        BIG sk = BIG.randomnum(new BIG(ROM.CURVE_Order), rng);
        ECP2 pk = G2.mul(sk);
        return new BLSKeyPair(pk,sk);
    }


    /*
        判断给定公私钥对是否匹配
     */
    public static boolean isKeyPairValid(BIG privateKey, ECP2 publicKey) {
        ECP2 publicKey_ = PAIR.G2mul(G2,privateKey); // 计算公钥 publicKey = privateKey * G
        return publicKey_.equals(publicKey);
    }

    public static BigInteger bigToBigInteger(BIG big)
    {
        // 将 BIG 对象转换为字节数组
        byte[] bigNumberBytes = new byte[BIG.MODBYTES]; // MODBYTES 是 BIG 类型所需的字节数
        big.toBytes(bigNumberBytes);

        // 使用字节数组创建 BigInteger
        return new BigInteger(1, bigNumberBytes); // 使用 1 作为 signum 保证正数
    }

    // 辅助方法：将 BigInteger 转换为 BIG
    public static BIG bigIntegerToBig(BigInteger bigIntegerValue) {
        // 将 BigInteger 转换为字节数组
        byte[] originalBytes = bigIntegerValue.toByteArray();
        byte[] bigBytes = new byte[48]; // 创建一个固定大小的字节数组

        // 复制原始字节数组到新数组，确保大端对齐
        int start = 48 - originalBytes.length;
        for (int i = 0; i < originalBytes.length; i++) {
            bigBytes[start + i] = originalBytes[i];
        }
        return new BIG(BIG.fromBytes(bigBytes));
    }



}

/*
jpbc jar implementation

    private final Pairing pairing;

    @Getter
    private final Element g; // 群 G1 的生成元
    @Getter
    private final Field<Element> Zr;
    @Getter
    private final Field<Element> G1;

    public BLS_jpbc(int rBits, int qBits) {
        TypeACurveGenerator pg = new TypeACurveGenerator(rBits, qBits);
        PairingParameters params = pg.generate();
        this.pairing = PairingFactory.getPairing(params);

        this.G1 = pairing.getG1();
        this.Zr = pairing.getZr();
        this.g = G1.newRandomElement().getImmutable();
    }

    public BLSKeyPair generateKeyPair() {
        Element privateKey = Zr.newRandomElement().getImmutable();
        Element publicKey = g.powZn(privateKey).getImmutable();
        return new BLSKeyPair(publicKey,privateKey);
    }
    public Element sign(Element privateKey, String message) {
        Element mHash = G1.newElement().setFromHash(message.getBytes(), 0, message.length()).getImmutable();
        return mHash.powZn(privateKey).getImmutable();  // 签名为消息的哈希的私钥次幂
    }

    public boolean verify(Element publicKey, Element signature, String message) {
        Element mHash = G1.newElement().setFromHash(message.getBytes(), 0, message.length()).getImmutable();
        Element temp1 = pairing.pairing(signature, g);  // 计算签名和g的配对
        Element temp2 = pairing.pairing(mHash, publicKey);  // 计算消息的哈希和公钥的配对
        return temp1.isEqual(temp2);  // 验证配对是否相等
    }

    public Element aggregateSignatures(List<Element> signatures) {
        Element aggregate = G1.newOneElement().getImmutable(); // 聚合签名初始化为单位元
        for (Element sig : signatures) {
            aggregate = aggregate.mul(sig).getImmutable();
        }
        return aggregate;
    }
*/