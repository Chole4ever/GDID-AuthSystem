package com.example.authproject.cryptoUtils;
import org.apache.milagro.amcl.BLS381.*;
import org.apache.milagro.amcl.HASH512;
import org.apache.milagro.amcl.RAND;

public class BLS {
    private static BIG G;
    private static ECP G1;
    private static ECP2 G2;  // G2 群的生成元
    private final RAND rng;

    static{
        G = new BIG(ROM.CURVE_Gx);
        G1 = ECP.generator();
        G2 = ECP2.generator();
    }
    public BLS(String randomSeed)
    {
        rng = new RAND();
        rng.clean();
        byte[] seed = randomSeed.getBytes();  // 可替换为更安全的随机种子
        rng.seed(seed.length, seed);
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