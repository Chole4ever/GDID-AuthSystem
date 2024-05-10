package com.example.authproject.cryptoUtils;

import org.apache.milagro.amcl.BLS381.*;
import org.apache.milagro.amcl.RAND;
import scala.util.Random;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/*
    生成多项式向量：生成一个随机多项式，常数项为总私钥。
    生成私钥片段：每个参与者会获得该多项式评估的结果作为他们的私钥片段。
 */
public class SecretSharing {
    private static final BIG CURVE_ORDER; // 阶
    private static ECP G1;
    private static ECP2 G2;  // G2 群的生成元

    private BIG[][] allPolynomials;// 用户的多项式

    private BLSKeyPair[] blsKeyPairs;
    private int THRESHOLD; // 阈值
    private int n;//成员个数

    private BIG globalPrivateKey;
    private ECP2 globalPublicKey;

    static{
        G1 = ECP.generator();
        G2 = ECP2.generator();
        CURVE_ORDER = new BIG(ROM.CURVE_Order);
    }

    public SecretSharing(int n,int t) throws Exception {
        this.THRESHOLD = t;
        this.n = n;
        this.blsKeyPairs = new BLSKeyPair[n];

        // 为每个用户生成多项式
        this.allPolynomials = new BIG[n][t];
        for (int i=0;i<n;i++) {
            this.allPolynomials[i] = generatePolynomial();
        }

        // 计算全局私钥
        this.globalPrivateKey = computeGlobalPrivateKey(allPolynomials);

        // 计算全局公钥
        this.globalPublicKey = computeGlobalPublicKey(allPolynomials);

        // 计算每个用户的公私钥
        for(int i=0;i<n;i++)
        {
            BIG sk = generateLocalPrivateKey(i+1,allPolynomials);
            ECP2 pk =  G2.mul(sk);
            this.blsKeyPairs[i] = new BLSKeyPair(pk,sk);
        }
        if(!BLS.isKeyPairValid(globalPrivateKey,globalPublicKey)) {
            throw new Exception("SS init wrong");
        }
    }


    /*
        每个用户生成多项式
     */

    public BIG[] generatePolynomial() {
        BIG[] coeffs = new BIG[THRESHOLD + 1];
        RAND rand = new RAND();
        for (int i = 0; i <= THRESHOLD; i++) {
            // 生成范围在[0, CURVE_ORDER-1]的随机系数
            coeffs[i] = BIG.randomnum(new BIG(ROM.CURVE_Order), rand);
        }
        return coeffs;
    }

    /*
        生成本地私钥
        为每个用户生成片段并组合得到本地私钥
     */

    public BIG generateLocalPrivateKey(int userId, BIG[][] allPolynomials) {
        BIG privateKey = new BIG(0);

        for (int i = 0; i < allPolynomials.length; i++) {
            BIG share = evaluatePolynomial(allPolynomials[i], userId);
            privateKey.add(share);
            privateKey.mod(CURVE_ORDER);
        }
        return privateKey;
    }
    /*
        获取s_i_j
        评估多项式
     */
    public BIG evaluatePolynomial(BIG[] coeffs, int x) {
        BIG result = new BIG(0);
        BIG xVal = new BIG(x);

        BIG term = new BIG(1); // 开始时，x^0 等于 1

        for (int i = 0; i < coeffs.length; i++) {
            if (i > 0) {
                term = BIG.modmul(term, xVal, CURVE_ORDER); // 每次迭代计算 x^i
            }
            BIG contrib = BIG.modmul(coeffs[i], term, CURVE_ORDER); // 计算 a_i * x^i % p

            result.add(contrib);
            result.mod(CURVE_ORDER);

        }
        return result;
    }


    /*
         计算全局公钥
     */

    public ECP2 computeGlobalPublicKey(BIG[][] allPolynomials) {
        ECP2 globalPublicKey = new ECP2(PAIR.G2mul(G2, allPolynomials[0][0]));
        for (int i = 1; i < allPolynomials.length; i++) {
            globalPublicKey.add(new ECP2(PAIR.G2mul(G2, allPolynomials[i][0])));
        }
        return globalPublicKey;
    }

    /*
          计算全局私钥
     */
    public BIG computeGlobalPrivateKey(BIG[][] allPolynomials) {
        BIG globalPrivateKey = new BIG(0);
        // 对每个用户的多项式，取其常数项并累加
        for (int i = 0; i < allPolynomials.length; i++) {
            globalPrivateKey.add(allPolynomials[i][0]);
            globalPrivateKey.mod(CURVE_ORDER); // 确保累加操作在曲线阶内
        }
        return globalPrivateKey;
    }

    @Override
    public String toString() {
        return "ss:\n+" +
                "Global PublicKey: "+this.globalPublicKey
                +"\nGlobal PrivateKey: "+this.globalPrivateKey
                +"\nLocal keyPairs: "+ Arrays.toString(this.blsKeyPairs);

    }
}
