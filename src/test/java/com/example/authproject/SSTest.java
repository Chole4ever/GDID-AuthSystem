package com.example.authproject;

import com.example.authproject.cryptoUtils.BLS;
import com.example.authproject.cryptoUtils.BLSKeyPair;
import com.example.authproject.cryptoUtils.SecretSharing;
import org.apache.milagro.amcl.BLS381.BIG;
import org.apache.milagro.amcl.BLS381.ECP;
import org.apache.milagro.amcl.BLS381.ECP2;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.math.BigInteger;

import static com.example.authproject.cryptoUtils.SecretSharing.*;



public class SSTest {

    @Test
    public void ssTest() throws Exception {
        int n=3;int t=2;
        SecretSharing ss = new SecretSharing(n,t);
        System.out.println(ss);

        System.out.println(BLS.isKeyPairValid(ss.getGlobalPrivateKey(),ss.getGlobalPublicKey()));
        System.out.println(BLS.isKeyPairValid(ss.getBlsKeyPairs()[0].getPrivateKey(),ss.getBlsKeyPairs()[0].getPublicKey()));

        BLS bls = new BLS("random");
        String msg = "test";

        ECP[] signatures = bls.generateSignatures(ss.getBlsKeyPairs(),msg.getBytes());

        int[] xValues = new int[n];
        for (int i=0;i<n;i++) xValues[i]=i+1;
        ECP aggregatedSignature = bls.generateAggregatedSignature(signatures,xValues,t);

        System.out.println(bls.verifySignature(ss.getGlobalPublicKey(),aggregatedSignature,msg.getBytes()));

    }

    @Test
    public void fucTest()
    {
        BIG big = new BIG(100);
        BigInteger bigInteger = BLS.bigToBigInteger(big);
        BIG big_ = BLS.bigIntegerToBig(bigInteger);
        System.out.println(big.equals(big_));
    }


}
