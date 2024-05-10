package com.example.authproject;

import com.example.authproject.cryptoUtils.BLS;
import com.example.authproject.cryptoUtils.BLSKeyPair;
import org.apache.milagro.amcl.BLS381.BIG;
import org.apache.milagro.amcl.BLS381.ECP;
import org.apache.milagro.amcl.BLS381.ECP2;
import org.apache.milagro.amcl.BLS381.ROM;
import org.apache.milagro.amcl.RAND;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class BLSTest {

    @Test
    public void verifySignature()
    {

        BLS bls = new BLS("random");
        BLSKeyPair blsKeyPair = bls.generateKeyPair();
        ECP2 pk = blsKeyPair.getPublicKey();
        BIG sk = blsKeyPair.getPrivateKey();
        // 签名消息
        String message = "Hello, BLS signature!";
        ECP signature = bls.generateSignature(message.getBytes(),sk);

        // 验证签名
        boolean isValid = bls.verifySignature(pk, signature, message.getBytes());
        System.out.println("Is the signature valid? " + isValid);
    }


}
