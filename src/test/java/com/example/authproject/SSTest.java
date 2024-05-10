package com.example.authproject;

import com.example.authproject.cryptoUtils.BLS;
import com.example.authproject.cryptoUtils.BLSKeyPair;
import com.example.authproject.cryptoUtils.SecretSharing;
import org.apache.milagro.amcl.BLS381.BIG;
import org.apache.milagro.amcl.BLS381.ECP2;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static com.example.authproject.cryptoUtils.SecretSharing.*;

@SpringBootTest
public class SSTest {

    @Test
    public void ssTest() throws Exception {
        SecretSharing ss = new SecretSharing(3,2);
        System.out.println(ss);

        BLS bls = new BLS("random");

        String msg = "test";


    }


}
