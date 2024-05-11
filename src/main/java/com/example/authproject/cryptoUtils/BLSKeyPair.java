package com.example.authproject.cryptoUtils;


import lombok.Getter;
import org.apache.milagro.amcl.BLS381.BIG;
import org.apache.milagro.amcl.BLS381.ECP2;

/**
 * @author wangyike
 */

public class BLSKeyPair {
    @Getter
    private final ECP2 publicKey;

    @Getter
    private final BIG privateKey;

    public BLSKeyPair(ECP2 publicKey, BIG privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    @Override
    public String toString() {
        return "BLSKeyPair{" +
                "publicKey=" + publicKey +
                ", privateKey=" + privateKey +
                '}'+"\n" ;
    }
}
