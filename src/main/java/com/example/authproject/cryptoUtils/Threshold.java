package com.example.authproject.cryptoUtils;


import org.apache.milagro.amcl.BLS381.*;

import java.util.HashMap;
import java.util.List;

/**
 * @author wangyike
 */
public class Threshold {

    private int n;//成员个数
    private int t;//阈值

    SecretSharing ss;

    private HashMap<String,BLSKeyPair> blsKeyPairs;

    public Threshold(int n, int t, List<String> didIdentitys) throws Exception {
        this.n = n;
        this.t = t;
        this.ss = new SecretSharing(n,t);
    }

//    private HashMap<String,BLSKeyPair> generateKeyPair(int n,int t, List<String> didIdentitys)
//    {
//
//    }

    public static void main(String[] args) {




    }



}
