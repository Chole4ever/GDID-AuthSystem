package com.example.authproject.service;

import com.example.authproject.data.PresentData;
import com.example.authproject.identity.*;

/**
 * @author wangyike
 */
public class Authentication {



    boolean verifyNode(DID entity, PresentData presentData)
    {

        return false;
    }
    boolean verifyGroup(GDID entity, PresentData presentData)
    {

        return false;
    }


    public static void main(String[] args) {
        /*实验方案
        常量时间
        1.读取DID/GDID文档，提取公钥时间
        2.单个签名的验证时间
        3.身份认证时延：
        群组身份认证延迟计算
        通信时延 + DID身份验证（lder节点） +
        */

        /*身份注册阶段（群组GDID)

        */


        //1.比较 不同的n（成员个数），生成群组公钥的时间


        //身份验证阶段
        //1，比较 相同的 n(成员个数），不同的阈值情况下，其身份认证的时延


        //2.比较 使用gdid与不使用gdid的方案下，相同成员的个数情况下，其身份认证的时延

        //3.不同的阈值签名协议，生成的签名长度对比




    }


}
