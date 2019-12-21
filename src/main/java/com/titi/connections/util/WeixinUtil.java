package com.titi.connections.util;

import com.alibaba.fastjson.JSONObject;
import com.google.common.collect.Maps;
import org.apache.commons.net.util.Base64;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.util.EntityUtils;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

public class WeixinUtil {
    public static final String AES = "AES";
    public static final String AES_CBC_PADDING = "AES/CBC/PKCS7Padding";
    public static JSONObject getJsCode(String appId,String jsCode) throws Exception{
        Map<String, String> query = new HashMap<>(2);
        query.put("appid",appId);
        query.put("secret",getSecret(appId));
        query.put("js_code",jsCode);
        query.put("grant_type","authorization_code");
        HttpResponse response = HttpUtils.doGet("https://api.weixin.qq.com/","sns/jscode2session","GET",new HashMap<>(2),query);
        JSONObject resultJSON=JSONObject.parseObject(EntityUtils.toString(response.getEntity()));
        System.out.println(""+resultJSON.toJSONString());
        return resultJSON;
    }
    private static String getSecret(String appId){
        Map<String,String> map= Maps.newHashMapWithExpectedSize(7);
        map.put("wx37344c1cb0f8ccc2","3e4368e1a0970d60690bc0609517d358");
        map.put("wx9dec518566e910bd","d5f9e1f1aee8c692656b3b8ebc109e71");
        map.put("wx02cee6cad5baff6a","c03b07181adbb327562e3e9fb0d2ab93");
        map.put("wx910ec6a25603379e","902283818255163254e33022640ecc90");
        return  map.get(appId);
    }
    public static BaseResult getUnlimited(String appId,String qrCodeName,String scene){
       try {
           JSONObject jsonObject=getAccessToken(appId);
           Map<String, String> query = new HashMap<>(2);
           query.put("access_token",jsonObject.getString("access_token"));

           JSONObject body=new JSONObject();
           body.put("scene",scene);

           HttpResponse response = HttpUtils.doPost("https://api.weixin.qq.com/","wxa/getwxacodeunlimit",new HashMap<>(2),query,body);
           if (response != null) {
               HttpEntity resEntity = response.getEntity();
               if (resEntity != null) {
                   InputStream inputStream = resEntity.getContent();
                   return new BaseResult(true,200,null,inputStream);


               }
           }
       }catch (Exception e){
           return new BaseResult(false,0,"系统错误"+e.getLocalizedMessage(),"");
       }
        return new BaseResult(false,0,"错误","");
    }

    public static JSONObject getAccessToken(String appId) throws Exception{
        Map<String, String> query = new HashMap<>(2);
        query.put("appid",appId);
        query.put("secret",getSecret(appId));
        query.put("grant_type","client_credential");
        HttpResponse response = HttpUtils.doGet("https://api.weixin.qq.com/","cgi-bin/token","GET",new HashMap<>(2),query);
        JSONObject resultJSON=JSONObject.parseObject(EntityUtils.toString(response.getEntity()));
        return resultJSON;
    }
    /**
     *    * 微信 数据解密<br/>
     *    * 对称解密使用的算法为 AES-128-CBC，数据采用PKCS#7填充<br/>
     *    * 对称解密的目标密文:encrypted=Base64_Decode(encryptData)<br/>
     *    * 对称解密秘钥:key = Base64_Decode(session_key),aeskey是16字节<br/>
     *    * 对称解密算法初始向量:iv = Base64_Decode(iv),同样是16字节<br/>
     *    *
     *    * @param encrypted 目标密文
     *    * @param session_key 会话ID
     *    * @param iv 加密算法的初始向量
     *
     */
    public static String wxDecrypt(String encrypted, String session_key, String iv) {
        String result = null;
        byte[] encrypted64 = Base64.decodeBase64(encrypted);
        byte[] key64 = Base64.decodeBase64(session_key);
        byte[] iv64 = Base64.decodeBase64(iv);
        try {
            init();
            result = new String(decrypt(encrypted64, key64, generateIV(iv64)));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     *    * 初始化密钥
     *
     */

    public static void init() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        KeyGenerator.getInstance(AES).init(128);
    }

    /**
     *    * 生成iv
     *
     */
    public static AlgorithmParameters generateIV(byte[] iv) throws Exception {
        // iv 为一个 16 字节的数组，这里采用和 iOS 端一样的构造方法，数据全为0
        // Arrays.fill(iv, (byte) 0x00);
        AlgorithmParameters params = AlgorithmParameters.getInstance(AES);
        params.init(new IvParameterSpec(iv));
        return params;
    }

    /**
     *    * 生成解密
     *
     */
    public static byte[] decrypt(byte[] encryptedData, byte[] keyBytes, AlgorithmParameters iv)
            throws Exception {
        Key key = new SecretKeySpec(keyBytes, AES);
        Cipher cipher = Cipher.getInstance(AES_CBC_PADDING);
        // 设置为解密模式
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(encryptedData);
    }

    public static JSONObject getUserInfo(String access_token,String openid,String lang) throws Exception{
        Map<String, String> query = new HashMap<>(2);
        query.put("access_token",access_token);
        query.put("openid",openid);
        query.put("lang","zh_CN");
        HttpResponse response = HttpUtils.doGet("https://api.weixin.qq.com/","cgi-bin/user/info","GET",new HashMap<>(2),query);
        JSONObject resultJSON=JSONObject.parseObject(EntityUtils.toString(response.getEntity()));
        return resultJSON;
    }

    public static void main(String [] args) throws Exception{
        //System.out.println(getJsCode("wx37344c1cb0f8ccc2","043LECEu03Mepj1mm9Du0XEhEu0LECEo"));
       System.out.println( JSONObject.toJSONString(getUnlimited("wx37344c1cb0f8ccc2","lijian1","!#$&'()*+,/:;=?@-._~")));
    }
}
