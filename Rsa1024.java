package com.mecewe.rsautil;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.RSAPrivateKeyStructure;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Decoder;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * @description:
 * @author: Mecewe
 * @createDate: 2019-08-10
 * @version: 1.0
 */
public class Rsa1024 {

    //不加会车也没问题
    private String DEFAULT_PUBLIC_KEY=
                    "MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgHU4CF6yvqb5WBhwcYfvh/o3Npwc" + "\r" +
                    "SJlcfj0nIZeKHLYvJOIgzkV6eITLobl1bXcd7WvvSzAfRXHoszOqYU7Uh93YKrqd" + "\r" +
                    "O9Mrmx3eG0yeY2GtXUW0uNMFlAUscwzE5sJoJT6QwRa0/7/AqlQBZhIsBDSs/w71" + "\r" +
                    "Xqtao8Lg6/wxOsehAgMBAAE=" + "\r";


    //不加会车也没问题
    private String DEFAULT_PRIVATE_KEY=
                    "MIICWwIBAAKBgHU4CF6yvqb5WBhwcYfvh/o3NpwcSJlcfj0nIZeKHLYvJOIgzkV6" + "\r" +
                    "eITLobl1bXcd7WvvSzAfRXHoszOqYU7Uh93YKrqdO9Mrmx3eG0yeY2GtXUW0uNMF" + "\r" +
                    "lAUscwzE5sJoJT6QwRa0/7/AqlQBZhIsBDSs/w71Xqtao8Lg6/wxOsehAgMBAAEC" + "\r" +
                    "gYBlHNR7e4xh1CxdyIDmVYTiHcaJmww03kg20A51/bkOnlQei1XjMOXNByqWI+kt" + "\r" +
                    "Gy+2L1CYTiFFRQlvw8T0jvgy+3rbelvsHzBB1PKuynKeaS7w2QbWNMLo+/mcE3HQ" + "\r" +
                    "i60CjgrHiZ7kS+LGvzOtsIBm7oj6rY/Yk9EBqSHFGcTYkQJBAOLjj6AF1+CG9kdf" + "\r" +
                    "kauxZEw5hjbuGb+yhOFrnBgEIQczxF86Ub2wMzV7faO6rRfOHXjdqcaWExWNuWKz" + "\r" +
                    "VB4CgeMCQQCEQjpFgU4TnPG2oQzRCKQ5nAyxG/eDY8Q5aS5bRliSv6w+6AhPjKM6" + "\r" +
                    "PME8h1g8Ti8w3tJ4CrMrjopYAQ5BlPerAkBi3iKh6qntbyI2a9DAbmZ0SMTRfuO9" + "\r" +
                    "gv8gc5HrbTEvQEGb9X/VFsjZz1wqUphGvUxedMkcfh0G0WEtP1OyWAldAkBPg6WW" + "\r" +
                    "7fNr1Tp46wBSmBhrzkbPIBpBsvRg87x8AaH0sCm1NDjy4oGr3KTsaA6DSxoSDpSI" + "\r" +
                    "uR4Y/Lxtxky03wO7AkEAs/6wWPecgKbSSx++Plw2gZ61Nm4FO1CU7gDth0MVWdyn" + "\r" +
                    "7K/1mHCVrqRR4UP4Q94QSsDmVKsixIYXcLYEB26c9Q==" + "\r";


    //公钥加密后的密文
    private  static final String SECRTE_DATA_ByPublicKey =
                "236C6A51BC11CD9DA0403124D6D05D6D12615D707E8BD1DF00497ABDEC8AF588" +
                    "735569720FE79CEDA9818E9B27CB69CFB1653A4E995CBE144EEBDA4F" +
                    "44BD482868063A9FEFEB2164C317AD8CCB47782BA17C89B4685370BA" +
                    "92FCC71E8064B1999B299643C145E730E559751AE15FC215B28E6F55" +
                    "EE8CE6935D5EEF058E18D0A6";

    //私钥加密后的密文
    private  static final String SECRTE_DATA_ByPrivateKey =
                    "4C1890DE745311791089DD60732D93ED28F5EB74E5CCFAAAE325597F75" +
                    "3E308B7E1495118D1658D5CF07792B54F49AE902086C92C1D0EDD" +
                    "4C106F64CF2646D7ED393AA57209A56A34E23524F2453C656FE5E5B" +
                    "A0FE2D78B77BFE7AD34FE33B4B6E421C543760D961BBA206B46F9525" +
                    "E9407784AE859849152F724A892FF134BE";


    /**
     * 私钥
     */
    private RSAPrivateKey privateKey;

    /**
     * 公钥
     */
    private RSAPublicKey publicKey;

    /**
     * 字节数据转字符串专用集合
     */
    private static final char[] HEX_CHAR= {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};


    public String getDEFAULT_PUBLIC_KEY() {
        return DEFAULT_PUBLIC_KEY;
    }

    public void setDEFAULT_PUBLIC_KEY(String DEFAULT_PUBLIC_KEY) {
        this.DEFAULT_PUBLIC_KEY = DEFAULT_PUBLIC_KEY;
    }

    public String getDEFAULT_PRIVATE_KEY() {
        return DEFAULT_PRIVATE_KEY;
    }

    public void setDEFAULT_PRIVATE_KEY(String DEFAULT_PRIVATE_KEY) {
        this.DEFAULT_PRIVATE_KEY = DEFAULT_PRIVATE_KEY;
    }

    /**
     * 获取私钥
     * @return 当前的私钥对象
     */
    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * 获取公钥
     * @return 当前的公钥对象
     */
    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * 随机生成密钥对
     */
    public void genKeyPair(){
        KeyPairGenerator keyPairGen= null;
        try {
            keyPairGen= KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        keyPairGen.initialize(1024, new SecureRandom());
        KeyPair keyPair= keyPairGen.generateKeyPair();
        this.privateKey= (RSAPrivateKey) keyPair.getPrivate();
        this.publicKey= (RSAPublicKey) keyPair.getPublic();
    }

    /**
     * 从文件中输入流中加载公钥
     * @param in 公钥输入流
     * @throws Exception 加载公钥时产生的异常
     */
    public void loadPublicKey(InputStream in) throws Exception{
        try {
            BufferedReader br= new BufferedReader(new InputStreamReader(in));
            String readLine= null;
            StringBuilder sb= new StringBuilder();
            while((readLine= br.readLine())!=null){
                if(readLine.charAt(0)=='-'){
                    continue;
                }else{
                    sb.append(readLine);
                    sb.append('\r');
                }
            }
            loadPublicKey(sb.toString());
        } catch (IOException e) {
            throw new Exception("公钥数据流读取错误");
        } catch (NullPointerException e) {
            throw new Exception("公钥输入流为空");
        }
    }


    /**
     * 从字符串中加载公钥
     * @param publicKeyStr 公钥数据字符串
     * @throws Exception 加载公钥时产生的异常
     */
    public void loadPublicKey(String publicKeyStr) throws Exception{
        try {
            BASE64Decoder base64Decoder= new BASE64Decoder();
            byte[] buffer= base64Decoder.decodeBuffer(publicKeyStr);
            System.out.println("公钥buffer length: "+buffer.length);
            System.out.println(byteArrayToString(buffer));
            System.out.println("==============");
            KeyFactory keyFactory= KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec= new X509EncodedKeySpec(buffer);
            this.publicKey= (RSAPublicKey) keyFactory.generatePublic(keySpec);
//            System.out.println(this.publicKey);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("公钥非法");
        } catch (IOException e) {
            throw new Exception("公钥数据内容读取错误");
        } catch (NullPointerException e) {
            throw new Exception("公钥数据为空");
        }
    }

    /**
     * 从文件中加载私钥
     * @param in keyFileName 私钥文件名
     * @return 是否成功
     * @throws Exception
     */
    public void loadPrivateKey(InputStream in) throws Exception{
        try {
            BufferedReader br= new BufferedReader(new InputStreamReader(in));
            String readLine= null;
            StringBuilder sb= new StringBuilder();
            while((readLine= br.readLine())!=null){
                if(readLine.charAt(0)=='-'){
                    continue;
                }else{
                    sb.append(readLine);
                    sb.append('\r');
                }
            }
            loadPrivateKey(sb.toString());
        } catch (IOException e) {
            throw new Exception("私钥数据读取错误");
        } catch (NullPointerException e) {
            throw new Exception("私钥输入流为空");
        }
    }

    public void loadPrivateKey(String privateKeyStr) throws Exception{
        try {
            BASE64Decoder base64Decoder= new BASE64Decoder();
            byte[] buffer= base64Decoder.decodeBuffer(privateKeyStr);
            System.out.println("私钥buffer length: "+buffer.length);
            System.out.println(byteArrayToString(buffer));
            System.out.println("==============");
            //从PKCS#1的私钥文件读取
            RSAPrivateKeyStructure asn1PrivKey = new RSAPrivateKeyStructure((ASN1Sequence) ASN1Sequence.fromByteArray(buffer));
            RSAPrivateKeySpec rsaPrivKeySpec = new RSAPrivateKeySpec(asn1PrivKey.getModulus(), asn1PrivKey.getPrivateExponent());
            KeyFactory keyFactory= KeyFactory.getInstance("RSA");
            this.privateKey=(RSAPrivateKey) keyFactory.generatePrivate(rsaPrivKeySpec);
            //私钥经过PKCS#8编码后的私钥
//            PKCS8EncodedKeySpec keySpec= new PKCS8EncodedKeySpec(buffer);
//            KeyFactory keyFactory= KeyFactory.getInstance("RSA");
//            this.privateKey= (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此算法");
        } catch (InvalidKeySpecException e) {
            throw new Exception("私钥非法");
        } catch (IOException e) {
            throw new Exception("私钥数据内容读取错误");
        } catch (NullPointerException e) {
            throw new Exception("私钥数据为空");
        }
    }

    /**
     * 加密过程
     * @param publicKey 公钥
     * @param plainTextData 明文数据
     * @return
     * @throws Exception 加密过程中的异常信息
     */
    public byte[] encrypt(RSAPublicKey publicKey, byte[] plainTextData) throws Exception{
        if(publicKey== null){
            throw new Exception("加密公钥为空, 请设置");
        }
        Cipher cipher= null;
        try {
            cipher= Cipher.getInstance("RSA", new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] output= cipher.doFinal(plainTextData);
            return output;
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此加密算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }catch (InvalidKeyException e) {
            throw new Exception("加密公钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("明文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("明文数据已损坏");
        }
    }

    /**
     * 解密过程
     * @param privateKey 私钥
     * @param cipherData 密文数据
     * @return 明文
     * @throws Exception 解密过程中的异常信息
     */
    public byte[] decrypt(RSAPrivateKey privateKey, byte[] cipherData) throws Exception{
        if (privateKey== null){
            throw new Exception("解密私钥为空, 请设置");
        }
        Cipher cipher= null;
        try {
            cipher= Cipher.getInstance("RSA", new BouncyCastleProvider());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] output= cipher.doFinal(cipherData);
            return output;
        } catch (NoSuchAlgorithmException e) {
            throw new Exception("无此解密算法");
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }catch (InvalidKeyException e) {
            throw new Exception("解密私钥非法,请检查");
        } catch (IllegalBlockSizeException e) {
            throw new Exception("密文长度非法");
        } catch (BadPaddingException e) {
            throw new Exception("密文数据已损坏");
        }
    }

    /**
     * 字节数据转十六进制字符串
     * @param data 输入数据
     * @return 十六进制内容
     */
    public static String byteArrayToString(byte[] data){
        StringBuilder stringBuilder= new StringBuilder();
        for (int i=0; i<data.length; i++){
            //取出字节的高四位 作为索引得到相应的十六进制标识符 注意无符号右移
            stringBuilder.append(HEX_CHAR[(data[i] & 0xf0)>>> 4]);
            //取出字节的低四位 作为索引得到相应的十六进制标识符
            stringBuilder.append(HEX_CHAR[(data[i] & 0x0f)]);
            if (i<data.length-1){
                stringBuilder.append(' ');
            }
        }
        return stringBuilder.toString();
    }

    /**
     * 十六进制转为byte[]
     * @param str
     * @return
     */
    public static byte[] stringToBytes(String str) {
        if(str == null || str.trim().equals("")) {
            return new byte[0];
        }

        byte[] bytes = new byte[str.length() / 2];
        for(int i = 0; i < str.length() / 2; i++) {
            String subStr = str.substring(i * 2, i * 2 + 2);
            bytes[i] = (byte) Integer.parseInt(subStr, 16);
        }

        return bytes;
    }



    /**
     * 私钥解密/私钥加密 通过传入字节流
     * @param byteStream
     * @return 十六进制数（带空格格式）
     */
    public String usePrivateKey(byte[] byteStream){
        if(byteStream == null){
            return null;
        }
        //加载私钥
        try {
            loadPrivateKey(DEFAULT_PRIVATE_KEY);

            System.out.println("加载私钥成功");
        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.err.println("加载私钥失败");
        }
        byte[] plainText = null;
        try {
            plainText = decrypt(getPrivateKey(),byteStream);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return byteArrayToString(plainText);
    }

    /**
     * 私钥解密/私钥加密 通过转入十六进制字符串
     * @param hexStr
     * @return 十六进制数（带空格格式）
     */
    public String usePrivateKey(String hexStr){
        if(hexStr != null){
            return usePrivateKey(stringToBytes(hexStr.replace(" ", "").toLowerCase()));
        }else {
            return null;
        }
    }

    /**
     * 公钥解密/公钥加密 通过传入字节流
     * @param byteStream
     * @return 十六进制数（带空格格式）
     */
    public String usePublicKey(byte[] byteStream){
        if(byteStream == null){
            return null;
        }
        //加载公钥
        try {
            loadPublicKey(DEFAULT_PUBLIC_KEY);
            System.out.println("加载公钥成功");
        } catch (Exception e) {
            System.err.println(e.getMessage());
            System.err.println("加载公钥失败");
        }
        byte[] cipher = null;
        try {
            cipher = encrypt(getPublicKey(), byteStream);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return byteArrayToString(cipher);
    }

    /**
     * 公钥解密/公钥加密 通过传入字节流
     * @param hexStr
     * @return 十六进制数（带空格格式）
     */
    public String usePublicKey(String hexStr){
        if(hexStr != null){
            return usePublicKey(stringToBytes(hexStr.replace(" ", "").toLowerCase()));
        }else {
            return null;
        }
    }

    /**
     * 输出到文件
     * @param data
     * @param location
     */
    public void outputFile(String data,String location){
        if(data == null){
            return;
        }
        File f = new File(location); // 相对路径，如果没有则要建立一个新的output。txt文件
        BufferedWriter out = null;
        try {
            out = new BufferedWriter(new OutputStreamWriter(
                    new FileOutputStream(f, true)));
            out.write(data+"\r\n");
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                out.close();
            } catch (IOException e) {
                e.printStackTrace();
            }

        }
    }


    public static void main(String[] args){
        Rsa1024 rsaEncrypt= new Rsa1024();
        //rsaEncrypt.genKeyPair();

        //测试字符串
        String encryptStr= "Test123456";
        String hexString = "12 34 56";

        String temp = rsaEncrypt.usePrivateKey(hexString);
        System.out.println("加密内容：\r\n"+temp);
        System.out.println(rsaEncrypt.usePublicKey(temp));

//        rsaEncrypt.outputFile(temp,"./test.txt");

    }
}