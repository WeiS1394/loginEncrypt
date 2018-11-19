//解密的工具类
package com.nssc.accountmis.honest.model;

import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import sun.misc.BASE64Decoder;

public class AesEncryptUtil {
	private static char ch[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
        'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b',
        'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w',
        'x', 'y', 'z', '0', '1' };//最后又重复两个0和1，因为需要凑足数组长度为64

	private static Random random = new Random();
    private static final String KEY = "o7H8uIM2O5qv65l2";  //加密和解密的Key要保持一致
    private static final String ALGORITHMSTR = "AES/ECB/PKCS5Padding";  
	private String key;
    
    public static String base64Encode(byte[] bytes){  
        return Base64.encodeBase64String(bytes);  
    }  
    
    public static byte[] base64Decode(String base64Code) throws Exception{  
        return new BASE64Decoder().decodeBuffer(base64Code);  
    }  
    
    public static byte[] aesEncryptToBytes(String content, String encryptKey) throws Exception {  
        KeyGenerator kgen = KeyGenerator.getInstance("AES");  
        kgen.init(128);  
        Cipher cipher = Cipher.getInstance(ALGORITHMSTR);  
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(encryptKey.getBytes(), "AES"));  

        return cipher.doFinal(content.getBytes("utf-8"));  
    }  
    
    public static String aesEncrypt(String content, String encryptKey) throws Exception {  
        return base64Encode(aesEncryptToBytes(content, encryptKey));  
    }  
    
    public static String aesDecryptByBytes(byte[] encryptBytes, String decryptKey) throws Exception {  
        KeyGenerator kgen = KeyGenerator.getInstance("AES");  
        kgen.init(128);  

        Cipher cipher = Cipher.getInstance(ALGORITHMSTR);  
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptKey.getBytes(), "AES"));  
        byte[] decryptBytes = cipher.doFinal(encryptBytes);  

        return new String(decryptBytes);  
    }  
    
    public static String aesDecrypt(String encryptStr, String decryptKey) throws Exception {  
        return aesDecryptByBytes(base64Decode(encryptStr), decryptKey);  
    }  

    public static String aesDecrypt(String encryptStr) throws Exception {  
        return aesDecryptByBytes(base64Decode(encryptStr), KEY);  
    }
    
	//生成指定长度的随机字符串
	public static synchronized String createRandomString(int length) {
	    if (length > 0) {
	        int index = 0;
	        char[] temp = new char[length];
	        int num = random.nextInt();
	        for (int i = 0; i < length % 5; i++) {
	            temp[index++] = ch[num & 63];//取后面六位，记得对应的二进制是以补码形式存在的。
	            num >>= 6;//63的二进制为:111111
	            // 为什么要右移6位？因为数组里面一共有64个有效字符。为什么要除5取余？因为一个int型要用4个字节表示，也就是32位。
	        }
	        for (int i = 0; i < length / 5; i++) {
	            num = random.nextInt();
	            for (int j = 0; j < 5; j++) {
	                temp[index++] = ch[num & 63];
	                num >>= 6;
	            }
	        }
	        return new String(temp, 0, length);
	    }
	    else if (length == 0) {
	        return "";
	    }
	    else {
	        throw new IllegalArgumentException();
	    }
	}

    /**
     * 测试
     * 
     */
    public static void main(String[] args) throws Exception {

        String content = "Test String么么哒";  //有几种情况加密时有空格字符，在解密的时候解密不出来的情况
        System.out.println("加密前：" + content);  

		key = createRandomString(16);  //获取随机值
        System.out.println("加密密钥和解密密钥：" + key);  

        String encrypt = aesEncrypt(content, key);    //加密
        System.out.println(encrypt.length()+":加密后：" + encrypt);  

		try{
			String decrypt = aesDecrypt(encrypt, key);    //解密  encrypt.replaceAll("@", "+")
		} catch (Exception e1) {
    	   decrypt = "";
		}
		//userid = userid.trim();
		decrypt = decrypt.trim();
        
        System.out.println("解密后：" + decrypt);  
    }

}