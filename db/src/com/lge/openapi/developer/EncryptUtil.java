/*!
 * @(#)EncryptUtil.java
 */
package com.lge.openapi.developer.common.util;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.springframework.stereotype.Component;

import com.lge.openapi.developer.common.exception.ApplicationException;
import com.lge.openapi.developer.common.response.MessageEnum;

import jakarta.xml.bind.DatatypeConverter;
import lombok.extern.slf4j.Slf4j;

/**
 * @section Program EncryptUtil - Utility class for encryption.
 */
@Component
@Slf4j
public class EncryptUtil {

	/**
	 * AES 암호화 관련 키
	 */
	public static final String PRIVATE_KEY_AES = "LGBC_OPEN_API_DEVELOPER_API__KEY";

	/**
	 * @brief SHA512 암호화
	 * @details SHA512 암호화
	 * @throw
	 */
	public String encryptSHA512(String str) {
		String sha = "";
		try {
			StringBuffer sb = new StringBuffer();
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			md.update(str.getBytes());
			byte[] digest = md.digest();
			String hex;
			for (byte aDigest : digest) {
				hex = Integer.toHexString(0xFF & aDigest);
				if (hex.length() < 2) {
					sb.append("0");
				}
				sb.append(hex);
			}
			sha = sb.toString();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			sha = null;
		}
		return sha;
	}

	/**
	 * @brief RSA2048 암호화
	 * @details RSA2048 암호화
	 * @throw
	 */
	public String encryptRSA2048(String decodeText) {
//		String	publicKeyString1	= 	"-----BEGIN PUBLIC KEY-----\n";
//		publicKeyString1			+=	"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkk9Kt8TBCC8K3S1qH6/W\n";
//		publicKeyString1			+=	"QNEnhbbkhJ5qtmdv5mg+Zazhl2qNpb38iP+JGeZD48JrUIaqi2G0Y4JlNRoQQMc2\n";
//		publicKeyString1			+=	"Z+pTa0AVfw+v1CflTQQFD9+2mVpu2kFH5bFyIeYg0vpbVl9oJSXKC6NJDi6hsZTw\n";
//		publicKeyString1			+=	"8olcdBtl0sUo9xwNyxA7efHHAV3kNghBEWmm2roRNd2oyWmwjJFcHyNH+FizMvxW\n";
//		publicKeyString1			+=	"6TTdFB83b27Lj5n1HsYoAZcMf3jYK00YdstLeEQnQURf6+LuBqClDhNJGloBncMv\n";
//		publicKeyString1			+=	"/jDp/M2WBMvPVH5+Yvlk55FJCTjQFHj4SJjCii/X9lYnnwOuPxTS5d4Vzn82Sajm\n";
//		publicKeyString1			+=	"SwIDAQAB\n";
//		publicKeyString1			+=	"-----END PUBLIC KEY-----";

		StringBuffer publicKeyString = new StringBuffer();
		publicKeyString.append("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkk9Kt8TBCC8K3S1qH6/W");
		publicKeyString.append("QNEnhbbkhJ5qtmdv5mg+Zazhl2qNpb38iP+JGeZD48JrUIaqi2G0Y4JlNRoQQMc2");
		publicKeyString.append("Z+pTa0AVfw+v1CflTQQFD9+2mVpu2kFH5bFyIeYg0vpbVl9oJSXKC6NJDi6hsZTw");
		publicKeyString.append("8olcdBtl0sUo9xwNyxA7efHHAV3kNghBEWmm2roRNd2oyWmwjJFcHyNH+FizMvxW");
		publicKeyString.append("6TTdFB83b27Lj5n1HsYoAZcMf3jYK00YdstLeEQnQURf6+LuBqClDhNJGloBncMv");
		publicKeyString.append("/jDp/M2WBMvPVH5+Yvlk55FJCTjQFHj4SJjCii/X9lYnnwOuPxTS5d4Vzn82Sajm");
		publicKeyString.append("SwIDAQAB");

		String encryption = null;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			SecureRandom secureRandom = new SecureRandom();
			keyPairGenerator.initialize(2048, secureRandom);
			PublicKey publicKey = (PublicKey) this.loadPublicKey(publicKeyString.toString());
			Cipher encryptionCipher = Cipher.getInstance("RSA");
			encryptionCipher.init(Cipher.ENCRYPT_MODE, publicKey);
			String message = decodeText;
			byte[] encryptedMessage = encryptionCipher.doFinal(message.getBytes());
			encryption = Base64.encodeBase64String(encryptedMessage);
		} catch (GeneralSecurityException gse) {
			gse.printStackTrace();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
		return encryption;
	}

	// 문자열 공개키를 Key로 변환
	private Key loadPublicKey(String stored) throws GeneralSecurityException, IOException {
		byte[] data = Base64.decodeBase64((stored.getBytes()));
		X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
		KeyFactory fact = KeyFactory.getInstance("RSA");
		return fact.generatePublic(spec);
	}

	/**
	 * @brief Password 암호화
	 * @details Password 암호화
	 * @throw
	 */
	public String encryptPwd(String val) {
		String sha = "";
		try {
			// MD5
			MessageDigest md = MessageDigest.getInstance("MD5");
			md.update(val.getBytes());
			byte[] digest = md.digest();
			sha = DatatypeConverter.printHexBinary(digest).toUpperCase();
			System.out.println("☆☆☆☆☆☆☆ sha[MD5] ---> \n" + sha);
			// SHA-1
			md = MessageDigest.getInstance("SHA-1");
			md.update(sha.getBytes());
			digest = md.digest();
			sha = DatatypeConverter.printHexBinary(digest).toUpperCase();
			System.out.println("☆☆☆☆☆☆☆ sha[SHA-1] ---> \n" + sha);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			sha = null;
		}
		return sha;
	}

	/**
	 * AES-256 양방향 암호화 인코딩
	 * @param plainText
	 * @return
	 * @throws Exception
	 */
	public String aesCBCEncode(String plainText) {

		byte[] encrpytionByte = null;
		try {
			SecretKeySpec secretKey = new SecretKeySpec(PRIVATE_KEY_AES.getBytes("UTF-8"), "AES");
			IvParameterSpec IV = new IvParameterSpec(PRIVATE_KEY_AES.substring(0, 16).getBytes());

			Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");

			c.init(Cipher.ENCRYPT_MODE, secretKey, IV);

			encrpytionByte = c.doFinal(plainText.getBytes("UTF-8"));
		} catch (InvalidKeyException | UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
			log.error("aesCBCEncode error : {}", e);
			throw new ApplicationException(MessageEnum.E50000, e.getMessage());
		}

		return Hex.encodeHexString(encrpytionByte);
	}

	/**
	 * AES-256 양방향 암호화 디코딩
	 * @param encodeText
	 * @return
	 * @throws Exception
	 */
	public String aesCBCDecode(String encodeText) {

		try {
			SecretKeySpec secretKey = new SecretKeySpec(PRIVATE_KEY_AES.getBytes("UTF-8"), "AES");
			IvParameterSpec IV = new IvParameterSpec(PRIVATE_KEY_AES.substring(0, 16).getBytes());

			Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");

			c.init(Cipher.DECRYPT_MODE, secretKey, IV);

			byte[] decodeByte = Hex.decodeHex(encodeText.toCharArray());

			return new String(c.doFinal(decodeByte), "UTF-8");
		} catch (InvalidKeyException | UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
				| DecoderException e) {
			log.error("aesCBCEncode error : {}", e);
			throw new ApplicationException(MessageEnum.E50000, e.getMessage());
		}
	}

}