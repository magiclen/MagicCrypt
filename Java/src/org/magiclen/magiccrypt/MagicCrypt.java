/*
 *
 * Copyright 2015-2018 magiclen.org
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */
package org.magiclen.magiccrypt;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import org.magiclen.magiccrypt.lib.Crypt;
import org.magiclen.magiccrypt.lib.Crypt.CryptListener;
import org.magiclen.magiccrypt.lib.AESCrypt;
import org.magiclen.magiccrypt.lib.DESCrypt;

/**
 * DES/AES CBC 64/128/192/256位元之加密/解密，使用PKCS5填充方式。支援檔案、字串加密。
 *
 * @see Base64
 * @see CRC64
 * @see Crypt
 * @see CryptListener
 * @see AESCrypt
 * @see DESCrypt
 *
 * @author Magic Len
 */
public class MagicCrypt {

    // -----物件變數-----
    /**
     * 加/解密物件。
     */
    private Crypt crypt;

    // -----建構子-----
    /**
     * 建構子，使用128位元的AES密鑰和預設IV。
     *
     * @param key 傳入任意長度的密鑰字串
     */
    public MagicCrypt(final String key) {
        this(key, 128);
    }

    /**
     * 建構子，使用64位元的DES密鑰，或是128位元、192位元、256位元的AES密鑰和預設IV。
     *
     * @param key 傳入任意長度的密鑰字串
     * @param bit 傳入密鑰長度，數值可以是64、128、192、256(位元)
     */
    public MagicCrypt(final String key, final int bit) {
        this(key, bit, null);
    }

    /**
     * <p>
     * 建構子，使用64位元的DES密鑰，或是128位元、192位元、256位元的AES密鑰和自訂IV。</p>
     *
     * <p>
     * 64位元的密鑰會使用CRC64進行計算；128位元的密鑰使用MD5進行計算，192位元的密鑰使用Tiger進行計算，256位元的密鑰使用SHA256進行計算。</p>
     *
     * <p>
     * DES的IV會使用CRC64進行計算(64位元)；AES的IV會使用MD5進行計算(128位元)。</p>
     *
     * @param key 傳入任意長度的密鑰字串
     * @param bit 傳入密鑰長度，數值可以是64、128、192、256(位元)
     * @param iv 傳入任意長度的IV字串
     */
    public MagicCrypt(String key, final int bit, final String iv) {
        if (key == null) {
            key = "";
        }
        final byte[] keyByte, ivByte;
        switch (bit) {
            case 64: {
                keyByte = getHash("CRC64", key);
                if (iv != null) {
                    ivByte = getHash("CRC64", iv);
                } else {
                    ivByte = new byte[]{0, 0, 0, 0, 0, 0, 0, 0};
                }
                crypt = new DESCrypt(keyByte, ivByte);
            }
            break;
            case 128:
            case 192:
            case 256: {
                switch (bit) {
                    case 128:
                        keyByte = getHash("MD5", key);
                        break;
                    case 192:
                        keyByte = getHash("TIGER", key);
                        break;
                    case 256:
                        keyByte = getHash("SHA-256", key);
                        break;
                    default:
                        throw new RuntimeException();
                }
                if (iv != null) {
                    ivByte = getHash("MD5", iv);
                } else {
                    ivByte = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
                }
                crypt = new AESCrypt(keyByte, ivByte);
            }
            break;
            default:
                throw new RuntimeException("The key must be 8 bytes(64 bits), 16 bytes(128 bits), 24 bytes(192 bits) or 32 bytes(256 bits)!");
        }
    }

    // -----類別方法-----
    /**
     * 講位元組陣列資料轉成16進制的字串。
     *
     * @param data 傳入位元組陣列資料
     * @return 傳回16進制的字串
     */
    public static String byteToHexString(final byte[] data) {
        if (data == null) {
            return null;
        }
        final StringBuilder sb = new StringBuilder();
        for (final int b : data) {
            final int m = (b << 24) >>> 28;
            final int l = (b << 28) >>> 28;
            sb.append(hexDigit(m)).append(hexDigit(l));
        }
        return sb.toString();
    }

    /**
     * 將16進制的單一位數轉成字元。
     *
     * @param digit 傳入整數，範圍在0~15之間
     * @return 傳回代表整數的字元
     */
    private static char hexDigit(final int digit) {
        if (digit >= 0 && digit <= 9) {
            return (char) ('0' + digit);
        } else if (digit >= 10 && digit <= 15) {
            return (char) ('a' + digit - 10);
        }
        throw new RuntimeException("The hex digit is out of bounds.");
    }

    /**
     * 取得字串的雜湊值。
     *
     * @param algorithm 傳入雜驟演算法
     * @param text 傳入要雜湊的字串
     * @return 傳回雜湊後資料內容
     */
    private static byte[] getHash(final String algorithm, final String text) {
        try {
            return getHash(algorithm, text.getBytes("UTF-8"));
        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    /**
     * 取得資料的雜湊值。
     *
     * @param algorithm 傳入雜驟演算法
     * @param data 傳入要雜湊的資料
     * @return 傳回雜湊後資料內容
     */
    private static byte[] getHash(final String algorithm, final byte[] data) {
        try {
            switch (algorithm.toUpperCase()) {
                case "CRC64":
                    return CRC64.getHash(data);
                case "TIGER":
                    return Tiger.getHash(data);
                default:
                    final MessageDigest digest = MessageDigest.getInstance(algorithm);
                    digest.update(data);
                    return digest.digest();
            }

        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    // -----物件方法-----
    /**
     * 加密文字。
     *
     * @param str 傳入要加密的文字
     * @return 傳回加密後的文字
     */
    public String encrypt(final String str) {
        try {
            return encrypt(str, null);
        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    /**
     * 加密文字。
     *
     * @param str 傳入要加密的文字
     * @param listener 傳入監聽者物件
     * @return 傳回加密後的文字
     */
    public String encrypt(final String str, final CryptListener listener) {
        try {
            final byte[] data = encrypt(str.getBytes("UTF-8"), listener);
            return Base64.getEncoder().encodeToString(data);
        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    /**
     * 加密資料。
     *
     * @param data 傳入要加密的資料
     * @return 傳回加密後的資料
     */
    public byte[] encrypt(final byte[] data) {
        try {
            return encrypt(data, null);
        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    /**
     * 加密資料。
     *
     * @param data 傳入要加密的資料
     * @param listener 傳入監聽者物件
     * @return 傳回加密後的資料
     */
    public byte[] encrypt(final byte[] data, final CryptListener listener) {
        try {
            return crypt.encrypt(data, listener);
        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    /**
     * 加密資料。
     *
     * @param inputFile 傳入要加密的檔案
     * @param outputFile 傳入已加密完成的檔案
     * @throws java.io.IOException 當輸入輸出處理時發生問題，會拋出這個例外
     */
    public void encrypt(final File inputFile, final File outputFile) throws IOException {
        encrypt(inputFile, outputFile, null);
    }

    /**
     * 加密資料。
     *
     * @param inputFile 傳入要加密的檔案
     * @param outputFile 傳入已加密完成的檔案
     * @param listener 傳入監聽者物件
     * @throws java.io.IOException 當輸入輸出處理時發生問題，會拋出這個例外
     */
    public void encrypt(final File inputFile, final File outputFile, final Crypt.CryptListener listener) throws IOException {
        try (final BufferedInputStream bis = new BufferedInputStream(new FileInputStream(inputFile)); final BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outputFile))) {
            encrypt(bis, bos, listener);
            bos.flush();
        }
    }

    /**
     * 加密資料。
     *
     * @param inputData 傳入要加密的資料流
     * @param outputData 傳入已加密的資料流
     * @throws java.io.IOException 當輸入輸出處理時發生問題，會拋出這個例外
     */
    public void encrypt(final InputStream inputData, final OutputStream outputData) throws IOException {
        encrypt(inputData, outputData, null);
    }

    /**
     * 加密資料。
     *
     * @param inputData 傳入要加密的資料流
     * @param outputData 傳入已加密的資料流
     * @param listener 傳入監聽者物件
     * @throws java.io.IOException 當輸入輸出處理時發生問題，會拋出這個例外
     */
    public void encrypt(final InputStream inputData, final OutputStream outputData, final Crypt.CryptListener listener) throws IOException {
        crypt.encrypt(inputData, outputData, listener);
    }

    /**
     * 解密文字。
     *
     * @param str 傳入要解密的文字
     * @return 傳回解密後的文字
     */
    public String decrypt(final String str) {
        try {
            return decrypt(str, null);
        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    /**
     * 解密文字。
     *
     * @param str 傳入要解密的文字
     * @param listener 傳入監聽者物件
     * @return 傳回解密後的文字
     */
    public String decrypt(final String str, final CryptListener listener) {
        try {
            final byte[] data = decrypt(Base64.getDecoder().decode(str), listener);
            return new String(data, "UTF-8");
        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    /**
     * 解密資料。
     *
     * @param data 傳入要解密的資料
     * @return 傳回解密後的資料
     */
    public byte[] decrypt(final byte[] data) {
        try {
            return decrypt(data, null);
        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    /**
     * 解密資料。
     *
     * @param data 傳入要解密的資料
     * @param listener 傳入監聽者物件
     * @return 傳回解密後的資料
     */
    public byte[] decrypt(final byte[] data, final CryptListener listener) {
        try {
            return crypt.decrypt(data, listener);
        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    /**
     * 解密資料。
     *
     * @param inputFile 傳入要解密的檔案
     * @param outputFile 傳入已解密完成的檔案
     * @throws java.io.IOException 當輸入輸出處理時發生問題，會拋出這個例外
     */
    public void decrypt(final File inputFile, final File outputFile) throws IOException {
        decrypt(inputFile, outputFile, null);
    }

    /**
     * 解密資料。
     *
     * @param inputFile 傳入要解密的檔案
     * @param outputFile 傳入已解密完成的檔案
     * @param listener 傳入監聽者物件
     * @throws java.io.IOException 當輸入輸出處理時發生問題，會拋出這個例外
     */
    public void decrypt(final File inputFile, final File outputFile, final Crypt.CryptListener listener) throws IOException {
        try (final BufferedInputStream bis = new BufferedInputStream(new FileInputStream(inputFile)); final BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(outputFile))) {
            decrypt(bis, bos, listener);
            bos.flush();
        }
    }

    /**
     * 解密資料。
     *
     * @param inputData 傳入要解密的資料流
     * @param outputData 傳入已解密的資料流
     * @throws java.io.IOException 當輸入輸出處理時發生問題，會拋出這個例外
     */
    public void decrypt(final InputStream inputData, final OutputStream outputData) throws IOException {
        crypt.decrypt(inputData, outputData, null);
    }

    /**
     * 解密資料。
     *
     * @param inputData 傳入要解密的資料流
     * @param outputData 傳入已解密的資料流
     * @param listener 傳入監聽者物件
     * @throws java.io.IOException 當輸入輸出處理時發生問題，會拋出這個例外
     */
    public void decrypt(final InputStream inputData, final OutputStream outputData, final Crypt.CryptListener listener) throws IOException {
        crypt.decrypt(inputData, outputData, listener);
    }
}
