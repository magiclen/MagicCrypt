/*
 *
 * Copyright 2015-2017 magiclen.org
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
package org.magiclen.magiccrypt.lib;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES CBC 128/192/256位元之加密/解密，使用PKCS5填充方式。
 *
 * @author Magic Len
 */
public class AESCrypt extends CipherCrpyt {

    // -----建構子-----
    /**
     * 建構子。
     *
     * @param key 傳入16位元組(128位元)、24位元組(192位元)或是32位元組(256位元)的密鑰
     * @param iv 傳入16位元組(128位元)的初始化向量
     */
    public AESCrypt(final byte[] key, final byte[] iv) {
        if (key == null || iv == null) {
            throw new RuntimeException("Need a key and an initialization vector to construct an AESCrypt object!");
        }

        final int keyLength = key.length;
        if (keyLength != 16 && keyLength != 24 && keyLength != 32) {
            throw new RuntimeException("The AES key must be 16 bytes(128 bits), 24 bytes(192 bits) or 32 bytes(256 bits)!");
        }

        final int ivLength = iv.length;
        if (ivLength != 16) {
            throw new RuntimeException("The IV must be 16 bytes(128 bits)!");
        }

        this.key = new SecretKeySpec(key, "AES");
        this.iv = new IvParameterSpec(iv);

        init();
    }

    // -----物件方法-----
    /**
     * 初始化。
     */
    private void init() {
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }
}
