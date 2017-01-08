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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * 加/解密抽象類別，可監聽加解密過程。
 *
 * @author Magic Len
 */
public abstract class Crypt {

    // -----類別介面-----
    public static interface CryptListener {

        /**
         * 開始進行加/解密。
         *
         * @param totalBytes 要處理的資料大小
         */
        public void onStarted(final long totalBytes);

        /**
         * 正在進行加/解密。
         *
         * @param currentBytes 目前已處理的資料大小
         * @param totalBytes 全部的資料大小
         * @return 傳回是否要繼續處理資料
         */
        public boolean onRunning(final long currentBytes, final long totalBytes);

        /**
         * 加/解密結束。
         *
         * @param finishedBytes 已處理的資料大小
         * @param totalBytes 全部的資料大小
         */
        public void onFinished(final long finishedBytes, final long totalBytes);
    }

    // -----類別常數-----
    /**
     * 緩衝空間大小。
     */
    public static final int BUFFER_SIZE = 4096;

    // -----物件變數-----
    // -----物件方法-----
    /**
     * 加密資料。
     *
     * @param data 傳入要加密的資料
     * @return 傳回加密後的資料
     */
    public byte[] encrypt(final byte[] data) {
        return encrypt(data, null);
    }

    /**
     * 加密資料。
     *
     * @param data 傳入要加密的資料
     * @param listener 傳入監聽者物件
     * @return 傳回加密後的資料
     */
    public byte[] encrypt(final byte[] data, final CryptListener listener) {
        try (final ByteArrayInputStream bais = new ByteArrayInputStream(data); final ByteArrayOutputStream baos = new ByteArrayOutputStream();) {
            encrypt(bais, baos, listener);
            return baos.toByteArray();
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
        return decrypt(data, null);
    }

    /**
     * 解密資料。
     *
     * @param data 傳入要解密的資料
     * @param listener 傳入監聽者物件
     * @return 傳回加密後的資料
     */
    public byte[] decrypt(final byte[] data, final CryptListener listener) {
        try (final ByteArrayInputStream bais = new ByteArrayInputStream(data); final ByteArrayOutputStream baos = new ByteArrayOutputStream();) {
            decrypt(bais, baos, listener);
            return baos.toByteArray();
        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
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
     * 解密資料。
     *
     * @param inputData 傳入要解密的資料流
     * @param outputData 傳入已解密的資料流
     * @throws java.io.IOException 當輸入輸出處理時發生問題，會拋出這個例外
     */
    public void decrypt(final InputStream inputData, final OutputStream outputData) throws IOException {
        decrypt(inputData, outputData, null);
    }

    // -----抽象方法-----
    /**
     * 加密資料。
     *
     * @param inputData 傳入要加密的資料流
     * @param outputData 傳入已加密的資料流
     * @param listener 傳入監聽者物件
     * @throws java.io.IOException 當輸入輸出處理時發生問題，會拋出這個例外
     */
    public abstract void encrypt(final InputStream inputData, final OutputStream outputData, final CryptListener listener) throws IOException;

    /**
     * 解密資料。
     *
     * @param inputData 傳入要解密的資料流
     * @param outputData 傳入已解密的資料流
     * @param listener 傳入監聽者物件
     * @throws java.io.IOException 當輸入輸出處理時發生問題，會拋出這個例外
     */
    public abstract void decrypt(final InputStream inputData, final OutputStream outputData, final CryptListener listener) throws IOException;
}
