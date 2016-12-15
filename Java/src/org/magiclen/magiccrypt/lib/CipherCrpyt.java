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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import static org.magiclen.magiccrypt.lib.Crypt.BUFFER_SIZE;

/**
 * 透過Cipher來實現加/解密。
 *
 * @author Magic Len
 */
public abstract class CipherCrpyt extends Crypt {

    // -----物件變數-----
    /**
     * 加/解密的密鑰。
     */
    protected Key key;
    /**
     * 初始化向量(IV, Initialization Vector)。
     */
    protected IvParameterSpec iv;
    /**
     * Cipher 物件。
     */
    protected Cipher cipher;

    // -----物件方法-----
    /**
     * 加/解密資料。
     *
     * @param inputData 傳入輸入的資料流
     * @param outputData 傳入輸出的資料流
     * @param listener 傳入監聽者物件
     * @throws java.io.IOException 當輸入輸出處理時發生問題，會拋出這個例外
     */
    protected void crypt(final InputStream inputData, final OutputStream outputData, final Crypt.CryptListener listener) throws IOException {
        final int totalBytes = inputData.available();

        if (listener != null) {
            listener.onStarted(totalBytes);
        }

        long sum = 0;
        try (final CipherOutputStream cos = new CipherOutputStream(outputData, cipher)) {
            int c;
            final byte[] buffer = new byte[BUFFER_SIZE];
            while ((c = inputData.read(buffer)) >= 0) {
                cos.write(buffer, 0, c);
                if (c > 0) {
                    sum += c;
                }
                if (listener != null) {
                    if (!listener.onRunning(sum, (sum > totalBytes) ? -1 : totalBytes)) {
                        break;
                    }
                }
            }
            inputData.close();
            cos.flush();
        }
        if (listener != null) {
            listener.onFinished(sum, totalBytes);
        }
    }

    /**
     * 加密資料。
     *
     * @param inputData 傳入要加密的資料流
     * @param outputData 傳入已加密的資料流
     * @param listener 傳入監聽者物件
     * @throws java.io.IOException 當輸入輸出處理時發生問題，會拋出這個例外
     */
    @Override
    public void encrypt(final InputStream inputData, final OutputStream outputData, final Crypt.CryptListener listener) throws IOException {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);
            crypt(inputData, outputData, listener);
        } catch (final IOException ex) {
            throw ex;
        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }

    /**
     * 解密資料。
     *
     * @param inputData 傳入要解密的資料流
     * @param outputData 傳入已解密的資料流
     * @param listener 傳入監聽者物件
     * @throws java.io.IOException 當輸入輸出處理時發生問題，會拋出這個例外
     */
    @Override
    public void decrypt(final InputStream inputData, final OutputStream outputData, final Crypt.CryptListener listener) throws IOException {
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, iv);
            crypt(inputData, outputData, listener);
        } catch (final IOException ex) {
            throw ex;
        } catch (final Exception ex) {
            throw new RuntimeException(ex.getMessage());
        }
    }
}
