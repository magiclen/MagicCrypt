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
package org.magiclen.magiccrypt;

/**
 * 計算CRC32雜奏值。
 *
 * @author Magic Len
 */
public class CRC32 {

    // -----類別方法-----
    /**
     * 取得資料的CRC32雜湊值。
     *
     * @param data 傳入要雜湊的資料
     * @return 傳回雜湊後資料內容
     */
    public static byte[] getHash(final byte[] data) {
        if (data == null) {
            return null;
        }
        final java.util.zip.CRC32 crc = new java.util.zip.CRC32();
        crc.update(data);
        final long sum = crc.getValue();
        final byte[] crc32 = new byte[8];
        crc32[0] = (byte) (sum >>> 56);
        crc32[1] = (byte) ((sum << 8) >>> 56);
        crc32[2] = (byte) ((sum << 16) >>> 56);
        crc32[3] = (byte) ((sum << 24) >>> 56);
        crc32[4] = (byte) ((sum << 32) >>> 56);
        crc32[5] = (byte) ((sum << 40) >>> 56);
        crc32[6] = (byte) ((sum << 48) >>> 56);
        crc32[7] = (byte) ((sum << 56) >>> 56);
        return crc32;
    }

    // -----建構子-----
    /**
     * 私有建構子，無法給外界實體化。
     */
    private CRC32() {
    }
}
