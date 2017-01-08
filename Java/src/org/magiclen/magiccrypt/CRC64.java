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
 * 計算CRC64(ECMA)雜奏值。
 *
 * @author Magic Len
 */
public class CRC64 {

    // -----類別常數-----
    private static final long POLY64REV = 0xC96C5795D7870F42L;
    private static final long[] LOOKUPTABLE = new long[256];

    // -----類別初始-----
    static {
        for (int i = 0; i < 256; ++i) {
            long v = i;
            for (int j = 0; j < 8; ++j) {
                if ((v & 1) == 1) {
                    v = (v >>> 1) ^ POLY64REV;
                } else {
                    v = (v >>> 1);
                }
            }
            LOOKUPTABLE[i] = v;
        }
    }

    // -----類別方法-----
    /**
     * 取得資料的CRC64雜湊值。
     *
     * @param data 傳入要雜湊的資料
     * @return 傳回雜湊後資料內容
     */
    public static byte[] getHash(final byte[] data) {
        if (data == null) {
            return null;
        }
        long sum = 0;
        for (final byte b : data) {
            final int lookupidx = ((int) sum ^ b) & 0xff;
            sum = (sum >>> 8) ^ LOOKUPTABLE[lookupidx];
        }
        final byte[] crc64 = new byte[8];
        crc64[0] = (byte) (sum >>> 56);
        crc64[1] = (byte) ((sum << 8) >>> 56);
        crc64[2] = (byte) ((sum << 16) >>> 56);
        crc64[3] = (byte) ((sum << 24) >>> 56);
        crc64[4] = (byte) ((sum << 32) >>> 56);
        crc64[5] = (byte) ((sum << 40) >>> 56);
        crc64[6] = (byte) ((sum << 48) >>> 56);
        crc64[7] = (byte) ((sum << 56) >>> 56);
        return crc64;
    }

    // -----建構子-----
    /**
     * 私有建構子，無法給外界實體化。
     */
    private CRC64() {
    }
}
