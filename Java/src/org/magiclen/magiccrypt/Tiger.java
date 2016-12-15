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
 * 計算Tiger雜奏值。
 *
 * @author Magic Len
 */
public class Tiger {

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
        final AwaruaTiger tiger = new AwaruaTiger();
        return tiger.ComputeHash(data);
    }

    // -----建構子-----
    /**
     * 私有建構子，無法給外界實體化。
     */
    private Tiger() {
    }
}
