MagicCrypt
=================================

# Introduction

**MagicCrypt** is a Java/PHP library to encrypt/decrpyt strings or data using Advanced Encryption Standard(AES) algorithm. It supports `CBC` block cipher mode, `PKCS5` padding and 128 or 256-bits key length. The encrypted data will be formatted to Base64 string.

# Usage For Java

## MagicCrypt Class

**MagicCrypt** class is in the *org.magiclen.magiccrypt* package. It can help you encrypt/decrpyt strings or data using Advanced Encryption Standard(AES) algorithm.

### Initialize

You have to input your AES key and key length to construct **MagicCrypt** object. For example,

    final MagicCrypt mc = new MagicCrypt("magickey", 256);

Note. **MagicCrypt** only supports 128 and 256-bits key length. The larger key length, the stronger security of course. The default length is 128 bits. If you want to use 256 bits in your Java Runtime Machine (JRE), you have to install Java Cryptography Extension (JCE) first.

By the way, if you want to change Initialization Vector(IV), you can set it by passing your IV string into the third parameter to the constructor of **MagicCrypt** object.

### Encrypt

You can use **encrypt** method to encrypt any string or data. For example,

    final MagicCrypt mc = new MagicCrypt("magickey", 256);
    System.out.println(mc.encrypt("http://magiclen.org"));

The result is,

    DS/2U8royDnJDiNY2ps3f6ZoTbpZo8ZtUGYLGEjwLDQ=

### Decrypt

You can use **decrypt** method to decrypt any encrypted string or data. For example,

    final MagicCrypt mc = new MagicCrypt("magickey", 256);
    System.out.println(mc.decrypt("DS/2U8royDnJDiNY2ps3f6ZoTbpZo8ZtUGYLGEjwLDQ="));

The result is,

    http://magiclen.org

## Base64 Class

**Base64** class is in the *org.magiclen.magiccrypt* package. It is a clone of an implementation of Base64 in Java 8 SE adjusted for the old Java versions lower than 8.

# Usage For PHP

## MagicCrypt.php

### Initialize

`require` of `include` **MagicCrypt.php** into your PHP program. Then, you have to input your AES key and key length to construct **MagicCrypt** object. For example,

    require('MagicCrypt.php');

    $mc = new MagicCrypt('magickey', 256);

If you want to change Initialization Vector(IV), you can set it by passing your IV string into the third parameter to the constructor of **MagicCrypt** object.

### Encrypt

You can use **encrypt** method to encrypt any string or data. For example,

    $mc = new MagicCrypt('magickey', 256);
    echo $mc->encrypt('http://magiclen.org');

The result is,

    DS/2U8royDnJDiNY2ps3f6ZoTbpZo8ZtUGYLGEjwLDQ=

### Decrypt

You can use **decrypt** method to decrypt any encrypted string or data. For example,

    $mc = new MagicCrypt('magickey', 256);
    echo $mc->decrypt('DS/2U8royDnJDiNY2ps3f6ZoTbpZo8ZtUGYLGEjwLDQ=');

The result is,

    http://magiclen.org

# License

    Copyright 2015-2016 magiclen.org

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

# What's More?

Please check out our web page at

http://magiclen.org/aes/
