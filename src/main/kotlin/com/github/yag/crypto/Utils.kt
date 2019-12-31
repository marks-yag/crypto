package com.github.yag.crypto

import java.util.*

fun ByteArray.toBase64() : String {
    return Base64.getEncoder().encodeToString(this)
}

fun String.decodeBase64() : ByteArray {
    return Base64.getDecoder().decode(this)
}

fun ByteArray.toUtf8() : String {
    return this.toString(Charsets.UTF_8)
}

fun String.toUtf8() : ByteArray {
    return this.toByteArray(Charsets.UTF_8)
}