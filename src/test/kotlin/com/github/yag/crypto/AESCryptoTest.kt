package com.github.yag.crypto

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue


class AESCryptoTest {

    private val crypto = AESCrypto("hello".toByteArray())

    @Test
    fun testByteArray() {
        val random = Random(System.currentTimeMillis())
        val data = random.nextBytes(1024)


        val encryptedData = crypto.encrypt(data)
        val decryptedData = crypto.decrypt(encryptedData)

        println("raw data: ${data.toBase64()}")
        println("encrypt data: ${encryptedData.toBase64()}")

        assertTrue(decryptedData.contentEquals(data))
    }

}