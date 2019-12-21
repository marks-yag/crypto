package com.github.yag.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue


class AESCryptoTest {

    private val crypto = AESCrypto("hello".toByteArray())

    @Test
    fun testString() {
        val data = "hello"
        val encryptedData = crypto.encrypt(data.toUtf8())
        val decryptedData = crypto.decrypt(encryptedData).toUtf8()

        assertEquals(data, decryptedData)
        assertEquals(32, encryptedData.size)

        assertEquals(10, Array(10) {
            crypto.encrypt(data.toUtf8()).also {
                assertEquals(data, crypto.decrypt(it).toUtf8())
            }
        }.toSet().size)
    }

    @Test
    fun testByteArray() {
        val data = "hello".toByteArray(Charsets.UTF_8)
        val encryptedData = crypto.encrypt(data)
        val decryptedData = crypto.decrypt(encryptedData)

        assertTrue(decryptedData.contentEquals(data))
        assertEquals(32, encryptedData.size)
    }

}