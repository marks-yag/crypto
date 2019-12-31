package com.github.yag.crypto

import java.security.SecureRandom
import java.time.Instant
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

/**
 *
 */
class AESCrypto(key: ByteArray) {

    constructor(key: String) : this(key.toByteArray(Charsets.UTF_8))

    private val key: ByteArray = padding(key)

    private val random = SecureRandom.getInstance("SHA1PRNG").apply {
        setSeed(Instant.now().toEpochMilli())
    }

    /**
     * Encrypt data in byte array.
     *
     * @param data origin data
     * @return encrypted data
     */
    fun encrypt(data: ByteArray): ByteArray {
        val iv = ByteArray(16).apply {
            random.nextBytes(this)
        }
        return iv.plus(getCipher().also {
            it.init(Cipher.ENCRYPT_MODE, getSecretKey(key), getIvParameterSpec(iv))
        }.doFinal(data))
    }

    fun decrypt(data: ByteArray): ByteArray {
        val iv = data.sliceArray(0..15)
        val encryptedData = data.sliceArray(16 until data.size)
        return getCipher().also {
            it.init(Cipher.DECRYPT_MODE, getSecretKey(key), getIvParameterSpec(iv))
        }.doFinal(encryptedData)
    }

    private fun getCipher() = Cipher.getInstance("AES/CBC/PKCS5Padding")

    private fun getIvParameterSpec(key: ByteArray) = IvParameterSpec(padding(key))

    private fun padding(key: ByteArray): ByteArray {
        return ByteArray(16).also {
            System.arraycopy(key, 0, it, 0, minOf(key.size, it.size))
        }
    }

    private fun getSecretKey(key: ByteArray): SecretKey {
        return KeyGenerator.getInstance("AES").apply {
            init(bits, SecureRandom.getInstance("SHA1PRNG").apply {
                setSeed(key)
            })
        }.generateKey()
    }

    companion object {

        private const val bits = 256

    }

}