package com.github.yag.crypto

import java.security.SecureRandom
import java.time.Instant
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class AESCrypto(key: ByteArray) {

    constructor(key: String) : this(key.toByteArray(Charsets.UTF_8))

    private val bits = 256

    private val key: ByteArray = padding(key)

    private val random = SecureRandom.getInstance("SHA1PRNG").apply {
        setSeed(Instant.now().toEpochMilli())
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

    fun encrypt(data: ByteArray): ByteArray {
        val iv = ByteArray(16).apply {
            random.nextBytes(this)
        }
        return iv.plus(getCipher().also {
            it.init(Cipher.ENCRYPT_MODE, getSecretKey(key), getIvParameterSpec(iv))
        }.doFinal(data))
    }

    fun encryptToBase64(data: ByteArray) = Base64.getEncoder().encodeToString(encrypt(data))

    fun encryptUTF(data: String) = encrypt(data.toByteArray(Charsets.UTF_8))

    fun encryptUTFToBase64(data: String) = Base64.getEncoder().encodeToString(encryptUTF(data))

    fun decrypt(data: ByteArray): ByteArray {
        assert(data.size == 32)

        val iv = data.sliceArray(0..15)
        val encryptedData = data.sliceArray(16 until data.size)
        return getCipher().also {
            it.init(Cipher.DECRYPT_MODE, getSecretKey(key), getIvParameterSpec(iv))
        }.doFinal(encryptedData)
    }

    fun decryptToUTF(data: ByteArray) = decrypt(data).toString(Charsets.UTF_8)

    fun decryptBase64(data: String) = decrypt(Base64.getDecoder().decode(data))

    fun decryptBase64ToUTF(data: String) = decryptBase64(data).toString(Charsets.UTF_8)

}