package com.github.smmousavi.mmplayer.android.service.encryption.inputestream

import java.io.FileInputStream
import java.math.BigInteger
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


class FileCipherInputStream(
    private val upstream: FileInputStream,
    private var cipher: Cipher,
    private val secretKeySpec: SecretKeySpec,
    private val ivParameterSpec: IvParameterSpec? = null,
) : TunedCipherInputStream(upstream, cipher, secretKeySpec) {

    fun forceSkip(bytesToSkip: Long): Long {
        val skipOverFlow = bytesToSkip % cipher.blockSize
        val skipBlockPosition = bytesToSkip - skipOverFlow
        try {
            if (skipBlockPosition <= 0) {
                initCipher()
                return 0L
            }
            var upstreamSkipped = upstream.skip(skipBlockPosition)
            while (upstreamSkipped < skipBlockPosition) {
                upstream.read()
                upstreamSkipped++
            }
            val cipherBlockArray = ByteArray(cipher.blockSize)
            upstream.read(cipherBlockArray)
            initCipher()
            val cipherSkipped = skip(skipBlockPosition)
            val negligibleBytes = ByteArray(skipOverFlow.toInt())
            read(negligibleBytes)
            return cipherSkipped
        } catch (e: Exception) {
            e.printStackTrace()
            return 0
        }
    }

    fun forceIvSkip(bytesToSkip: Long): Long {
        val skipped: Long = upstream.skip(bytesToSkip)
        try {
            val skipOverFlow = (bytesToSkip % cipher.blockSize).toInt()
            val skipBlockPosition = bytesToSkip - skipOverFlow
            val blocksNumber = skipBlockPosition / cipher.blockSize
            val ivOffset = BigInteger(1, ivParameterSpec!!.iv).add(
                BigInteger.valueOf(blocksNumber)
            )
            val ivOffsetBytes = ivOffset.toByteArray()
            val skippedIvSpec = if (ivOffsetBytes.size < cipher.blockSize) {
                val resizedIvOffsetBytes = ByteArray(cipher.blockSize)
                System.arraycopy(
                    ivOffsetBytes,
                    0,
                    resizedIvOffsetBytes,
                    cipher.blockSize - ivOffsetBytes.size,
                    ivOffsetBytes.size
                )
                IvParameterSpec(resizedIvOffsetBytes)
            } else {
                IvParameterSpec(
                    ivOffsetBytes,
                    ivOffsetBytes.size - cipher.blockSize,
                    cipher.blockSize
                )
            }

            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, skippedIvSpec)
            val skipBuffer = ByteArray(skipOverFlow)
            cipher.update(skipBuffer, 0, skipOverFlow, skipBuffer)
        } catch (e: java.lang.Exception) {
            e.printStackTrace()
            return 0
        }
        return skipped
    }
}