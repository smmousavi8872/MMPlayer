package com.github.smmousavi.mmplayer.android.service.encryption.datasource

import androidx.annotation.OptIn
import androidx.media3.common.util.UnstableApi
import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.SecretKey
import javax.crypto.ShortBufferException

@OptIn(UnstableApi::class)
open class AesCtrTunedCipherInputStream(
    private val inputStream: InputStream,
    private val cipher: Cipher,
    private val keyParameterSpec: SecretKey,
) : FilterInputStream(inputStream) {


    // We need to return the available bytes from the upstream.
    // In this implementation we're front loading it, but it's possible the value might change during the lifetime
    // of this instance, and reference to the stream should be retained and queried for available bytes instead
    @Throws(IOException::class)
    override fun available(): Int {
        return inputStream.available()
    }

    /* the buffer holding data that have been read in from the
       underlying stream, but have not been processed by the cipher
       engine. the size 512 bytes is somewhat randomly chosen */
    private val iBuffer = ByteArray(8192)

    // having reached the end of the underlying input stream
    private var end = false

    /* the buffer holding data that have been processed by the cipher
       engine, but have not been read out */
    private var oBuffer: ByteArray? = null

    // the offset pointing to the next "new" byte
    private var oStart = 0

    // the offset pointing to the last "new" byte
    private var ofinish = 0

    // stream status
    private var closed = false

    private fun getMoreData(): Int {
        // Android-changed: The method was creating a new object every time update(byte[], int, int)
        // or doFinal() was called resulting in the old object being GCed. With do(byte[], int) and
        // update(byte[], int, int, byte[], int), we use already initialized obuffer.
        if (end) return -1
        ofinish = 0
        oStart = 0
        val expectedOutputSize: Int = cipher.getOutputSize(iBuffer.size)
        if (oBuffer == null || expectedOutputSize > oBuffer!!.size) {
            oBuffer = ByteArray(expectedOutputSize)
        }
        val readin = inputStream.read(iBuffer)
        if (readin == -1) {
            end = true
            try {
                // doFinal resets the cipher and it is the final call that is made. If there isn't
                // any more byte available, it returns 0. In case of any exception is raised,
                // obuffer will get reset and therefore, it is equivalent to no bytes returned.
                ofinish = cipher.doFinal(oBuffer, 0)
            } catch (e: IllegalBlockSizeException) {
                oBuffer = null
                throw IOException(e)
            } catch (e: BadPaddingException) {
                oBuffer = null
                throw IOException(e)
            } catch (e: ShortBufferException) {
                oBuffer = null
                throw IllegalStateException("ShortBufferException is not expected", e)
            }
        } else {
            // update returns number of bytes stored in obuffer.
            try {
               // cipher.init(Cipher.DECRYPT_MODE, keyParameterSpec)
                ofinish = cipher.update(iBuffer, 0, readin, oBuffer, 0)
            } catch (e: ShortBufferException) {
                e.printStackTrace()
            }
        }
        return ofinish
    }

    override fun read(): Int {
        if (oStart >= ofinish) {
            // we loop for new data as the spec says we are blocking
            var i = 0
            while (i == 0) i = getMoreData()
            if (i == -1) return -1
        }
        return oBuffer!![oStart++].toInt() and 0xff
    }

    override fun read(bytes: ByteArray): Int {
        return super.read(bytes)
    }

    override fun read(bytes: ByteArray?, offest: Int, length: Int): Int {
        if (oStart >= ofinish) {
            // we loop for new data as the spec says we are blocking
            var i = 0
            while (i == 0) i = getMoreData()
            if (i == -1) return -1
        }
        if (length <= 0) {
            return 0
        }
        var available = ofinish - oStart
        if (length < available) available = length
        if (bytes != null) {
            oBuffer?.let { System.arraycopy(it, oStart, bytes, offest, available) }
        }
        oStart += available
        return available
    }

    override fun skip(length: Long): Long {
        var n = length
        val available = ofinish - oStart
        if (n > available) {
            n = available.toLong()
        }
        if (n < 0) {
            return 0
        }
        oStart += n.toInt()
        return n
    }


//    @Throws(
//        IOException::class,
//        InvalidAlgorithmParameterException::class,
//        InvalidKeyException::class
//    )
//    fun forceSkip(bytesToSkip: Long): Long {
//        val skipped = inputStream.skip(bytesToSkip)
//        val skip = (bytesToSkip % 16).toInt()
//        val blockOffset = bytesToSkip - skip
//        val numberOfBlocks = blockOffset / 16
//        val ivForOffsetAsBigInteger =
//            BigInteger(1, ivParameterSpec.iv).add(BigInteger.valueOf(numberOfBlocks))
//        val ivForOffsetByteArray = ivForOffsetAsBigInteger.toByteArray()
//        val computedIvParameterSpecForOffset: IvParameterSpec =
//            if (ivForOffsetByteArray.size < 16) {
//                val resizedIvForOffsetByteArray = ByteArray(16)
//                System.arraycopy(
//                    ivForOffsetByteArray,
//                    0,
//                    resizedIvForOffsetByteArray,
//                    16 - ivForOffsetByteArray.size,
//                    ivForOffsetByteArray.size
//                )
//                IvParameterSpec(resizedIvForOffsetByteArray)
//            } else {
//                IvParameterSpec(
//                    ivForOffsetByteArray,
//                    ivForOffsetByteArray.size - 16,
//                    16
//                )
//            }
//        cipher.init(Cipher.DECRYPT_MODE, keyParameterSpec, computedIvParameterSpecForOffset)
//        val skipBuffer = ByteArray(16)
//        try {
//            cipher.update(skipBuffer, 0, skip, skipBuffer)
//        } catch (e: ShortBufferException) {
//            e.printStackTrace()
//        }
//        Arrays.fill(skipBuffer, 0.toByte())
//        return skipped
//    }

    /**
     * Tests if this input stream supports the `mark`
     * and `reset` methods, which it does not.
     *
     * @return  `false`, since this class does not support the
     * `mark` and `reset` methods.
     * @see java.io.InputStream.mark
     * @see java.io.InputStream.reset
     * @since   JCE1.2
     */
    override fun markSupported(): Boolean {
        return false
    }


    override fun close() {
        if (closed) {
            return
        }
        closed = true
        inputStream.close()

        // Android-removed: Removed a now-inaccurate comment
        if (!end) {
            try {
                cipher.doFinal()
            } catch (ex: BadPaddingException) {
                // Android-changed: Added throw if bad tag is seen.  See b/31590622.
                if (ex is AEADBadTagException) {
                    throw IOException(ex)
                }
            } catch (ex: IllegalBlockSizeException) {
                throw IOException(ex)
            }
        }
        oStart = 0
        ofinish = 0
    }


}