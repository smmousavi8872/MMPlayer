package com.github.smmousavi.mmplayer.android.service.encryption.datasource

import android.annotation.SuppressLint
import android.net.Uri
import androidx.media3.common.C
import androidx.media3.common.util.UnstableApi
import androidx.media3.datasource.DataSource
import androidx.media3.datasource.DataSpec
import androidx.media3.datasource.TransferListener
import com.github.smmousavi.mmplayer.android.service.encryption.inputestream.FileCipherInputStream
import java.io.EOFException
import java.io.File
import java.io.FileInputStream
import java.io.IOException
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

@UnstableApi
class FileEncryptedDataSource(private val key: ByteArray) : DataSource {

    private var encryptedFileStream: FileInputStream? = null
    private var cipherInputStream: FileCipherInputStream? = null
    private var bytesToRead: Long = 0
    private var bytesRead: Int = 0
    private var isOpen = false
    private var dataSpec: DataSpec? = null

    @Throws(IOException::class)
    override fun open(dataSpec: DataSpec): Long {
        this.dataSpec = dataSpec
        if (isOpen) return bytesToRead
        try {
            setupCipherInputStream()
            cipherInputStream?.forceSkip(dataSpec.position)

            if (dataSpec.length != C.LENGTH_UNSET.toLong()) {
                bytesToRead = dataSpec.length
                return bytesToRead
            }
            if (bytesToRead == Int.MAX_VALUE.toLong()) {
                bytesToRead = C.LENGTH_UNSET.toLong()
                return bytesToRead
            }
            bytesToRead = cipherInputStream!!.available().toLong()
        } catch (e: IOException) {
            throw IOException(e)
        }
        isOpen = true
        return bytesToRead
    }

    @SuppressLint("GetInstance")
    private fun setupCipherInputStream() {
        val path = uri?.path ?: throw RuntimeException("Path can Not be empty!")
        encryptedFileStream = File(path).inputStream()
        val keySpec = SecretKeySpec(
            key,
            "AES"
        )
        val cipher = Cipher.getInstance(
            "AES/ECB/PCSK5-Padding"
        )
        cipherInputStream = FileCipherInputStream(
            encryptedFileStream!!,
            cipher,
            keySpec
        )
    }

    @Throws(IOException::class)
    override fun read(buffer: ByteArray, offset: Int, readLength: Int): Int {
        if (bytesToRead == 0L) {
            return C.RESULT_END_OF_INPUT
        }

        bytesRead = try {
            cipherInputStream!!.read(buffer, offset, readLength)
        } catch (e: IOException) {
            throw IOException(e)
        }

        if (bytesRead < 0) {
            if (bytesToRead != C.LENGTH_UNSET.toLong())
                throw IOException(EOFException())
            return C.RESULT_END_OF_INPUT
        }

        if (bytesToRead != C.LENGTH_UNSET.toLong())
            bytesToRead -= bytesRead
        return bytesRead
    }

    override fun addTransferListener(transferListener: TransferListener) {}

    override fun getUri(): Uri? = dataSpec?.uri

    @Throws(IOException::class)
    override fun close() {
        try {
            encryptedFileStream?.close()
            cipherInputStream?.close()
        } catch (e: IOException) {
            throw IOException(e)
        } finally {
            if (isOpen) {
                isOpen = false
            }
        }
    }
}