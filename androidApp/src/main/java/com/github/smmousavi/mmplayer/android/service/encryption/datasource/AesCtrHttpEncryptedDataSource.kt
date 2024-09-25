package com.github.smmousavi.mmplayer.android.service.encryption.datasource

import android.net.Uri
import androidx.media3.common.C
import androidx.media3.common.PlaybackException
import androidx.media3.common.util.UnstableApi
import androidx.media3.common.util.Util
import androidx.media3.datasource.DataSource
import androidx.media3.datasource.DataSourceException
import androidx.media3.datasource.DataSpec
import androidx.media3.datasource.HttpDataSource
import androidx.media3.datasource.HttpUtil
import androidx.media3.datasource.TransferListener
import com.github.smmousavi.mmplayer.android.service.encryption.HttpConnectionMaker
import com.google.common.net.HttpHeaders
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.math.BigInteger
import java.net.HttpURLConnection
import java.util.Arrays
import java.util.zip.GZIPInputStream
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

@UnstableApi
class AesCtrHttpEncryptedDataSource(
    private val mCipher: Cipher,
    private val mSecretKeySpec: SecretKey,
    private val mIvParameterSpec: IvParameterSpec
) : DataSource {

    private val connectionMaker = HttpConnectionMaker()
    private var mTransferListener: TransferListener? = null


    private var _connection: HttpURLConnection? = null
    private val connection get() = _connection!!

    private var _inputStream: InputStream? = null
    private val inputStream get() = _inputStream!!

    private var _updatedDataSpec: DataSpec? = null
    private val updatedDataSpec get() = _updatedDataSpec!!

    private var uri: Uri? = null

    private var mBytesRemaining: Long = 0
    private var bytesRead: Long = 0
    private var isOpen = false

    override fun open(dataSpec: DataSpec): Long {
        if (isOpen) {
            return mBytesRemaining
        }
        bytesRead = 0
        mBytesRemaining = 0
        uri = dataSpec.uri
        /// set encryption setup for encrypted files.
        _updatedDataSpec = dataSpec

        // make server connection
        val responseCode: Int
        val responseMessage: String
        try {
            _connection = connectionMaker.make(updatedDataSpec)
            responseCode = connection.responseCode
            responseMessage = connection.responseMessage
        } catch (e: IOException) {
            connectionMaker.closeConnection()
            throw HttpDataSource.HttpDataSourceException.createForIOException(
                e, dataSpec, HttpDataSource.HttpDataSourceException.TYPE_OPEN
            )
        }

        // Check for book file links expiration
        if (responseCode == LINK_EXPIRED_RESPONSE_CODE) {
            throw DataSourceException(
                Throwable("RetrieveRequiredException: Book file links are expired."),
                ERROR_FILE_LINKS_EXPIRED
            )
        }

        // Check for a valid response code.
        if (responseCode < 200 || responseCode > 299) {
            val headers = connection.headerFields
            if (responseCode == 416) {
                val documentSize =
                    HttpUtil.getDocumentSize(connection.getHeaderField(HttpHeaders.CONTENT_RANGE))
                if (updatedDataSpec.position == documentSize) {
                    isOpen = true
                    return if (updatedDataSpec.length != C.LENGTH_UNSET.toLong()) {
                        updatedDataSpec.length
                    } else 0
                }
            }
            val errorStream = connection.errorStream
            val errorResponseBody = try {
                if (errorStream != null) Util.toByteArray(errorStream) else Util.EMPTY_BYTE_ARRAY
            } catch (e: IOException) {
                Util.EMPTY_BYTE_ARRAY
            }
            connectionMaker.closeConnection()
            val cause: IOException? =
                if (responseCode == 416)
                    DataSourceException(PlaybackException.ERROR_CODE_IO_READ_POSITION_OUT_OF_RANGE)
                else null
            throw HttpDataSource.InvalidResponseCodeException(
                responseCode, responseMessage, cause, headers, updatedDataSpec, errorResponseBody
            )
        }

        // calculate current position
        val bytesToSkip =
            if (responseCode == 200 && updatedDataSpec.position != 0L) {
                updatedDataSpec.position
            } else 0

        // Determine the length of the data to be read, after skipping.
        val isCompressed = isCompressed(connection)
        if (!isCompressed) {
            mBytesRemaining = if (updatedDataSpec.length != C.LENGTH_UNSET.toLong()) {
                updatedDataSpec.length
            } else {
                val contentLength = HttpUtil.getContentLength(
                    connection.getHeaderField(HttpHeaders.CONTENT_LENGTH),
                    connection.getHeaderField(HttpHeaders.CONTENT_RANGE)
                )
                if (contentLength != C.LENGTH_UNSET.toLong()) contentLength - bytesToSkip else C.LENGTH_UNSET.toLong()
            }
        } else {
            // Gzip is enabled. If the server opts to use gzip then the content length in the response
            // will be that of the compressed data, which isn't what we want. Always use the dataSpec
            // length in this case.
            mBytesRemaining = updatedDataSpec.length
        }

        // handle encrypt inputStream
        var httpStream: InputStream?
        try {
            httpStream = connection.inputStream
            if (isCompressed) {
                httpStream = GZIPInputStream(httpStream)
            }
            setupCipherInputStream(httpStream!!)

        } catch (e: IOException) {
            connectionMaker.closeConnection()
            throw HttpDataSource.HttpDataSourceException(
                e,
                updatedDataSpec,
                PlaybackException.ERROR_CODE_IO_UNSPECIFIED,
                HttpDataSource.HttpDataSourceException.TYPE_OPEN
            )
        }
        mTransferListener?.onTransferStart(this, dataSpec, true)

        isOpen = true
        return mBytesRemaining
    }




    private fun setupCipherInputStream(encryptedStream: InputStream) {
        mSecretKeySpec.let { keySpec ->
            mCipher.let { cipher ->
                val skip = (updatedDataSpec.position % AES_BLOCK_SIZE).toInt()
                val blockOffset = updatedDataSpec.position - skip
                val numberOfBlocks = blockOffset / AES_BLOCK_SIZE
                val ivForOffsetAsBigInteger =
                    BigInteger(1, mIvParameterSpec.iv).add(BigInteger.valueOf(numberOfBlocks))
                val ivForOffsetByteArray = ivForOffsetAsBigInteger.toByteArray()
                val computedIvParameterSpecForOffset: IvParameterSpec =
                    if (ivForOffsetByteArray.size < AES_BLOCK_SIZE) {
                        val resizedIvForOffsetByteArray = ByteArray(AES_BLOCK_SIZE)
                        System.arraycopy(
                            ivForOffsetByteArray,
                            0,
                            resizedIvForOffsetByteArray,
                            AES_BLOCK_SIZE - ivForOffsetByteArray.size,
                            ivForOffsetByteArray.size
                        )
                        IvParameterSpec(resizedIvForOffsetByteArray)
                    } else {
                        IvParameterSpec(
                            ivForOffsetByteArray,
                            ivForOffsetByteArray.size - AES_BLOCK_SIZE,
                            AES_BLOCK_SIZE
                        )
                    }
                cipher.init(Cipher.DECRYPT_MODE, keySpec, computedIvParameterSpecForOffset)
                val skipBuffer = ByteArray(AES_BLOCK_SIZE)
                try {
                    mCipher.update(skipBuffer, 0, skip, skipBuffer)
                } catch (e: Exception) {
                    e.printStackTrace()
                }
                Arrays.fill(skipBuffer, 0.toByte())
                _inputStream =
                    AesCtrTunedCipherInputStream(
                        encryptedStream,
                        mCipher,
                        keySpec
                    )
            }
        }
    }

    private fun isCompressed(connection: HttpURLConnection): Boolean {
        val contentEncoding = connection.getHeaderField("Content-Encoding")
        return "gzip".equals(contentEncoding, ignoreCase = true)
    }

    @Throws(HttpDataSource.HttpDataSourceException::class)
    override fun read(target: ByteArray, offset: Int, readLength: Int): Int {
        if (readLength == 0) {
            return 0
        }
        val bytesToRead = getBytesToRead(readLength)
        val bytesRead: Int? = _inputStream?.read(target, offset, bytesToRead)
        bytesRead?.let { nonNullBytesRead ->
            if (nonNullBytesRead == -1) {
                if (bytesToRead.toLong() == C.RESULT_END_OF_INPUT.toLong()) {
                    throw EOFException()
                }
                return nonNullBytesRead
            }
            if (bytesToRead.toLong() != C.LENGTH_UNSET.toLong() && bytesRead.toLong() < mBytesRemaining) {
                mBytesRemaining -= nonNullBytesRead
            }
            _updatedDataSpec?.let {
                mTransferListener?.onBytesTransferred(
                    this,
                    it,
                    false,
                    bytesRead
                ) //the last Parameter was bytesToRead
            }
        }
        return bytesRead ?: -1

    }

    private fun getBytesToRead(bytesToRead: Int): Int {
        if (mBytesRemaining == C.LENGTH_UNSET.toLong()) {
            return bytesToRead
        } else if (bytesRead.toInt() == C.LENGTH_UNSET) {
            return C.RESULT_END_OF_INPUT
        }
        return Math.min(mBytesRemaining, bytesToRead.toLong()).toInt()
    }

    override fun addTransferListener(transferListener: TransferListener) {
        mTransferListener = transferListener
    }

    override fun getUri() = uri

    @Throws(HttpDataSource.HttpDataSourceException::class)
    override fun close() {
        try {
            if (_inputStream != null) {
                val bytesRemaining =
                    if (mBytesRemaining == C.LENGTH_UNSET.toLong()) C.LENGTH_UNSET.toLong() else mBytesRemaining - bytesRead
                connectionMaker.maybeTerminateInputStream(connection, bytesRemaining)
                try {
                    inputStream.close()
                } catch (e: IOException) {
                    throw HttpDataSource.HttpDataSourceException(
                        e,
                        Util.castNonNull(updatedDataSpec),
                        PlaybackException.ERROR_CODE_IO_UNSPECIFIED,
                        HttpDataSource.HttpDataSourceException.TYPE_CLOSE
                    )
                }
            }
        } finally {
            _inputStream = null
            connectionMaker.closeConnection()
            if (isOpen) {
                mTransferListener?.onTransferEnd(this, updatedDataSpec, true)
                isOpen = false
            }
        }
    }

    companion object {
        private const val LINK_EXPIRED_RESPONSE_CODE = 432
        const val ERROR_FILE_LINKS_EXPIRED = 2023
        const val AES_BLOCK_SIZE = 16

    }
}