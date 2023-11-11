package com.github.smmousavi.mmplayer.android.service.encryption.datasource

import android.annotation.SuppressLint
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
import com.google.common.net.HttpHeaders
import com.github.smmousavi.mmplayer.android.service.encryption.HttpConnectionMaker
import com.github.smmousavi.mmplayer.android.service.encryption.inputestream.TunedCipherInputStream
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.util.zip.GZIPInputStream
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

@UnstableApi class HttpEncryptedDataSource(private val key: ByteArray?) : DataSource {

    private val connectionMaker = HttpConnectionMaker()
    private var keySpec: SecretKeySpec? = null
    private var cipher: Cipher? = null

    private var _connection: HttpURLConnection? = null
    private val connection get() = _connection!!

    private var _inputStream: InputStream? = null
    private val inputStream get() = _inputStream!!

    private var _updatedDataSpec: DataSpec? = null
    private val updatedDataSpec get() = _updatedDataSpec!!

    private var uri: Uri? = null

    private var bytesToRead: Long = 0
    private var bytesRead: Long = 0
    private var isOpen = false

    override fun open(dataSpec: DataSpec): Long {
        bytesRead = 0
        bytesToRead = 0
        uri = dataSpec.uri

        /// set encryption setup for encrypted files.
        _updatedDataSpec = if (key != null) {
            initCipher()
            modifyBlockPosition(dataSpec, dataSpec.position)
        } else {
            dataSpec
        }

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
            bytesToRead = if (updatedDataSpec.length != C.LENGTH_UNSET.toLong()) {
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
            bytesToRead = updatedDataSpec.length
        }

        // handle encrypt inputStream
        var httpStream: InputStream?
        try {
            httpStream = connection.inputStream
            if (isCompressed) {
                httpStream = GZIPInputStream(httpStream)
            }
            if (key != null) {
                setupCipherInputStream(httpStream!!)
            } else {
                _inputStream = httpStream
            }
        } catch (e: IOException) {
            connectionMaker.closeConnection()
            throw HttpDataSource.HttpDataSourceException(
                e,
                updatedDataSpec,
                PlaybackException.ERROR_CODE_IO_UNSPECIFIED,
                HttpDataSource.HttpDataSourceException.TYPE_OPEN
            )
        }

        isOpen = true
        return bytesToRead
    }

    // check if the new position divided by cipher.blockSize
    // results in zero. If not truncate the remaining.
    private fun modifyBlockPosition(dataSpec: DataSpec, position: Long): DataSpec {
        var skipBlockPosition = position
        cipher?.let {
            val skipOverFlow = position % it.blockSize
            skipBlockPosition = position - skipOverFlow
            if (skipBlockPosition < 0) skipBlockPosition = 0
        }
        return dataSpec
            .buildUpon()
            .setPosition(skipBlockPosition)
            .build()
    }

    @SuppressLint("GetInstance")
    private fun initCipher() {
        keySpec = SecretKeySpec(
            key,
            "AES"
        )
        cipher = Cipher.getInstance(
            "AES/ECB/PCSK5-Padding"
        )
    }

    private fun setupCipherInputStream(encryptedStream: InputStream) {
        keySpec?.let { keySpec ->
            cipher?.let { cipher ->
                cipher.init(Cipher.DECRYPT_MODE, keySpec)
                _inputStream = TunedCipherInputStream(encryptedStream, cipher, keySpec)
            }
        }
    }

    private fun isCompressed(connection: HttpURLConnection): Boolean {
        val contentEncoding = connection.getHeaderField("Content-Encoding")
        return "gzip".equals(contentEncoding, ignoreCase = true)
    }

    @Throws(HttpDataSource.HttpDataSourceException::class)
    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        try {
            var readLength = length
            if (readLength == 0) {
                return 0
            }
            if (bytesToRead != C.LENGTH_UNSET.toLong()) {
                val bytesRemaining = bytesToRead - bytesRead
                if (bytesRemaining == 0L) {
                    return C.RESULT_END_OF_INPUT
                }
                readLength = readLength.toLong().coerceAtMost(bytesRemaining).toInt()
            }

            val read =
                Util.castNonNull<InputStream>(inputStream).read(buffer, offset, readLength)
            if (read == -1) {
                return C.RESULT_END_OF_INPUT
            }

            bytesRead += read.toLong()
            return read
        } catch (e: IOException) {
            throw HttpDataSource.HttpDataSourceException.createForIOException(
                e, Util.castNonNull(updatedDataSpec), HttpDataSource.HttpDataSourceException.TYPE_READ
            )
        }
    }

    override fun addTransferListener(transferListener: TransferListener) {}

    override fun getUri() = uri

    @Throws(HttpDataSource.HttpDataSourceException::class)
    override fun close() {
        try {
            if (_inputStream != null) {
                val bytesRemaining =
                    if (bytesToRead == C.LENGTH_UNSET.toLong()) C.LENGTH_UNSET.toLong() else bytesToRead - bytesRead
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
                isOpen = false
            }
        }
    }

    companion object {
        private const val LINK_EXPIRED_RESPONSE_CODE = 432
        const val ERROR_FILE_LINKS_EXPIRED = 2023
    }
}