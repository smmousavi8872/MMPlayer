package com.github.smmousavi.mmplayer.android.service.encryption

import androidx.annotation.VisibleForTesting
import androidx.media3.common.C
import androidx.media3.common.PlaybackException
import androidx.media3.common.util.Assertions
import androidx.media3.common.util.UnstableApi
import androidx.media3.common.util.Util
import androidx.media3.datasource.DataSpec
import androidx.media3.datasource.HttpDataSource
import com.google.common.net.HttpHeaders
import java.io.IOException
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.MalformedURLException
import java.net.NoRouteToHostException
import java.net.URL

@UnstableApi class HttpConnectionMaker {

    private var defaultRequestProperties: HttpDataSource.RequestProperties? = null
    private var requestProperties = HttpDataSource.RequestProperties()
    private var readTimeoutMillis = DEFAULT_CONNECT_TIMEOUT_MILLIS
    private var connectTimeoutMillis = DEFAULT_READ_TIMEOUT_MILLIS
    private var allowCrossProtocolRedirects = false
    private var keepPostFor302Redirects = false
    private var connection: HttpURLConnection? = null
    private var userAgent: String? = null

    @Throws(IOException::class)
    fun make(dataSpec: DataSpec): HttpURLConnection {
        var url = URL(dataSpec.uri.toString())
        var httpMethod: @DataSpec.HttpMethod Int = dataSpec.httpMethod
        var httpBody = dataSpec.httpBody
        val position = dataSpec.position
        val length = dataSpec.length
        val allowGzip = dataSpec.isFlagSet(DataSpec.FLAG_ALLOW_GZIP)
        if (!allowCrossProtocolRedirects && !keepPostFor302Redirects) {
            // HttpURLConnection disallows cross-protocol redirects, but otherwise performs redirection
            // automatically. This is the behavior we want, so use it.
            return make(
                url,
                httpMethod,
                httpBody,
                position,
                length,
                allowGzip,  /* followRedirects= */
                true,
                dataSpec.httpRequestHeaders
            )
        }

        // We need to handle redirects ourselves to allow cross-protocol redirects or to keep the POST
        // request method for 302.
        var redirectCount = 0
        while (redirectCount++ <= MAX_REDIRECTS) {
            connection = make(
                url,
                httpMethod,
                httpBody,
                position,
                length,
                allowGzip,  /* followRedirects= */
                false,
                dataSpec.httpRequestHeaders
            )
            val responseCode = connection?.responseCode
            val location = connection?.getHeaderField("Location")
            if ((httpMethod == DataSpec.HTTP_METHOD_GET || httpMethod == DataSpec.HTTP_METHOD_HEAD)
                && (responseCode == HttpURLConnection.HTTP_MULT_CHOICE
                        || responseCode == HttpURLConnection.HTTP_MOVED_PERM
                        || responseCode == HttpURLConnection.HTTP_MOVED_TEMP
                        || responseCode == HttpURLConnection.HTTP_SEE_OTHER
                        || responseCode == HTTP_STATUS_TEMPORARY_REDIRECT
                        || responseCode == HTTP_STATUS_PERMANENT_REDIRECT)
            ) {
                connection?.disconnect()
                url = handleRedirect(url, location, dataSpec)
            } else if (httpMethod == DataSpec.HTTP_METHOD_POST
                && (responseCode == HttpURLConnection.HTTP_MULT_CHOICE
                        || responseCode == HttpURLConnection.HTTP_MOVED_PERM
                        || responseCode == HttpURLConnection.HTTP_MOVED_TEMP
                        || responseCode == HttpURLConnection.HTTP_SEE_OTHER)
            ) {
                connection?.disconnect()
                val shouldKeepPost =
                    keepPostFor302Redirects && responseCode == HttpURLConnection.HTTP_MOVED_TEMP
                if (!shouldKeepPost) {
                    // POST request follows the redirect and is transformed into a GET request.
                    httpMethod = DataSpec.HTTP_METHOD_GET
                    httpBody = null
                }
                url = handleRedirect(url, location, dataSpec)
            } else {
                return connection!!
            }
        }
        throw HttpDataSource.HttpDataSourceException(
            NoRouteToHostException("Too many redirects: $redirectCount"),
            dataSpec,
            PlaybackException.ERROR_CODE_IO_NETWORK_CONNECTION_FAILED,
            HttpDataSource.HttpDataSourceException.TYPE_OPEN
        )
    }

    @Throws(IOException::class)
    private fun make(
        url: URL,
        httpMethod: @DataSpec.HttpMethod Int,
        httpBody: ByteArray?,
        position: Long,
        length: Long,
        allowGzip: Boolean,
        followRedirects: Boolean,
        requestParameters: Map<String, String>,
    ): HttpURLConnection {
        val connection = openConnection(url)
        connection.connectTimeout = connectTimeoutMillis
        connection.readTimeout = readTimeoutMillis
        val requestHeaders: MutableMap<String, String> = HashMap()
        if (defaultRequestProperties != null) {
            requestHeaders.putAll(defaultRequestProperties!!.snapshot)
        }
        requestHeaders.putAll(requestProperties.snapshot)
        requestHeaders.putAll(requestParameters)
        for ((key, value) in requestHeaders) {
            connection.setRequestProperty(key, value)
        }
        //header range
        val rangeHeader = buildRangeRequestHeader(position, length)
        if (rangeHeader != null) {
            connection.setRequestProperty(HttpHeaders.RANGE, rangeHeader)
        }
        if (userAgent != null) {
            connection.setRequestProperty(HttpHeaders.USER_AGENT, userAgent)
        }
        connection.setRequestProperty(
            HttpHeaders.ACCEPT_ENCODING,
            if (allowGzip) "gzip" else "identity"
        )
        connection.instanceFollowRedirects = followRedirects
        connection.doOutput = httpBody != null
        connection.requestMethod = DataSpec.getStringForHttpMethod(httpMethod)
        if (httpBody != null) {
            connection.setFixedLengthStreamingMode(httpBody.size)
            connection.connect()
            val os = connection.outputStream
            os.write(httpBody)
            os.close()
        } else {
            connection.connect()
        }
        return connection
    }

    private fun buildRangeRequestHeader(position: Long, length: Long): String? {
        if (position == 0L && length == C.LENGTH_UNSET.toLong()) return null

        val rangeValue = StringBuilder()
        rangeValue.append("bytes=")
        rangeValue.append(position)
        rangeValue.append("-")

        if (length != C.LENGTH_UNSET.toLong()) {
            rangeValue.append(position + length - 1)
        }
        return rangeValue.toString()
    }

    @VisibleForTesting
    @Throws(IOException::class)
    fun openConnection(url: URL): HttpURLConnection {
        return url.openConnection() as HttpURLConnection
    }

    @Throws(HttpDataSource.HttpDataSourceException::class)
    private fun handleRedirect(originalUrl: URL, location: String?, dataSpec: DataSpec): URL {
        if (location == null) {
            throw HttpDataSource.HttpDataSourceException(
                "Null location redirect",
                dataSpec,
                PlaybackException.ERROR_CODE_IO_NETWORK_CONNECTION_FAILED,
                HttpDataSource.HttpDataSourceException.TYPE_OPEN
            )
        }
        // Form the new url.
        val url: URL = try {
            URL(originalUrl, location)
        } catch (e: MalformedURLException) {
            throw HttpDataSource.HttpDataSourceException(
                e,
                dataSpec,
                PlaybackException.ERROR_CODE_IO_NETWORK_CONNECTION_FAILED,
                HttpDataSource.HttpDataSourceException.TYPE_OPEN
            )
        }

        // Check that the protocol of the new url is supported.
        val protocol = url.protocol
        if ("https" != protocol && "http" != protocol) {
            throw HttpDataSource.HttpDataSourceException(
                "Unsupported protocol redirect: $protocol",
                dataSpec,
                PlaybackException.ERROR_CODE_IO_NETWORK_CONNECTION_FAILED,
                HttpDataSource.HttpDataSourceException.TYPE_OPEN
            )
        }
        if (!allowCrossProtocolRedirects && protocol != originalUrl.protocol) {
            throw HttpDataSource.HttpDataSourceException(
                "Disallowed cross-protocol redirect ("
                        + originalUrl.protocol
                        + " to "
                        + protocol
                        + ")",
                dataSpec,
                PlaybackException.ERROR_CODE_IO_NETWORK_CONNECTION_FAILED,
                HttpDataSource.HttpDataSourceException.TYPE_OPEN
            )
        }
        return url
    }

    fun closeConnection() {
        if (connection != null) {
            try {
                connection?.disconnect()
            } catch (e: Exception) {
                e.printStackTrace()
            }
            connection = null
        }
    }

    fun maybeTerminateInputStream(connection: HttpURLConnection?, bytesRemaining: Long) {
        if (connection == null || Util.SDK_INT < 19 || Util.SDK_INT > 20) {
            return
        }
        try {
            val inputStream = connection.inputStream
            if (bytesRemaining == C.LENGTH_UNSET.toLong()) {
                // If the input stream has already ended, do nothing. The socket may be re-used.
                if (inputStream.read() == -1) {
                    return
                }
            } else if (bytesRemaining <= MAX_BYTES_TO_DRAIN) {
                // There isn't much data left. Prefer to allow it to drain, which may allow the socket to be
                // re-used.
                return
            }
            val className = inputStream.javaClass.name
            if ("com.android.okhttp.internal.http.HttpTransport\$ChunkedInputStream" == className
                || ("com.android.okhttp.internal.http.HttpTransport\$FixedLengthInputStream"
                        == className)
            ) {
                val superclass: Class<in InputStream>? = inputStream.javaClass.superclass
                val unexpectedEndOfInput =
                    Assertions.checkNotNull(superclass).getDeclaredMethod("unexpectedEndOfInput")
                unexpectedEndOfInput.isAccessible = true
                unexpectedEndOfInput.invoke(inputStream)
            }
        } catch (e: Exception) {
            // If an IOException then the connection didn't ever have an input stream, or it was closed
            // already. If another type of exception then something went wrong, most likely the device
            // isn't using okhttp.
            e.printStackTrace()
        }
    }

    companion object {
        private const val DEFAULT_CONNECT_TIMEOUT_MILLIS = 8 * 1000

        /** The default read timeout, in milliseconds.  */
        private const val DEFAULT_READ_TIMEOUT_MILLIS = 8 * 1000

        private const val MAX_REDIRECTS = 20 // Same limit as okhttp.

        private const val HTTP_STATUS_TEMPORARY_REDIRECT = 307
        private const val HTTP_STATUS_PERMANENT_REDIRECT = 308

        private const val MAX_BYTES_TO_DRAIN: Long = 2048
    }
}