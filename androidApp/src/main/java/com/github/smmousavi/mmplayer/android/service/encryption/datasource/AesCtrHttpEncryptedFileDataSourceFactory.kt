package com.github.smmousavi.mmplayer.android.service.encryption.datasource

import androidx.annotation.OptIn
import androidx.media3.common.util.UnstableApi
import androidx.media3.datasource.DataSource
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

@OptIn(UnstableApi::class)
class AesCtrHttpEncryptedFileDataSourceFactory(
    private val mCipher: Cipher,
    private val mSecretKeySpec: SecretKey,
    private val mIvParameterSpec: IvParameterSpec
) : DataSource.Factory {
    override fun createDataSource(): DataSource {
        return AesCtrHttpEncryptedDataSource(mCipher, mSecretKeySpec, mIvParameterSpec)
    }
}
