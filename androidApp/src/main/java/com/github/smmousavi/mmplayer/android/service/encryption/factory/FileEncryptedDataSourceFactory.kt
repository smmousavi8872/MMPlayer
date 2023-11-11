package com.github.smmousavi.mmplayer.android.service.encryption.factory

import androidx.media3.common.util.UnstableApi
import androidx.media3.datasource.DataSource
import com.github.smmousavi.mmplayer.android.service.encryption.datasource.FileEncryptedDataSource

@UnstableApi
class FileEncryptedDataSourceFactory(private val key: ByteArray) : DataSource.Factory {

    override fun createDataSource(): DataSource = FileEncryptedDataSource(key)
}