package com.github.smmousavi.mmplayer.android.service.encryption.util

import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import javax.crypto.Cipher
import javax.crypto.NoSuchPaddingException
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

object CipherManagement {

    private fun getCipherForCtrHttpDataSource() {

           val mSecretKeySpec =
                SecretKeySpec("key".toByteArray(), "AES")
            val mIvParameterSpec = IvParameterSpec("Iv".toByteArray())
            try {
                var mCipher = Cipher.getInstance("AES/CTR/NoPadding")
                mCipher.init(Cipher.DECRYPT_MODE, mSecretKeySpec, mIvParameterSpec)
            } catch (e: NoSuchAlgorithmException) {
                e.printStackTrace()
            } catch (e: InvalidKeyException) {
                e.printStackTrace()

            } catch (e: InvalidAlgorithmParameterException) {
                e.printStackTrace()
            } catch (e: NoSuchPaddingException) {
                e.printStackTrace()
            }
        }


}