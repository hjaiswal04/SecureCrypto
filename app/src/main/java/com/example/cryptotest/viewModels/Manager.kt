package com.example.cryptotest.viewModels

import android.util.Log
import androidx.lifecycle.ViewModel
import com.example.cryptotest.Utilities.KeyGeneratorUtility
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.security.PrivateKey
import java.security.PublicKey
import java.security.cert.Certificate
import javax.crypto.SecretKey

class Manager : ViewModel() {

    private val keyGenerator = KeyGeneratorUtility()

    private val _privateKey = MutableStateFlow<PrivateKey?>(null)
    private val _publicKey = MutableStateFlow<PublicKey?>(null)
    private val _certificate = MutableStateFlow<Certificate?>(null)
    private val _aesKey = MutableStateFlow<SecretKey?>(null)
    private val _aesAlgoData = MutableStateFlow<String>("")
    private val _aesEncryptedData = MutableStateFlow<ByteArray>(emptyArray<Byte>().toByteArray())

    val privateKey: StateFlow<PrivateKey?> = _privateKey.asStateFlow()
    val publicKey: StateFlow<PublicKey?> = _publicKey.asStateFlow()
    val certificate: StateFlow<Certificate?> = _certificate.asStateFlow()
    val aesKey: StateFlow<SecretKey?> = _aesKey.asStateFlow()
    val aesAlgoData: StateFlow<String> = _aesAlgoData.asStateFlow()
    val aesEncryptedData: StateFlow<ByteArray> = _aesEncryptedData.asStateFlow()

    // Generate both RSA and AES keys using Bouncy Castle
    fun generateKeys() {
        // Generate RSA KeyPair
        val rsaKeyPair = keyGenerator.generateRSAKeyPair()
        _privateKey.value = rsaKeyPair.private
        _publicKey.value = rsaKeyPair.public

        // Generate AES Key
        _aesKey.value = keyGenerator.generateAESKey()
    }


    fun getCertificate() {

        val rsaKeyPair = keyGenerator.generateRSAKeyPair()
        val cert = keyGenerator.generateSelfSignedCertificate(rsaKeyPair)
        _certificate.value = cert
    }

    // AES Encryption using the generated AES key
    fun encryptData(key: SecretKey, data: String) {
        _aesEncryptedData.value = keyGenerator.aesEncryptData(key, _aesAlgoData.value)
        Log.d("Inside Manager", "Encrypted Data: ${_aesEncryptedData.value.toString()}")
    }

    // AES Decryption
    fun decryptData(key: SecretKey, data: String) {
        _aesAlgoData.value = keyGenerator.aesDecryptData(key, _aesEncryptedData.value)
    }

    // Update the data for AES encryption
    fun changeAesAlgoData(data: String) {
        _aesAlgoData.value = data
    }
}
