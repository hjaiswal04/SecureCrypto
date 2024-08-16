package com.example.cryptotest

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.example.cryptotest.ui.theme.CryptoTestTheme
import com.example.cryptotest.viewModels.Manager
import androidx.lifecycle.viewmodel.compose.viewModel
import java.security.cert.Certificate
import javax.crypto.SecretKey

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            val manager: Manager = viewModel()
            CryptoTestTheme {
                Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
                    GenerateKeys(
                        modifier = Modifier.padding(innerPadding),
                        onGenerateKeysClick = { manager.generateKeys() },
                        privateKey = manager.privateKey.collectAsState().value?.toString() ?: "null",
                        publicKey = manager.publicKey.collectAsState().value?.toString() ?: "null",
                        onGetCertificateClick = { manager.getCertificate() },
                        certificate = manager.certificate.collectAsState().value,
                        aesKey = manager.aesKey.collectAsState().value,
                        aesAlgoString = manager.aesAlgoData.collectAsState().value,
                        changeAesAlgoString = {
                            manager.changeAesAlgoData(it)
                        },
                        encryptData = { key, data ->
                            manager.encryptData(
                                key, data
                            )
                        },
                        decryptData = { key, data ->
                            manager.decryptData(key, data)
                        },
                        aesEncryptedData = manager.aesEncryptedData.collectAsState().value.toString()
                    )
                }
            }
        }
    }
}

@Composable
fun GenerateKeys(
    modifier: Modifier = Modifier,
    onGenerateKeysClick: () -> Unit,
    privateKey: String,
    publicKey: String,
    onGetCertificateClick: () -> Unit,
    certificate: Certificate?,
    aesKey: SecretKey?,
    aesAlgoString: String,
    changeAesAlgoString: (data: String) -> Unit,
    encryptData: (key: SecretKey, data: String) -> Unit,
    decryptData: (key: SecretKey, data: String) -> Unit,
    aesEncryptedData: String
) {

    var certificateButton by rememberSaveable { mutableStateOf("Show Certificate") }
    var decryptString by rememberSaveable { mutableStateOf("") }
    var aesDataButton by rememberSaveable { mutableStateOf("encrypt") }

    Box(
        modifier = modifier
            .fillMaxSize()
            .padding(20.dp)
            .imePadding(),
    ) {
        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            item {
                Button(onClick = {
                    onGenerateKeysClick()
                }) {
                    Text(text = "Generate Keys")
                }
            }

            item {
                if (privateKey != "null") {
                    Text(text = "Private Key: $privateKey")
                }
            }
            item {
                if (publicKey != "null") {
                    Text(text = "Public Key: $publicKey")
                }
            }
            item {
                if (aesKey != null) {
                    Text(text = "AES Key: $aesKey")
                }
            }
            item {
                if (privateKey != "null" && publicKey != "null") {
                    Button(onClick = { 
                        onGetCertificateClick()
                        certificateButton = if (certificateButton == "Show Certificate") {
                            "Hide Certificate"
                        } else {
                            "Show Certificate"
                        }
                    }) {
                        Text(text = certificateButton)
                    }
                }
            }
            item {
                if (certificate != null && certificateButton == "Hide Certificate") {
                    Text(text = "Certificate: $certificate")
                }
            }
            if (aesKey != null) {
                item {
                    Column {
                        OutlinedTextField(
                            value = if (aesDataButton == "encrypt") decryptString else aesEncryptedData,
                            onValueChange = {
                                decryptString = it
                                changeAesAlgoString(it)
                            },
                            label = { Text("Enter String to Encrypt") },
                            modifier = Modifier.fillMaxWidth()
                        )
                        Button(onClick = {
                            if (aesDataButton == "encrypt") {
                                aesDataButton = "decrypt"
                                encryptData(aesKey, aesAlgoString)
                            } else {
                                aesDataButton = "encrypt"
                                decryptData(aesKey, aesAlgoString)
                            }
                        }) {
                            Text(text = aesDataButton)
                        }
                    }
                }
            }
        }
    }
}
