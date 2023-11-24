<?php

include_once('wolfssl.php');

// Call wolfSSL_Init
wolfssl::wolfSSL_Init();

// Create a new SSL context
$ctx = wolfssl::wolfSSL_CTX_new(wolfssl::wolfSSLv23_client_method());

// Set the CA certificate file
$cacertFile = 'wolfssl/certs/ca-cert.pem';
$resultCA = wolfssl::wolfSSL_CTX_load_verify_locations($ctx, $cacertFile, null);

if ($resultCA !== 1) {
    // Failed to set CA certificate
    $this->logger->debug('Failed to set CA certificate.');
    exit;
}

$ssl =  wolfssl::wolfSSL_new($ctx);

// Load client certificate and private key
$certFile = 'wolfssl/certs/client-cert.pem';
$keyFile = 'wolfssl/certs/client-key.pem';

$resultCert =  wolfssl::wolfSSL_use_certificate_buffer($ssl, file_get_contents($certFile), filesize($certFile), 1);
$resultKey =  wolfssl::wolfSSL_use_PrivateKey_buffer($ssl,  file_get_contents($keyFile), filesize($keyFile), 1);

// Check the results
if ($resultCert === 1 && $resultKey === 1) {
    // Certificate and private key set successfully
    echo 'Certificate and private key set successfully.';
} else {
    // Failed to set certificate or private key
    echo 'Failed to set certificate or private key.';
}
echo "\n";
echo "\n";

print_r($resultCert);
echo "\n";
print_r($resultKey);
echo "\n";

print_r($certFile);
echo "\n";

print_r($keyFile);
echo "\n";

print_r($ssl);
echo "\n";
echo "\n";

// Now you can continue with your SSL/TLS operations using $ssl

?>