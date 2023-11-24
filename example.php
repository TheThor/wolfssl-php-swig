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

var_dump($ssl);
echo "\n";
echo "\n";

// Now you can continue with your SSL/TLS operations using $ssl

// Generate Thumbprint
$thumbprint = generateThumbprint($certFile);


// Dummy example for JWT payload
$jwtPayload = [
    "iss" => "your_issuer",
    "sub" => "user123",
    "iat" => time(),
    "exp" => time() + 3600, // Example: Expires in 1 hour
    "aud" => "your_audience",
    "custom_claim" => "custom_value"
];

// Generate JWT Signature
$jwtSignature = generateJwtSignature($ssl, $jwtPayload);

print_r($jwtSignature);
echo "\n";
echo "\n";
function generateThumbprint($certFile): string
{
    $certData = file_get_contents($certFile);
    $hash = hash('sha256', $certData, true);
    return bin2hex($hash);
}

function generateJwtSignature($ssl, $payload) {
    // Convert payload to JSON string
    $payloadJson = json_encode($payload);

    // Allocate space for the signature
    $signature = str_repeat("\0", 256);

    var_dump($payloadJson);
    // Sign the payload using the private key associated with the certificate
    $result = wolfssl::wc_RsaSSL_Sign($payloadJson, strlen($payloadJson), $signature, 256, $ssl, null);

    if ($result !== 0) {
        // Error handling for signature generation failure
        echo "Failed to generate JWT signature.\n";
        exit;
    }

    // Encode the signature as base64
    return base64_encode($signature);
}