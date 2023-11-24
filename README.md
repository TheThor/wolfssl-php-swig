# wolfssl-php-swig
Project to create a swig that will try to replace Open SSL in PHP crypt ops. 

### Requirements
- WolfSSL SSL/TLS Library
- SWIG
- PHP 8

### Instructions

- Clone git@github.com:wolfSSL/wolfssl.git to this folder
- Install WolfSSL
- Run `swig -php7 wolfssl.i`
- Compile the generated files with gcc
- Add your new extension to PHP