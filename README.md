# WolfSSL PHP Extension via SWIG - (still WIP)
Project to create a (SWIG)[https://www.swig.org/Doc1.3/Php.html] that will try to replace OpenSSL in PHP crypt ops. 

### Requirements
- WolfSSL SSL/TLS Library
- SWIG
- PHP 8
- `sudo apt-get install php-dev`
- apt get for dev wolfssl lib can also be installed if you prefer


### Instructions

- Clone git@github.com:wolfSSL/wolfssl.git to this folder
- Install WolfSSL (you need to also run ./configure as per docs)
- Run `swig -php7 wolfssl.i`
- Update the file _**wolfssl_wrap.c**_ as seen in the notes section below
- Compile the generated files with gcc
  - Run the following command but keep in mind the paths are only references
    - `gcc -Wall -shared -fPIC -o wolfssl.so wolfssl_wrap.c -I./wolfssl -I/usr/include/php/xxx/Zend -Ixxxx/tmp/php-8.1.22 -I/usr/include/php/20220829/main -I/usr/include/php/20220829/TSRM -I./wolfssl/wolfssl -I/xxxx/tmp/wolfssl/wolfssl -L/usr/local/lib/ -lwolfssl`
- Add your new extension to PHP
  - php -i | grep extension_dir to figure the folder for example
- 

#### Notes
For some reason I'm yet to figure out, the SWIG command needs to have relative paths (ex.: wolfssl/wolfssl/*) but gcc requires a small change in the wrapper header files (removing the first path) as seen below:
```
### wolfssl.i (with SWIG paths in mind) 
%{
    #include <wolfssl/wolfssl/ssl.h>
    #include <wolfssl/wolfssl/wolfcrypt/rsa.h>
    #include <wolfssl/wolfssl/options.h>
    #include <wolfssl/wolfssl/wolfcrypt/signature.h>
    #include <wolfssl/wolfcrypt/pwdbased.h>
    #include <wolfssl/wolfcrypt/settings.h>
    #include <wolfssl/wolfcrypt/types.h>

    char* wolfSSL_error_string(int err);
    int   wolfSSL_swig_connect(WOLFSSL*, const char* server, int port);
    WC_RNG* GetRng(void);
    RsaKey* GetRsaPrivateKey(const char* file);
    void    FillSignStr(unsigned char*, const char*, int);

%}

### wolfssl_wrap.c (Generated with WRONG paths)

    #include <wolfssl/wolfssl/ssl.h>
    #include <wolfssl/wolfssl/wolfcrypt/rsa.h>
    #include <wolfssl/wolfssl/options.h>
    #include <wolfssl/wolfssl/wolfcrypt/signature.h>
    #include <wolfssl/wolfcrypt/pwdbased.h>
    #include <wolfssl/wolfcrypt/settings.h>
    #include <wolfssl/wolfcrypt/types.h>

### wolfssl_wrap.c (After correcting)

    #include <wolfssl/ssl.h>
    #include <wolfssl/wolfcrypt/rsa.h>
    #include <wolfssl/options.h>
    #include <wolfssl/wolfcrypt/signature.h>
    #include <wolfssl/wolfcrypt/pwdbased.h>
    #include <wolfssl/wolfcrypt/settings.h>
    #include <wolfssl/wolfcrypt/types.h>

```
