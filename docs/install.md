# Installing the SecureDNS Library

## Installation
1. Make sure you have `gcc` and `make` downloaded. To check this, run 
`apt info <either-gcc-or-make>` for Ubuntu or `dnf info <either-gcc-or-make>` 
for Fedora or other variants of Debian. If either are not installed, you can 
install them using `sudo apt install <either-gcc-or-make>` for Ubuntu or 
`dnf install <either-gcc-or-make>` for Debian variants.    
2. Download the source code from github (either download the zip or run 
`git clone https://github.com/nathaniel-bennett/secureDNS` from a terminal). 
3. If the source was downloaded, unzip the directory. In either case, navigate 
to the downloaded secureDNS folder. 
4. Run `make`, and then run `sudo make install`. 

This should install the appropriate libraries into /usr/lib/ and the 
`securedns.h` header into /usr/include/. If a different directory than '/' is 
desired, the DESTDIR environment variable can be set to reroute the 
installation to a different path. 

## Using/Linking the Library
Once the libraries are installed there, the `securedns.h` header can be 
included in any project as shown:
```c
#include <securedns.h>
```
When compiling a project that uses the secureDNS library, you need to add the 
following flags: `-lsecuredns -lssl -lcrypto`. The `-lssl` and `-lcrypto` are 
OpenSSL's libraries, so in order to build a project you'll need to make sure 
it's installed as well (`sudo apt install openssl` and 
`sudo apt install libssl-dev` for Ubuntu; replace `apt` with `dnf` for Debian). 
Note that OpenSSL 1.1.1a and newer is required for the library to work.

For a good primer on using the library, head [here](primer.md).
