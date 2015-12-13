Ledger U2F Applet
=================

# Overview

This applet is a Java Card implementation of the [FIDO Alliance U2F standard](https://fidoalliance.org/)

It uses no specific extension and is freely available on [Ledger Unplugged](https://www.ledgerwallet.com/products/6-ledger-unplugged) through [Fidesmo store](http://www.fidesmo.com/apps/4f97a2e9)

# Building 

  - Set the environment variable `JC_HOME` to the folder containg the JavaCard Development Kit 
  - Run `gradle convertJavacard`

# Installing 

Either load the CAP file using your favorite third party software or refer to [Fidesmo Gradle Plugin](https://github.com/fidesmo/gradle-javacard) to use on the Fidesmo platform

 
The following install parameters are expected : 

  - 1 byte flag : provide 01 to pass the current [Fido NFC interoperability tests](https://github.com/google/u2f-ref-code/tree/master/u2f-tests), or 00 
  - 2 bytes length (big endian encoded) : length of the attestation certificate to load, supposed to be using a private key on the P-256 curve 
  - 32 bytes : private key of the attestation certificate 

Before using the applet, the attestation certificate shall be loaded using a proprietary APDU 

| CLA | INS | P1            | P2           | Data                    |
| --- | --- | ------------- | ------------ | ----------------------- |
| F0  | 01  | offset (high) | offset (low) | Certificate data chunk  | 

# License

This application is licensed under [Apache 2.0](http://www.apache.org/licenses/LICENSE-2.0)

# Contact

Please contact hello@ledger.fr for any question

