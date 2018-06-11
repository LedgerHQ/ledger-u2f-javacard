Ledger U2F Applet
=================

[![Build status](https://travis-ci.org/LedgerHQ/ledger-u2f-javacard.svg?branch=master)](https://travis-ci.org/LedgerHQ/ledger-u2f-javacard) [![Codecov](https://img.shields.io/codecov/c/github/ledgerhq/ledger-u2f-javacard.svg)](https://codecov.io/gh/ledgerhq/ledger-u2f-javacard)

# Overview

This applet is a Java Card implementation of the [FIDO Alliance U2F standard](https://fidoalliance.org/)

It uses no proprietary vendor API and is freely available on [Ledger Unplugged](https://www.ledgerwallet.com/products/6-ledger-unplugged) and for a small fee on other Fidesmo devices through [Fidesmo store](http://www.fidesmo.com/apps/4f97a2e9)

# Building 

  - Set the environment variable `JC_HOME` to the folder containg the [Java Card Development Kit 3.0.2](http://www.oracle.com/technetwork/java/embedded/javacard/downloads/index.html)
  - Run `gradlew convertJavacard`

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

# Testing on Android 

  - Download [Google Authenticator](https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2)
  - Test on http://u2fdemo.appspot.com or https://demo.yubico.com/u2f from Chrome
  - For additional API reference and implementations, check [the reference code](https://github.com/google/u2f-ref-code), the [beta NFC API](https://github.com/google/u2f-ref-code/blob/no-extension/u2f-gae-demo/war/js/u2f-api.js) and [Yubico guide](https://www.yubico.com/applications/fido/) 

# Certification

This implementation has been certified FIDO U2F compliant on December 17, 2015 (U2F100020151217001). See tag [u2f-certif-171215](https://github.com/LedgerHQ/ledger-u2f-javacard/tree/u2f-certif-171215)
  
# License

This application is licensed under [Apache 2.0](http://www.apache.org/licenses/LICENSE-2.0)

# Contact

Please contact hello@ledger.fr for any question

