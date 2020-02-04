# Kajool-FIDO2

For a long time until nowadays, users have used username and
password combination as the main online authentication mechanism.
However, this single factor authentication mechanism has several
security drawbacks such as leakage, reuse, poor entropy and hard to
remember, in addition to very common attacks which allow stealing
this sensitive information, for instance, brute force, phishing and man
in the middle attacks. Recently, the FIDO2 authentication protocol
was published as a standard. FIDO2 uses signatures to provide proof
of having a secret without revealing it. Besides, It can provide a
passwordless experience which will help to improve authentication
usability. Increasing security and usability will help to reduce the
risks associated with the authentication process. However, FIDO2 is a
very recent standard, and as every standard, it takes time to be
adopted, and it requires support from many corners. Therefore, this
project is trying to contribute to the FIDO2 adoption by developing
an open-source FIDO2 authenticator project using a promising
nRF52840 SoC. Although the result of this project is a small
contribution of a basic implementation of FIDO2, it sets the path to
create a robust open-source FIDO2 authenticator.

# Documentation
For now, visit the docs subfolder to read the dissertation that helped to create this project.

# To Do
- Rewrite README.
- Add explanation about Kajool mayan word.
- Add instructions to compile the project. This istructions are inside doc subfolder, however, it must be rewritten to fit actual subtree folder in this project.
- Add aknowledges from code used for this project.
- Establish an open-source license for this project.
- Implement ClientPIN, Reset and nextAssertion CTAP2 methods.
- Test implementation on NRF52840 DK board

## Contributing
All contributions are welcome.
