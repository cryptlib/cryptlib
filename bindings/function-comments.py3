{

#------------------------------------------------------------------------------#
# ./bindings/function-comments.py3 is a representation of a dictionary
# used to store method comments for Javadoc
# These method comments are inserted into crypt.java by cryptlibConverter.py3
# For more information refer to https://github.com/cryptlib/cryptlib/blob/main/manual.pdf
# Ralf Senderek, March 2026
#------------------------------------------------------------------------------#

'Init' 			:'The cryptInit function is used to initialise cryptlib before use. This function should be called before any other cryptlib function is called.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'End'			:'The cryptEnd function is used to shut down cryptlib after use. This function should be called after you have finished using cryptlib.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'QueryCapability'	:'The cryptQueryCapability function is used to obtain information about the characteristics of a particular encryption algorithm. The information returned covers the algorithm’s key size, data block size, and other algorithm-specific information. <p>\n\
<b>Remarks</b>: Any fields in the CRYPT_QUERY_INFO structure that don’t apply to the algorithm being queried are set to CRYPT_ERROR, null or zero as appropriate. To determine whether an algorithm is available (without returning information on it), set the query information pointer to null.\n\
* @param cryptAlgo The encryption algorithm to be queried.\n\
* @return The address of a CRYPT_QUERY_INFO structure which is filled with the information on the requested algorithm and mode, or null if this information isn’t required.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'CreateContext'		:'The cryptCreateContext function is used to create an encryption context for a given encryption algorithm.\n\
* @return The address of the encryption context to be created.\n\
* @param cryptUser The user who is to own the encryption context or CRYPT_UNUSED for the default, normal user.\n\
* @param cryptAlgo The encryption algorithm to be used in the context.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'DestroyContext'	:'The cryptDestroyContext function is used to destroy an encryption context after use. This erases all keying and security information used by the context and frees up any memory it uses.\n\
* @param cryptContext The encryption context to be destroyed.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'DestroyObject'	:'The cryptDestroyObject function is used to destroy a cryptlib object after use. This erases all security information used by the object, closes any open data sources, and frees up any memory it uses. <p><b>Remarks</b>: This function is a generic form of the specialised functions that destroy/close specific cryptlib object types such as encryption contexts and certificate and keyset objects. In some cases it may not be possible to determine the exact type of an object (for example the keyset access functions may return a key certificate object or only an encryption context depending on the keyset type), cryptDestroyObject can be used to destroy an object of an unknown type.\n\
* @param cryptObject The object to be destroyed.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'GenerateKey'	:'The cryptGenerateKey function is used to generate a new key into an encryption context. <p><b>Remarks</b>: Hash contexts don’t require keys, so an attempt to generate a key into a hash context will return CRYPT_ERROR_NOTAVAIL. cryptGenerateKey will generate a key of a length appropriate for the algorithm being used into an encryption context. If you want to specify the generation of a key of a particular length, you should set the CRYPT_CTXINFO_KEYSIZE attribute before calling this function.\n\
* @param cryptContext The encryption context into which the key is to be generated.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'Encrypt'	:'The cryptEncrypt function is used to encrypt or hash data.<p><b>Remarks</b>: Public-key encryption and signature algorithms have special data formatting requirements that need to be taken into account when this function is called. You shouldn’t use this function with these algorithm types, but instead should use the higher-level functions cryptCreateSignature, cryptCheckSignature, cryptExportKey, and cryptImportKey.\n\
* @param cryptContext The encryption context to use to encrypt or hash the data.\n\
* @param buffer The address of the data to be encrypted or hashed.\n\
* @param length The length in bytes of the data to be encrypted or hashed.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'Decrypt'	:'The cryptDecrypt function is used to decrypt or hash data.<p><b>Remarks</b>: Public-key encryption and signature algorithms have special data formatting requirements that need to be taken into account when this function is called. You shouldn’t use this function with these algorithm types, but instead should use the higher-level functions cryptCreateSignature, cryptCheckSignature, cryptExportKey, and cryptImportKey.\n\
* @param cryptContext The encryption context to use to decrypt or hash the data.\n\
* @param buffer The address of the data to be decrypted or hashed.\n\
* @param length The length in bytes of the data to be decrypted or hashed.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'SetAttribute'	:'The cryptSetAttribute function is used to add boolean or numeric information, command codes, and objects to a cryptlib object.\n\
* @param cryptHandle The object to which to add the value.\n\
* @param attributeType The attribute which is being added.\n\
* @param value The boolean or numeric value, command code, or object which is being added.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'SetAttributeString'	:'The cryptSetAttributeString function is used to add text or binary strings or time values to an object.\n\
* @param cryptHandle The object to which to add the text or binary string or time value.\n\
* @param attributeType The attribute which is being added.\n\
* @param value The address of the data being added.\n\
* @param valueLength The length in bytes of the data being added.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'GetAttribute'	:'The cryptGetAttribute function is used to obtain a boolean or numeric value, status information, or object from a cryptlib object.\n\
* @param cryptHandle The object from which to read the boolean or numeric value, status information, or object.\n\
* @param attributeType The attribute which is being read.\n\
* @return The boolean or numeric value, status information, or object.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'GetAttributeString'	:'The cryptGetAttributeString function is used to obtain text or binary strings or time values from a cryptlib object.\n\
* @param cryptHandle The object from which to read the text or binary string or time value.\n\
* @param attributeType The attribute which is being read.\n\
* @param value The address of a buffer to contain the data. If you set this parameter to null, cryptGetAttributeString will return the length of the data in attributeLength without returning the data itself.\n\
* @return The address of a buffer to contain the data. If you set this parameter to null, cryptGetAttributeString will return the length of the data in attributeLength without returning the data itself.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'DeleteAttribute'	:'The cryptDeleteAttribute function is used to delete an attribute from an object.<p><b>Remarks</b>. Most attributes are always present and can’t be deleted, in general only certificate attributes are deletable.\n\
* @param cryptHandle The object from which to delete the attribute.\n\
* @param attributeType The attribute to delete.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'AddRandom'	:'The cryptAddRandom function is used to add random data to the internal random data pool maintained by cryptlib, or to tell cryptlib to poll the system for random information. The random data pool is used to generate session keys and public/private keys, and by several of the high-level cryptlib functions.\n\
* @param randomData The address of the random data to be added, or null if cryptlib should poll the system for random information.\n\
* @param randomDataLength The length of the random data being added, or CRYPT_RANDOM_SLOWPOLL to perform an in-depth, slow poll or CRYPT_RANDOM_FASTPOLL to perform a less thorough but faster poll for random information.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'QueryObject'	:'The cryptQueryObject function is used to obtain information about an exported key object created with cryptExportKey or a signature object created with cryptCreateSignature. It returns information such as the type and algorithms used by the object.<p><b>Remarks</b>: Any fields in the CRYPT_OBJECT_INFO structure that don’t apply to the object being queried are set to CRYPT_ERROR, null or zero as appropriate.\n\
* @param objectData The address of a buffer that contains the object created by cryptExportKey or\n\
* @param objectDataLength The length in bytes of the object data.\n\
* @return The address of a CRYPT_OBJECT_INFO structure that contains information on the exported key or signature.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'ExportKey'	:'The cryptExportKey function is used to share a session key between two parties by either exporting a session key from a context in a secure manner or by establishing a new shared key. The exported/shared key is placed in a buffer in a portable format that allows it to be imported back into a context using cryptImportKey.\n\
<p> If an existing session key is to be shared, it can be exported using either a public key or key certificate or a conventional encryption key. If a new session key is to be established, it can be done using a Diffie-Hellman encryption context.\n\
<p><b>Remarks</b>: A session key can be shared in one of two ways, either by one party exporting an existing key and the other party importing it, or by both parties agreeing on a key to use. The export/import process requires an existing session key and a public/private or conventional encryption context or key certificate object to export/import it with. The key agreement process requires a Diffie-Hellman context and an empty session key context (with no key loaded) that the new shared session key is generated into.\n\
* @param encryptedKey The address of a buffer to contain the exported key. If you set this parameter to null, cryptExportKey will return the length of the exported key in encryptedKeyLength without actually exporting the key.\n\
* @param encryptedKeyMaxLength The maximum size in bytes of the buffer to contain the exported key.\n\
* @return The address of the exported key length.\n\
* @param exportKey A public-key or conventional encryption context or key certificate object containing the public or conventional key used to export the session key.\n\
* @param sessionKeyContext An encryption context containing the session key to export (if the key is to be shared) or an empty context with no key loaded (if the key is to be established).\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'ExportKeyEx'	:'The cryptExportKeyEx function is used to share a session key between two parties by either exporting a session key from a context in a secure manner or by establishing a new shared key, with extended control over the exported key format. The exported/shared key is placed in a buffer in a portable format that allows it to be imported back into a context using cryptImportKey.<p>\n\
If an existing session key is to be shared, it can be exported using either a public key or key certificate or a conventional encryption key. If a new session key is to be established, it can be done using a Diffie-Hellman encryption context.<p>\n\
<b>Remarks</b> A session key can be shared in one of two ways, either by one party exporting an existing key and the other party importing it, or by both parties agreeing on a key to use. The export/import process requires an existing session key and a public/private or conventional encryption context or key certificate object to export/import it with. The key agreement process requires a Diffie-Hellman context and an empty session key context (with no key loaded) that the new shared session key is generated into.\n\
* @param encryptedKey The address of a buffer to contain the exported key. If you set this parameter to null, cryptExportKeyEx will return the length of the exported key in encryptedKeyLength without actually exporting the key.\n\
* @param encryptedKeyMaxLength The maximum size in bytes of the buffer to contain the exported key.\n\
* @return The address of the exported key length.\n\
* @param formatType The format for the exported key.\n\
* @param exportKey A public-key or conventional encryption context or key certificate object containing the public or conventional key used to export the session key.\n\
* @param sessionKeyContext An encryption context containing the session key to export (if the key is to be shared) or an empty context with no key loaded (if the key is to be established).\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'ImportKey'	:'The cryptImportKey function is used to share a session key between two parties by importing an encrypted session key that was previously exported with cryptExportKey into an encryption context.<p>\n\
If an existing session key being shared, it can be imported using either a private key or a conventional encryption key. If a new session key is being established, it can be done using a Diffie-Hellman encryption context.<p>\n\
<b>Remarks</b>: A session key can be shared in one of two ways, either by one party exporting an existing key and the other party importing it, or by both parties agreeing on a key to use. The export/import process requires an existing session key and a public/private or conventional encryption context or key certificate object to export/import it with. The key agreement process requires a Diffie-Hellman context and an empty session key context (with no key loaded) that the new shared session key is generated into.\n\
* @param encryptedKey The address of a buffer that contains the exported key created by cryptExportKey.\n\
* @param encryptedKeyLength The length in bytes of the encrypted key data.\n\
* @param importKey A public-key or conventional encryption context containing the private or conventional key required to import the session key.\n\
* @param sessionKeyContext The context used to contain the imported session key.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'ImportKeyEx'	:'cryptImportKeyEx takes one extra parameter, a pointer to the imported key, which is required for OpenPGP key import. For all other formats this value is set to NULL, for OpenPGP the imported key parameter is set to CRYPT_UNUSED and the key is returned in the extra parameter:<p>\n\
<code>/* Import a non-PGP format key *\\/ <br>\n\
cryptImportKeyEx( encryptedKey, encryptedKeyLength, importContext, cryptContext, NULL );<br><br>/* Import a PGP-format key *\\/<br>cryptImportKeyEx( encryptedKey, encryptedKeyLength, importContext, CRYPT_UNUSED, &amp;cryptContext );</code><p>\n\
This is required because PGP’s handling of keys differs somewhat from that used with other formats.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'CreateSignature'	:'The cryptCreateSignature function digitally signs a piece of data. The signature is placed in a buffer in a portable format that allows it to be checked using cryptCheckSignature.\n\
* @param signature The address of a buffer to contain the signature. If you set this parameter to null, cryptCreateSignature will return the length of the signature in signatureLength without actually generating the signature.\n\
* @param signatureMaxLength The maximum size in bytes of the buffer to contain the signature data.\n\
* @return The address of the signature length.\n\
* @param signContext A public-key encryption or signature context containing the private key used to sign the data.\n\
* @param hashContext A hash context containing the hash of the data to sign.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'CreateSignatureEx'	:'The cryptCreateSignatureEx function digitally signs a piece of data with extended control over the signature format. The signature is placed in a buffer in a portable format that allows it to be checked using cryptCheckSignatureEx.\n\
* @param signature The address of a buffer to contain the signature. If you set this parameter to null, cryptCreateSignature will return the length of the signature in signatureLength without actually generating the signature.\n\
* @param signatureMaxLength The maximum size in bytes of the buffer to contain the signature data.\n\
* @return The address of the signature length.\n\
* @param formatType The format of the signature to create.\n\
* @param signContext A public-key encryption or signature context containing the private key used to sign the data.\n\
* @param hashContext A hash context containing the hash of the data to sign.\n\
* @param extraData Extra information to include with the signature or CRYPT_UNUSED if the format is the default signature format (which doesn’t use the extra data) or CRYPT_USE_DEFAULT if the signature isn’t the default format and you want to use the default extra information.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'CheckSignature'	:'The cryptCheckSignature function is used to check the digital signature on a piece of data.\n\
* @param signature The address of a buffer that contains the signature.\n\
* @param signatureLength The length in bytes of the signature data.\n\
* @param sigCheckKey A public-key context or key certificate object containing the public key used to verify the signature.\n\
* @param hashContext A hash context containing the hash of the data.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'CheckSignatureEx'	:'The cryptCheckSignatureEx function is used to check the digital signature on a piece of data with extended control over the signature information.\n\
* @param signature The address of a buffer that contains the signature.\n\
* @param signatureLength The length in bytes of the signature data.\n\
* @param sigCheckKey A public-key context or key certificate object containing the public key used to verify the signature.\n\
* @param hashContext A hash context containing the hash of the data.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'KeysetOpen'	:'The cryptKeysetOpen function is used to establish a connection to a key collection or keyset.\n\
* @return The address of the keyset object to be created.\n\
* @param cryptUser The user who is to own the keyset object or CRYPT_UNUSED for the default, normal user.\n\
* @param keysetType The keyset type to be used.\n\
* @param name The name of the keyset.\n\
* @param options Option flags to apply when opening or accessing the keyset.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'KeysetClose'	:'The cryptKeysetClose function is used to destroy a keyset object after use. This closes the connection to the key collection or keyset and frees up any memory it uses.\n\
* @param keyset The keyset object to be destroyed.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'GetPublicKey':'The cryptGetPublicKey function is used to create an encryption context from a public key in a keyset or crypto device. The public key is identified either through the key owner’s name or their email address.\n\
* @param keyset The keyset or device from which to obtain the key.\n\
* @return The address of the context or certificate to be fetched.\n\
* @param keyIDtype The type of the key ID, either CRYPT_KEYID_NAME for the name or key label, or CRYPT_KEYID_EMAIL for the email address.\n\
* @param keyID The key ID of the key to read.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'GetPrivateKey'	:'The cryptGetPrivateKey function is used to create an encryption context from a private key in a keyset or crypto device. The private key is identified either through the key owner’s name or their email address.\n\
* <p><b>Remarks</b>: cryptGetPrivateKey will return CRYPT_ERROR_WRONGKEY if an incorrect password is supplied. This can be used to determine whether a password is necessary by first calling the function with a null password and then retrying the read with a user-supplied password if the first call returns with CRYPT_ERROR_WRONGKEY.\n\
* @param keyset The keyset or device from which to obtain the key.\n\
* @return The address of the context to be fetched.\n\
* @param keyIDtype The type of the key ID, either CRYPT_KEYID_NAME for the name or key label, or CRYPT_KEYID_EMAIL for the email address.\n\
* @param keyID The key ID of the key to read.\n\
* @param password The password required to decrypt the private key, or null if no password is required.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'GetKey'	:'see GetPublicKey'


, 'AddPublicKey'	:'The cryptAddPublicKey function is used to add a user’s public key or certificate to a keyset.<p> <b>Remarks</b>: This function requires a key certificate object rather than an encryption context, since the certificate contains additional identification information which is used when the certificate is written to the keyset.\n\
* @param keyset The keyset object to which to write the key.\n\
* @param certificate The certificate to add to the keyset.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'AddPrivateKey'	:'The cryptAddPrivateKey function is used to add a user’s private key to a keyset. <p><b>Remarks</b>: The use of a password to encrypt the private key is required when storing a private key to a keyset, but not to a crypto device such as a smart card or HSM or TPM, since these provide their own protection for the key data.\n\
* @param keyset The keyset object to which to write the key.\n\
* @param cryptKey The private key to write to the keyset.\n\
* @param password The password used to encrypt the private key.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'DeleteKey'	:'The cryptDeleteKey function is used to delete a key or certificate from a keyset ordevice. The key to delete is identified either through the key owner’s name or theiremail address.\n\
* @param keyset The keyset or device object from which to delete the key.\n\
* @param keyIDtype The type of the key ID, either CRYPT_KEYID_NAME for the name or key label, or CRYPT_KEYID_EMAIL for the email address.\n\
* @param keyID The key ID of the key to delete.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'CreateCert'	:'The cryptCreateCert function is used to create a certificate object that contains a certificate\n\
* @return The address of the certificate object to be created.\n\
* @param cryptUser The user who is to own the certificate object or CRYPT_UNUSED for the default, normal user.\n\
* @param certType The type of certificate item that will be created in the certificate object.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'DestroyCert'	:'The cryptDestroyCert function is used to destroy a certificate object after use. This erases all keying and security information used by the object and frees up any memory it uses.\n\
* @param certificate The certificate object to be destroyed.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'GetCertExtension'	:'The cryptGetCertExtension function is used to obtain a generic blob-type certificate extension from a certificate object or public or private key with an attached certificate.<p>\n\
<b>Remarks</b>: cryptlib directly supports extensions from X.509, PKIX, SET, SigG, and various vendors itself, so you shouldn’t use this function for anything other than unknown, proprietary extensions.\n\
* @param certificate The certificate or public/private key object from which to read the extension.\n\
* @param oid The object identifier value for the extension being queried, specified as a sequence of integers.\n\
* @param extension The address of a buffer to contain the data. If you set this parameter to null, cryptGetCertExtension will return the length of the data in extensionLength without returning the data itself.\n\
* @param extensionMaxLength The maximum size in bytes of the buffer to contain the extension data.\n\
* @return The length in bytes of the extension data.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'AddCertExtension'	:'The cryptAddCertExtension function is used to add a generic blob-type certificate extension to a certificate object.<p><b>Remarks</b>: cryptlib directly supports extensions from X.509, PKIX, SET, SigG, and various vendors itself, so you shouldn’t use this function for anything other than unknown, proprietary extensions.\n\
* @param certificate The certificate object to which to add the extension.\n\
* @param oid The object identifier value for the extension being added, specified as a sequence of integers\n\
* @param criticalFlag The critical flag for the extension being added.\n\
* @param extension The address of the extension data.\n\
* @param extensionLength The length in bytes of the extension data.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'DeleteCertExtension'	:'The cryptDeleteCertExtension function is used to delete a generic blob-type certificate extension from a certificate object.<p>\n\
<b>Remarks</b>: cryptlib directly supports extensions from X.509, PKIX, SET, SigG, and various vendors itself, so you shouldn’t use this function for anything other than unknown, proprietary extensions.\n\
* @param certificate The certificate object from which to delete the extension.\n\
* @param oid The object identifier value for the extension being deleted, specified as a sequence of integers.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'SignCert'	:'The cryptSignCert function is used to digitally sign a public key certificate, CA certificate, certification request, CRL, or other certificate-related item held in a certificate container object.<p>\n\
<b>Remarks</b>: Once a certificate item has been signed, it can no longer be modified or updated using the usual certificate manipulation functions. If you want to add further data to the certificate item, you have to start again with a new certificate object.\n\
* @param certificate The certificate container object that contains the certificate item to sign.\n\
* @param signContext A public-key encryption or signature context containing the private key used to sign the certificate.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'CheckCert'	:'The cryptCheckCert function is used to check the signature on a certificate object, or to verify a certificate object against a CRL or a keyset containing a CRL.\n\
* @param certificate The certificate container object that contains the certificate item to check.\n\
* @param sigCheckKey A public-key context or key certificate object containing the public key used to verify the signature, or alternatively CRYPT_UNUSED if the certificate item is self-signed. If the certificate is to be verified against a CRL, this should be a certificate object or keyset containing the CRL. If the certificate is to be verified online, this should be a session object for the server used to verify the certificate.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'ImportCert'	:'The cryptImportCert function is used to import an encoded certificate, certification request, CRL, or other certificate-related item into a certificate container object.\n\
* @param certObject The address of a buffer that contains the encoded certificate.\n\
* @param certObjectLength The encoded certificate length.\n\
* @param cryptUser The user who is to own the imported object or CRYPT_UNUSED for the default, normal user.\n\
* @return The certificate object to be created using the imported certificate data.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'ExportCert'	:'The cryptExportCert function is used to export an encoded signed public key certificate, certification request, CRL, or other certificate-related item from a certificate container object.<p>\n\
<b>Remarks</b>: The certificate object needs to have all the required fields filled in and must then be signed using cryptSignCert before it can be exported.\n\
* @param certObject The address of a buffer to contain the encoded certificate.\n\
* @param certObjectMaxLength The maximum size in bytes of the buffer to contain the exported certificate.\n\
* @return The address of the exported certificate length.\n\
* @param certFormatType The encoding format for the exported certificate object.\n\
* @param certificate The address of the certificate object to be exported.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'CAAddItem'	:'The cryptCAAddItem function is used to add a certificate object to a certificate store. cryptAddPublicKey is used to add standard certificates, this CA-specific function can be used by CAs to add special items such as certificate requests and PKI user information.\n\
* @param keyset The certificate store to which the item will be added.\n\
* @param certificate The item to add to the certificate store.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'CAGetItem'	:'The cryptCAGetItem function is used to read a certificate object from a certificate store. cryptGetPublicKey is used to read standard certificates, this CA-specific function can be used by CAs to obtain special items such as certificate requests and PKI user information. The item to be fetched is identified either through the key owner’s name or their email address.\n\
* @param keyset The certificate store from which to obtain the item.\n\
* @return The address of the certificate object to be fetched.\n\
* @param certType The item type.\n\
* @param keyIDtype The type of the key ID, either CRYPT_KEYID_NAME for the name or key label, or CRYPT_KEYID_EMAIL for the email address.\n\
* @param keyID The key ID of the item to read.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'CADeleteItem'	:'no function comment avaiilable\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'CACertManagement'	:'The cryptCACertManagement function is used to perform a CA certificate management operation such as a certificate issue, revocation, CRL issue, certificate expiry, or other operation with a certificate store.\n\
* @return The address of the certificate object to be created.\n\
* @param action The certificate management operation to perform.\n\
* @param keyset The certificate store to use to perform the action.\n\
* @param caKey The CA key to use when performing the action, or CRYPT_UNUSED if no key is necessary for this action.\n\
* @param certRequest The certificate request to use when performing the action, or CRYPT_UNUSED if no request is necessary for this action.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'CreateEnvelope'	:'The cryptCreateEnvelope function is used to create an envelope object for encrypting or decrypting, signing or signature checking, compressing or decompressing, or otherwise processing data.\n\
* @return The address of the envelope to be created.\n\
* @param cryptUser The user who is to own the envelope object or CRYPT_UNUSED for the default, normal user.\n\
* @param formatType The data format for the enveloped data.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'DestroyEnvelope'	:'The cryptDestroyEnvelope function is used to destroy an envelope after use. This erases all keying and security information used by the envelope and frees up any memory it uses.\n\
* @param envelope The envelope to be destroyed.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'CreateSession'	:'The cryptCreateSession function is used to create a secure session object for use in securing a communications link or otherwise communicating with a remote server or client.\n\
* @return The address of the session to be created.\n\
* @param cryptUser The user who is to own the session object or CRYPT_UNUSED for the default, normal user.\n\
* @param formatType The type of the secure session.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'DestroySession'	:'The cryptDestroySession function is used to destroy a session object after use. This close the link to the client or server, erases all keying and security information used by the session, and frees up any memory it uses.\n\
* @param session The session to be destroyed.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'PushData'	:'The cryptPushData function is used to add data to an envelope or session object.\n\
* @param envelope The envelope or session object to which to add the data.\n\
* @param buffer The address of the data to add.\n\
* @param length The length of the data to add.\n\
* @return bytesCopied The address of the number of bytes copied into the envelope.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'FlushData'	:'The cryptFlushData function is used to flush data through an envelope or session object, completing processing and (for session objects) sending the data to the remote client or server.\n\
* @param envelope The envelope or session object to flush the data through.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'PopData'	:'The cryptPopData function is used to remove data from an envelope or session object.\n\
* @param envelope The envelope or session object from which to remove the data.\n\
* @param buffer The address of the data to remove.\n\
* @param length The length of the data to remove.\n\
* @return bytesCopied The address of the number of bytes copied from the envelope.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'DeviceOpen'	:'The cryptDeviceOpen function is used to establish a connection to a crypto device such as a crypto hardware accelerator or a PCMCIA card or smart card.\n\
* @param cryptUser The address of the device object to be created.\n\
* @param deviceType The device type to be used.\n\
* @param name The user who is to own the device object or CRYPT_UNUSED for the default, normal user.\n\
* @return The address of the device object to be created.\n\
* @throws CryptException This exception returns an integer status code and a string error message '

, 'DeviceClose'	:'The cryptDeviceClose function is used to destroy a device object after use. This closes the connection to the device and frees up any memory it uses.\n\
* @param device The device object to be destroyed.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'DeviceQueryCapability'	:'The cryptDeviceQueryCapability function is used to obtain information about the characteristics of a particular encryption algorithm provided by an encryption device.  The information returned covers the algorithm’s key size, data block size, and other algorithm-specific information.<p>\n\
<b>Remarks</b>: Any fields in the CRYPT_QUERY_INFO structure that don’t apply to the algorithm being queried are set to CRYPT_ERROR, null or zero as appropriate. To determine whether an algorithm is available (without returning information on them), set the query information pointer to null.\n\
* @param device The encryption device to be queried.\n\
* @param cryptAlgo The encryption algorithm to be queried.\n\
* @return The address of a CRYPT_QUERY_INFO structure which is filled with the information on the requested algorithm and mode, or null if this information isn’t required.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'DeviceCreateContext'	:'The cryptDeviceCreateContext function is used to create an encryption context for a given encryption algorithm via an encryption device.\n\
* @param device The device object used to create the encryption context.\n\
* @param cryptAlgo The encryption algorithm to be used in the context.\n\
* @return The address of the encryption context to be created.\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'Login'	:'Log on / create a user object\n\
* @param name the user’s ID\n\
* @param password secret login password\n\
* @return The address of the user login\n\
* @throws CryptException This exception returns an integer status code and a string error message '


, 'Logout'	:'Log out / destroy a user object\n\
* @param user The address for the user as generated by Login()\n\
* @throws CryptException This exception returns an integer status code and a string error message '

}
