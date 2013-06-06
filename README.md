AesManagedHelper
================

C# Encryption / Decryption wrapper using AesManaged. 

Encrypts a utf8 string to give a base64 encoded string of format `[IV]-[DATA]` where `[IV]` is randomly generated. 

Decrypts a base64 encoded string of format `[IV]-[DATA]` to give a utf8 string. 

You could use [random.org](http://www.random.org/strings/) to generate passphrase.

### Example

    var passphrase = "some secret stuff that you get from saturn :)";
    var aes = new AesManagedHelper(passphrase);

    // Encrypt
    var encrypted = aes.EncryptString("encrypt this");
    // encrypted: "KXR05UCx8BYQNBmw0FNeH/bDwdXaotbg/YvP50qoWIk="
    
    // Decrypt 
    var decrypted = aes.DecryptString(encrypted);
    // decrypted: "encrypt this"
    

### Note

Url-encode the encrypted text before using in urls.

    var encrypted = WebUtility.UrlEncode(aes.EncryptString("encrypt this"));

