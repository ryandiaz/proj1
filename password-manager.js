"use strict";

// COMMENTS BY RYAN BEGIN //R

/********* External Imports ********/

var lib = require("./lib");

var KDF = lib.KDF,
    HMAC = lib.HMAC,
    SHA256 = lib.SHA256,
    setup_cipher = lib.setup_cipher,
    enc_gcm = lib.enc_gcm,
    dec_gcm = lib.dec_gcm,
    bitarray_slice = lib.bitarray_slice,
    bitarray_to_string = lib.bitarray_to_string,
    string_to_bitarray = lib.string_to_bitarray,
    bitarray_to_hex = lib.bitarray_to_hex,
    hex_to_bitarray = lib.hex_to_bitarray,
    bitarray_to_base64 = lib.bitarray_to_base64,
    base64_to_bitarray = lib.base64_to_bitarray,
    byte_array_to_hex = lib.byte_array_to_hex,
    hex_to_byte_array = lib.hex_to_byte_array,
    string_to_padded_byte_array = lib.string_to_padded_byte_array,
    string_to_padded_bitarray = lib.string_to_padded_bitarray,
    string_from_padded_byte_array = lib.string_from_padded_byte_array,
    string_from_padded_bitarray = lib.string_from_padded_bitarray,
    random_bitarray = lib.random_bitarray,
    bitarray_equal = lib.bitarray_equal,
    bitarray_len = lib.bitarray_len,
    bitarray_concat = lib.bitarray_concat,
    dict_num_keys = lib.dict_num_keys;


/********* Implementation ********/


var keychain = function() {
  // Class-private instance variables.
  var priv = {
    secrets: { /* secret data here */ },
    data: { /* Non-secret data here */ }
  };

  // Maximum length of each record in bytes
  var MAX_PW_LEN_BYTES = 64;
  // Flag to indicate whether password manager is "ready" or not
  var ready = false;
  // Public salt
  var salt = null;
  var keychain = {};

  /** 
    * Creates an empty keychain with the given password. Once init is called,
    * the password manager should be in a ready state.
    * O(1)
    * Arguments:
    *   password: string
    * Return Type: void
    */
  keychain.init = function(password) {
    var init_salt = random_bitarray(256);
    var init_key = KDF(password, init_salt);
    // set HMAC key using KDF function
    priv.secrets.key_HMAC = init_key;
    // use first 128 bits of output of HMAC on the HMAC key to get pseudo-random gcm key
    priv.secrets.key_gcm = bitarray_slice(HMAC(init_key, password), 0, 128);
    // initialize counter, set salt, and set ready flag to true
    priv.secrets.counter = 0;
    salt = init_salt;
    ready = true;
  };

  /**
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the save function). The trusted_data_check
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (e.g., the result of a 
    * call to the save function). Returns true if the data is successfully loaded
    * and the provided password is correct. Returns false otherwise.
    * O(n)
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trusted_data_check: string
    * Return Type: boolean
    */
  keychain.load = function(password, repr, trusted_data_check) {
    // parse repr and unwrap its contents: the encrypted keychain and the salt
    var obj = JSON.parse(repr);
    var encrypted_keychain = obj.keychain_str;
    salt = obj.salt;
    // use the provided password and salt to create a load_key that should
    // match the HMAC key from the previous dump if password is correct
    var load_key = KDF(password, salt);
    // then generate the gcm key from the previous dump (if password correct)
    var encryption_key = bitarray_slice(HMAC(load_key, password), 0, 128);
    // decrypt the encrypted keychain using the gcm key based on the input password.
    // If this key is different from the one used for encryption, the wrong password
    // was input and thus we return false.
    var keychain_str;
    try {
      keychain_str = dec_gcm(setup_cipher(encryption_key), encrypted_keychain);
    }
    catch(err) {
      return false
    }
    // parse the decrypted keychain string to generate the object
    var keychain_obj = JSON.parse(bitarray_to_string(keychain_str));
    // compare the HMAC'ed counter to the HMAC output of the HMAC of the input counter
    // using the key (generated from the input password). If they do not match then we
    // have evidence of tampering and we throw the appropriate error message
    if (!bitarray_equal(keychain_obj.counter_hmac, HMAC(load_key, string_to_bitarray(trusted_data_check+'')))) throw "integrity check fails!";
    // set our keychain to the objects keychain
    keychain = keychain_obj.keychain;
    // decrypt the encrypted password check (resulting in the original gcm key) and compare
    // it to the gcm key generated using the given password (redundant check). If dec_gcm
    // throws an exception when it attempts to decrypt using a different key than was used 
    // originally to encrypt, then this step is necessary. Can't hurt though.
    var decrypted;
    try {
      decrypted = dec_gcm(setup_cipher(encryption_key), keychain_obj.pass_check);
      if (!bitarray_equal(encryption_key,decrypted)) return false;
    }
    catch(err) {
      return false
    }
    // set appropriate variables for use
    priv.secrets.key_HMAC = load_key;
    priv.secrets.key_gcm = encryption_key;
    priv.secrets.counter = trusted_data_check;
    ready = true;
    return true;
  };

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity. If the
    * password manager is not in a ready-state, return null.
    * O(n)
    * Return Type: array
    */ 
  keychain.dump = function() {
    if (!ready) return null;
    // increment the counter at each dump
    priv.secrets.counter = priv.secrets.counter+1;
    // setup the cipher using the gcm key
    var cipher_sk = setup_cipher(priv.secrets.key_gcm);
    // encrypt the gcm key using the gcm key for comparison in
    // load to determine if password is correct (redundant check)
    var pass_check = enc_gcm(cipher_sk, priv.secrets.key_gcm);
    // object to be encrypted containing actual keychain, the encryption
    // of the gcm key, and the HMAC of the counter
    var keychain_obj = {};
    keychain_obj.keychain = keychain;
    keychain_obj.pass_check = pass_check;
    keychain_obj.counter_hmac = HMAC(priv.secrets.key_HMAC, string_to_bitarray(priv.secrets.counter+''));
    // stringify this object and then encrypt it with the gcm key to prevent tampering
    var encrypted_keychain = enc_gcm(cipher_sk, string_to_bitarray(JSON.stringify(keychain_obj)));
    // wrap the resulting encrypted object in another object along with the salt.
    var obj = {};
    obj.keychain_str = encrypted_keychain;
    obj.salt = salt;
    // return stringification of the object along with the counter as a trusted_data_check
    return [JSON.stringify(obj), priv.secrets.counter];
  }

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null. If the password manager is not in a ready state, throw an exception. If
    * tampering has been detected with the records, throw an exception.
    * O(1)
    * Arguments:
    *   name: string
    * Return Type: string
    */
  keychain.get = function(name) {
    if (!ready) throw "Keychain not initialized.";
    // set signature of domain to hex value of the HMAC of its name using key_HMAC
    var domain_bits = HMAC(priv.secrets.key_HMAC, name);
    var domain_sig = bitarray_to_hex(domain_bits);
    // check for key existance in keychain
    if (!(domain_sig in keychain)) return null;
    // get result and decrypt it to get resulting password value entry
    var result = keychain[domain_sig];
    var decrypted = dec_gcm(setup_cipher(priv.secrets.key_gcm), result);
    // last 256 bits are the domain_bits, the first are the password plus padding
    var pass_padded = bitarray_slice(decrypted, 0, bitarray_len(decrypted)-256);
    var domain_bits_val = bitarray_slice(decrypted, bitarray_len(decrypted)-256, bitarray_len(decrypted));
    // check domain_bits to check against swap attacks
    if (!bitarray_equal(domain_bits, domain_bits_val)) throw "It's a swap! Mission aborted!";
    // remove padding on password and return it
    var pass = string_from_padded_bitarray(pass_padded, MAX_PW_LEN_BYTES);
    return pass;
  }

  /** 
  * Inserts the domain and associated data into the KVS. If the domain is
  * already in the password manager, this method should update its value. If
  * not, create a new entry in the password manager. If the password manager is
  * not in a ready state, throw an exception.
  * O(1)
  * Arguments:
  *   name: string
  *   value: string
  * Return Type: void
  */
  keychain.set = function(name, value) {
    if (!ready) throw "Keychain not initialized.";
    // if the password is too long throw exception to tell the user
    if (value.length > MAX_PW_LEN_BYTES) throw "Password max length exceeded";
    // pad the password and convert to bitarray
    var padded_value = string_to_padded_bitarray(value, MAX_PW_LEN_BYTES);
    // get domain signature from domain
    var domain_bits = HMAC(priv.secrets.key_HMAC, name);
    var domain_sig = bitarray_to_hex(domain_bits);
    // encrypt the padded value concatenated with the domain_bits and store it in keychain
    var pass_enc = enc_gcm(setup_cipher(priv.secrets.key_gcm), bitarray_concat(padded_value, domain_bits));
    keychain[domain_sig] = pass_enc;
  }

  /**
    * Removes the record with name from the password manager. Returns true
    * if the record with the specified name is removed, false otherwise. If
    * the password manager is not in a ready state, throws an exception.
    * O(1)
    * Arguments:
    *   name: string
    * Return Type: boolean
  */
  keychain.remove = function(name) {
    if (!ready) throw "Keychain not initialized.";
    // get domain signature, check to see if its in the keychain, and if so delete entry
    var domain_sig = bitarray_to_hex(HMAC(priv.secrets.key_HMAC, name));
    if (!(domain_sig in keychain)) return false;
    delete keychain[domain_sig];
    return true;
  }

  return keychain;
}

module.exports.keychain = keychain;
