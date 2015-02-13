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
    secrets: { /* secret data here */ }, //R to store serialized version of encrypted key value store
    data: { /* Non-secret data here */ } //R store the SHA 256 checksum? Apparently not since the 
  };

  // Maximum length of each record in bytes
  var MAX_PW_LEN_BYTES = 64;
  //R How are we gonna pad the passwords? What if it is exactly 64-bytes?
  //R we could do n bytes of value n-1, storing the password as 65-bytes in the encrypted form like a dummy block
  
  // Flag to indicate whether password manager is "ready" or not
  var ready = false;
  
  //R START RYAN ADDED VARS
  //R salt public for now. does the salt need to be private or change?
  var salt = null;
  //R can't store either of these
  //R END

  var keychain = {}; //R SO This is the apparent store for the key-values 

  /** 
    * Creates an empty keychain with the given password. Once init is called,
    * the password manager should be in a ready state.
    * O(1)
    * Arguments:
    *   password: string
    * Return Type: void
    */
  keychain.init = function(password) {
    //R check the master password? or use key produce to decrypt other passswords?
    var init_salt = random_bitarray(256);
    var init_key = KDF(password, init_salt);//R how can we generate separate encryption and HMAC keys with one KDF call?
    //R for now they are the same but I think this should change
    priv.secrets.key_HMAC = init_key;
    priv.secrets.key_gcm = bitarray_slice(HMAC(init_key, password), 0, 128);
    priv.secrets.counter = 0;
    salt = init_salt;
    ready = true;
    priv.data.version = "CS 255 Password Manager v1.0";
    priv.data.checksum = null;
    
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
    //R repr will contain the encrypted key-value store 
    var obj = JSON.parse(repr);
    var encrypted_keychain = obj.keychain_str;
    salt = obj.salt;
    var load_key = KDF(password, salt);
    //R check if the passwords match
    var key = bitarray_slice(HMAC(load_key, password), 0, 128);
    // console.log(encrypted_keychain)
    var keychain_str = dec_gcm(setup_cipher(key), encrypted_keychain);
    var keychain_obj = JSON.parse(bitarray_to_string(keychain_str));
    //R take load_key to verify the password is correct
    //R check if the password is correct if not return false
    if (!bitarray_equal(keychain_obj.counter_hmac, HMAC(load_key, string_to_bitarray(trusted_data_check+'')))) throw "integrity check fails!";
    // if (!bitarray_equal(trusted_data_check, SHA256(string_to_bitarray(repr)))) throw "integrity check fails!";
    //R trusted_data_check should equal the checksum value in the repsentation, if not throw exception
    // salt = repr_obj.salt;
    keychain = keychain_obj.keychain;
    // var load_key = KDF(password, salt);
    //R check if the passwords match
    // var key = bitarray_slice(HMAC(load_key, password), 0, 128);
    var decrypted = dec_gcm(setup_cipher(key), keychain_obj.pass_check);
    priv.secrets.key_HMAC = load_key;
    priv.secrets.key_gcm = key;
    priv.secrets.counter = trusted_data_check;
    console.log('load')
    console.log(priv.secrets.counter)
    if (!bitarray_equal(key,decrypted)) return false;
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
    //R tentatively implemented
    if (!ready) return null;
    var cipher_sk = setup_cipher(priv.secrets.key_gcm);
    var pass_check = enc_gcm(cipher_sk, priv.secrets.key_gcm);
    var repr_obj = {};
    repr_obj.keychain = keychain;
    repr_obj.pass_check = pass_check;
    priv.secrets.counter = priv.secrets.counter+1;
    repr_obj.counter_hmac = HMAC(priv.secrets.key_HMAC, string_to_bitarray(priv.secrets.counter+''));
    var keychain_str = JSON.stringify(repr_obj);
    var encrypted_keychain = enc_gcm(cipher_sk, string_to_bitarray(keychain_str));
    var obj = {};
    // console.log(encrypted_keychain)
    obj.keychain_str = encrypted_keychain;
    obj.salt = salt;
    var repr = JSON.stringify(obj)
    // var checksum = SHA256(string_to_bitarray(keychain_str)); //R SHA256 takes in bit array
    console.log('dump')
    console.log(priv.secrets.counter)
    return [repr, priv.secrets.counter];
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
    //R how to check checksum?
    //R could strignify keychain, run HMAC and check if equal to value stored in priv
    // var result, pad_len, pass_padded;
    if (!ready) throw "Keychain not initialized.";
    var domain_bits = HMAC(priv.secrets.key_HMAC, name);
    var domain_sig = bitarray_to_hex(domain_bits);
    if (!(domain_sig in keychain)) return null;
    var result = keychain[domain_sig];
    var decrypted = dec_gcm(setup_cipher(priv.secrets.key_gcm), result);
    // console.log(decrypted)
    // console.log(decrypted.length)
    var pass_padded = bitarray_slice(decrypted, 0, bitarray_len(decrypted)-256);
    var domain_bits_val = bitarray_slice(decrypted, bitarray_len(decrypted)-256, bitarray_len(decrypted));
    if (!bitarray_equal(domain_bits, domain_bits_val)) throw "It's a swap! Mission aborted!";
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
    //R signature for name and encrypted value are put in keychain
    if (!ready) throw "Keychain not initialized.";
    if (value.length > MAX_PW_LEN_BYTES) throw "Password max length exceeded";
    var padded_value = string_to_padded_bitarray(value, MAX_PW_LEN_BYTES);
    // value = value + Array(pad_length+1).join(chr_pad) //R pad makes value 65 bytes long, at decrypt look at char val and remove that many from end
    var domain_bits = HMAC(priv.secrets.key_HMAC, name);
    var domain_sig = bitarray_to_hex(domain_bits);

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
    var domain_sig = bitarray_to_hex(HMAC(priv.secrets.key_HMAC, name));
    if (!(domain_sig in keychain)) return false;
    delete keychain[domain_sig];
    return true;
  }

  return keychain;
}

module.exports.keychain = keychain;
