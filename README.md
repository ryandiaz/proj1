* Making a Key-Value Store
* not encrypting a whole js object with all key-val pairs together
* keys = HMAC of the domains
 - lookup = HMAC(k,domain) if exists in kvs and get value
* max password len = 64 bytes , so always padd to 64
* master password to derive key for HMAC as well as authenticated encryption
  - use PBKDF2 to derive keys from passwords 
  - do not store master password in serialized DB
* security game: adv sends (d,p0,p1) to server, in EXP(0) p0 added to db, in EXP(1) p1 added
 - adv specifies a domain to remove from the db
 - adv will recieve entire disk serialization, which can be altered and returned to the challenger/system
 - adv can specify a domain for authentication, challenger must send password for that domain, but the query must be p1=p0 (or else the adv could just out 1 if d=p1)
 - adv wins if abs(prob(out=1, b=1) - prob(out=1, b=0)) is non-negligible
* provide a defense against the swap attack: adv switches domain to a domain he controls, challenger supplies p for original benign domain
* provide defense on rollback attack: adv can replace an updated record with a previous version
  - system should compute a hash of the system to be stored on a trusted storage medium, when loading password manager check that the hash is valid
* swap attack defense must work without SHA 256 hash
* salt passwords to prevent 'oracle model'
** keychain.init(password): creates new KVS and generates keys O(1)
** keychain.load(master_pass, serialized keychain, hash of keychain from trusted source): verifies and loads keychain O(n)
** keychain.dump() returns JSON encoded serialization and hash of keychain O(n)
** keychain.get(domain) returns password O(1)
** keychain.remove(domain) returns bool_success O(1)


___SECTION__
to run code:
node test-password-manager.js

tests are independent of code writen for password manager
- write more tests to make more robust

* password-manager.js has all code and explanation neccessary
* imported functions are all you'll need. Given functions are sufficient
* look at what these do:  JSON.stringify (toString)  and JSON.parse (fromString)
* don't do ==, will fail on bit arrays
* treat bitarrays as black blocks interacted with with the given function
* Authenticated encryption
 - gcm functions 
 - try{decrypt} if error the decryption sent fail 
* gcm keys are cipher objects
* on page 3 the powers of the adversary are listed
  - adversary has access to harddrive (basically), whereever you're storing on disk. 
  - you can ask for (power 4) the password on a domain only if you have not submited more than one password for that domain
    - look up rollback attack
* one domain, one password
____22:10_____

* 
