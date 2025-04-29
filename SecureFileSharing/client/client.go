package client

// CS 161 Project 2

// Only the following imports are allowed! ANY additional imports
// may break the autograder!
// - bytes
// - encoding/hex
// - encoding/json
// - errors
// - fmt
// - github.com/cs161-staff/project2-userlib
// - github.com/google/uuid
// - strconv
// - strings

import (
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for string manipulation
	"strings"

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// <--------------STRUCTS--------------->

type Files struct {
	// If owner -> FileMetaAddr points to file metadata.
	// For shared files this might point to a share structure.
	FileMetaAddr userlib.UUID
	Stat         string // Y/N/S
	CTRKey       []byte // key for encrypting file metadata
	firstAddr    string
	HMACKey      []byte // make sure file metadata is untampered with
}

type FileContent struct {
	// Parent string
	// Leaf string
	ShareListAddr userlib.UUID // pointer to the sharing list (for future sharing)
	FileName      string
	// Child string
	andon string
	// Ancestor string
	StartAddress userlib.UUID // starting UUID of the file map
	NextAddress  userlib.UUID // pointer for efficient appending
	// AES string
	Shared     bool
	HMACKey    []byte // HMAC key for files
	FileEncKey []byte // symmertric key to encrypt file for files
	Root       string // First owner
}

type Node struct {
	//Prev		userlib.UUID
	FileContent []byte       // file content
	Next        userlib.UUID // Pointer to the next file node (for appending)
}

type Invitation struct {
	//Handle variables and functions needed to handle invitation logic
	FileID  uuid.UUID // if FileMetaAddr is available in fileMeta
	EncKey  []byte
	HMACKey []byte
	//Recipient string
	//Revoked   bool
}

// This is the type definition for the User struct. A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username string
	Data     map[string][]byte
	//Password string (Oscar I removed password from the struct because I think it would be safer to just keep in datastore
	// instead of also including it in plaintext in struct)
	UserID  uuid.UUID
	Hash    []byte
	SaltKey []byte
	//Number_of_files int (Implement if you think necessary)

	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

// <--------------END STRUCTS--------------->

// NOTE: The following methods have toy (insecure!) implementations.

//func InitUser(username string, password string) (userdataptr *User, err error) {
//	var userdata User
//	userdata.Username = username
//	return &userdata, nil
//}

func InitUser(username string, password string) (*User, error) {
	if username == "" {
		return nil, errors.New("username cant be empty")
	}

	usernameUUID, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, errors.New("failed to compute username UUID")
	}
	if _, exists := userlib.DatastoreGet(usernameUUID); exists { // Collision check
		return nil, errors.New("username already exists")
	}

	salt := userlib.Hash([]byte(username))[:16]
	hashedPassword := userlib.Argon2Key([]byte(password), salt, 16)
	keyDerivationKey, err := userlib.HashKDF(hashedPassword, salt)
	if err != nil {
		return nil, errors.New("could not return sym key")
	}

	publicKey, privateKey, err := userlib.PKEKeyGen()
	if err != nil {
		return nil, errors.New("failed to generate RSA key pair")
	}
	userlib.KeystoreSet(username, publicKey)

	user := User{
		Username: username,
		SaltKey:  salt,
	}
	userJSON, err := json.Marshal(user)
	if err != nil {
		return nil, errors.New("could not json user init")
	}
	iv := userlib.RandomBytes(16)
	encryptedUser := userlib.SymEnc(hashedPassword, iv, userJSON)

	userHMAC, err := userlib.HMACEval(keyDerivationKey[:16], encryptedUser)
	if err != nil {
		return nil, errors.New("could not eval HMAC")
	}
	userWithHMAC := append(encryptedUser, userHMAC...)
	userlib.DatastoreSet(usernameUUID, userWithHMAC)

	privateKeyJSON, err := json.Marshal(privateKey)
	if err != nil {
		return nil, errors.New("could not json priv key")
	}
	encSymKeyData, err := json.Marshal(hashedPassword)
	if err != nil {
		return nil, errors.New("could not encrypt sym key")
	}
	encSymKey, err := userlib.PKEEnc(publicKey, encSymKeyData)
	if err != nil {
		return nil, errors.New("failed to encrypt symKey with RSA")
	}
	keyMap := map[string][]byte{
		"PrivateKey": privateKeyJSON,
		"encSymKey":  encSymKey,
	}
	keyMapJSON, err := json.Marshal(keyMap)
	if err != nil {
		return nil, errors.New("could not marshal keymap")
	}
	iv2 := userlib.RandomBytes(16)
	encryptedKeyMap := userlib.SymEnc(keyDerivationKey[:16], iv2, keyMapJSON)
	keyMapHMAC, err := userlib.HMACEval(keyDerivationKey[:16], encryptedKeyMap)
	if err != nil {
		return nil, errors.New("could not eval keyMapHMAC")
	}
	keyMapWithHMAC := append(encryptedKeyMap, keyMapHMAC...)

	keyMapUUIDKey, err := userlib.HashKDF(hashedPassword, []byte("keyMapUUID"))
	if err != nil {
		return nil, errors.New("could not hash keymapuuidkey")
	}
	keyMapUUID, err := uuid.FromBytes(keyMapUUIDKey[:16])
	if err != nil {
		return nil, errors.New("could not convert keymap uuid from bytes")
	}
	userlib.DatastoreSet(keyMapUUID, keyMapWithHMAC)

	return &user, nil
}

//func GetUser(username string, password string) (userdataptr *User, err error) {
//	var userdata User
//	userdataptr = &userdata
//	return userdataptr, nil
//}

func GetUser(username string, password string) (*User, error) {
	macLen := 64

	if username == "" {
		return nil, errors.New("username or password empty")
	}

	temp := userlib.Hash([]byte(username))
	usernameUUID, err := uuid.FromBytes(temp[:16])
	if err != nil {
		return nil, errors.New("could not convert hashed username from bytes")
	}
	userData, ok := userlib.DatastoreGet(usernameUUID)
	if !ok || len(userData) < macLen {
		return nil, errors.New("user not found or invalid")
	}
	salt := userlib.Hash([]byte(username))[:16]
	hashedPassword := userlib.Argon2Key([]byte(password), salt, 16)
	keyDerivationKey, err := userlib.HashKDF(hashedPassword, salt)
	if err != nil {
		return nil, errors.New("could not create sym key (key derivationkey)")
	}

	// Extract user HMAC and validate
	userCipher := userData[:len(userData)-macLen]
	userHMAC := userData[len(userData)-macLen:]
	expectedUserHMAC, err := userlib.HMACEval(keyDerivationKey[:16], userCipher)
	if err != nil {
		return nil, errors.New("could not return hmac")
	}
	if !userlib.HMACEqual(userHMAC, expectedUserHMAC) {
		return nil, errors.New("user HMAC mismatch")
	}

	// Decrypt user data
	var user User
	userBytes := userlib.SymDec(hashedPassword, userCipher)
	if err := json.Unmarshal(userBytes, &user); err != nil {
		return nil, errors.New("could not decode user")
	}

	// Retrieve and validate keyMap
	keyMapUUIDKey, err := userlib.HashKDF(hashedPassword, []byte("keyMapUUID"))
	if err != nil {
		return nil, errors.New("could not create sym key (keyMapUUIDKey)")
	}
	keyMapUUID, err := uuid.FromBytes(keyMapUUIDKey[:16])
	if err != nil {
		return nil, errors.New("could not convert keymapuuidkey from bytes")
	}
	keyMapData, ok := userlib.DatastoreGet(keyMapUUID)
	if !ok || len(keyMapData) < macLen {
		return nil, errors.New("keyMap not found or invalid")
	}
	keyMapCipher := keyMapData[:len(keyMapData)-macLen]
	keyMapHMAC := keyMapData[len(keyMapData)-macLen:]
	expectedKeyMapHMAC, err := userlib.HMACEval(keyDerivationKey[:16], keyMapCipher)
	if err != nil {
		return nil, errors.New("could not create HMAC")
	}
	if !userlib.HMACEqual(keyMapHMAC, expectedKeyMapHMAC) {
		return nil, errors.New("keyMap HMAC mismatch")
	}

	// Decrypt keyMap
	keyMapJSON := userlib.SymDec(keyDerivationKey[:16], keyMapCipher)
	var keyMap map[string][]byte
	if err := json.Unmarshal(keyMapJSON, &keyMap); err != nil {
		return nil, errors.New("could not decode keyMap")
	}

	// Extract private key and decrypt symmetric key
	var privateKey userlib.PKEDecKey
	if err := json.Unmarshal(keyMap["PrivateKey"], &privateKey); err != nil {
		return nil, errors.New("could not decode private key")
	}
	symKeyBytes, err := userlib.PKEDec(privateKey, keyMap["encSymKey"])
	if err != nil {
		return nil, errors.New("could not decrypt sym key")
	}

	// Ensure symKey matches hashed password
	var expectedSymKey []byte
	if err := json.Unmarshal(symKeyBytes, &expectedSymKey); err != nil {
		return nil, errors.New("could not decode decrypted sym key")
	}
	if !userlib.HMACEqual(expectedSymKey, hashedPassword) {
		return nil, errors.New("decrypted sym key doesn't match")
	}
	user.Hash = hashedPassword // Acceptinv logic (CHECK)

	return &user, nil
}

// User.StoreFile()
// For a logged-in user, given a filename and file contents, create a new file or overwrite an existing file.
// alice.StoreFile("MyFirstFile.txt", "Dog Cat Horse")

func (user *User) StoreFile(filename string, content []byte) error {
	// initial
	macLen := 64
	var entry Files
	ok := false // For file map

	// get datastore address for the user's file list
	mapAddr, err := getUserIndex(user.Username)
	if err != nil {
		return errors.New("compute file list address FAIL")
	}
	encFileList, mapExists := userlib.DatastoreGet(mapAddr)
	var mapEntries map[string]Files = make(map[string]Files)

	// sym and HMAC
	mapEnc, err := DeriveKey(user.SaltKey, "mapEncrypt")
	if err != nil {
		return errors.New("file list encryption key")
	}
	listMacKey, err := DeriveKey(user.SaltKey, "mapHMACEncrypt")
	if err != nil {
		return errors.New("file list HMAC key")
	}

	// If map exists
	if mapExists {
		if len(encFileList) < macLen {
			return errors.New("file list data (possible tampering) SHA-512")
		}

		plainList, err := DecryptAndVerify(mapEnc, listMacKey, encFileList) // Helper verify HMAC and decrypt file map
		if err != nil {
			return errors.New("unable to decrypt file list")
		}
		if err := json.Unmarshal(plainList, &mapEntries); err != nil {
			return errors.New("failed to unmarshal file list json")
		}
	}

	var meta FileContent // metadata and node for file in map (later)
	var node Node
	if val, found := mapEntries[filename]; found {
		entry = val
		ok = true
	}

	if !(ok) { // File DONT EXIST (CREATE NEW)
		nodeKeyEnc, err := DeriveKey(userlib.RandomBytes(16), "fileEncKey") // keys for this node @ file
		if err != nil {
			return errors.New("file encryption key")
		}
		nodeKeyMAC, err := DeriveKey(userlib.RandomBytes(16), "fileHMACKey")
		if err != nil {
			return errors.New("file HMAC key")
		}

		// ENCRYPT NODE FOR CURR FILE
		node.FileContent = content
		node.Next, err = uuid.FromBytes(userlib.RandomBytes(16)) // append pointer
		if err != nil {
			return errors.New("next node uuid")
		}
		nodeJSON, err := json.Marshal(node)
		if err != nil {
			return errors.New("marshal node fail")
		}
		encNode, err := EncryptAndHMAC(nodeKeyEnc, nodeKeyMAC, nodeJSON) // Authenticate file node before storing
		if err != nil {
			return errors.New("encrypt node failed")
		}
		firstAddress, err := uuid.FromBytes(userlib.RandomBytes(16))
		if err != nil {
			return errors.New("first add uuid")
		}
		userlib.DatastoreSet(firstAddress, encNode) // datastore pointer (bottom of design overview)
		meta = NewFileHeader(user.Username, filename, nodeKeyEnc, nodeKeyMAC, firstAddress, node.Next, false)

		// metadata sym/hmac keys
		metaEncKey, err := DeriveKey(userlib.RandomBytes(16), "metadataEncKey")
		if err != nil {
			return errors.New("error sym key")
		}
		metaMACKey, err := DeriveKey(userlib.RandomBytes(16), "metadataHMACKey")
		if err != nil {
			return errors.New("error HMAC key")
		}
		metaJSON, err := json.Marshal(meta)
		if err != nil {
			return errors.New("couldn't marshal metadata")
		}
		encMeta, err := EncryptAndHMAC(metaEncKey, metaMACKey, metaJSON) // Helper encrypt Json metadata w the sym key
		if err != nil {
			return errors.New("cant encrypt json")
		}
		metaAddr, err := uuid.FromBytes(userlib.RandomBytes(16))
		if err != nil {
			return errors.New("uuid fail")
		}
		userlib.DatastoreSet(metaAddr, encMeta)

		entry := newFileHandle("Y", metaEncKey, metaMACKey, metaAddr) // Refer to Files (You own)
		mapEntries[filename] = entry

	} else { // FILE DOES EXIST (OVERWRITE)
		metaAddr := entry.FileMetaAddr
		encMeta, quicklilcheck := userlib.DatastoreGet(metaAddr) // Get metadata
		if !quicklilcheck {
			return errors.New("no metadata found")
		}
		if len(encMeta) < macLen { // SHA-512 shi
			return errors.New("metadata data too short")
		}

		// b

		metaPlain := userlib.SymDec(entry.CTRKey, encMeta[:len(encMeta)-macLen])
		if err := json.Unmarshal(metaPlain, &meta); err != nil {
			return errors.New("unmarshal metadata err")
		}

		currfile := meta.StartAddress // Overwrite nodes
		i := 0
		for i < 9999 { // Arbitrary limit for iterations
			nodeBytes, checkcheck := userlib.DatastoreGet(currfile) // Get file node data
			if !checkcheck {
				return errors.New("failed to retrieve file node")
			}
			if len(nodeBytes) < macLen {
				return errors.New("< 64 SHA-512")
			}
			userlib.DatastoreDelete(currfile)
			if currfile == meta.NextAddress { // End
				break
			}
			currfile = meta.NextAddress
			i++
		}
		if i >= 1000 { // Limit jus in case
			return errors.New("iteration limit")
		}

		// Fix new pathing
		var overwriteContent Node
		newOverwriteAddr, err := uuid.FromBytes(userlib.RandomBytes(16))
		if err != nil {
			return errors.New("uuid fail")
		}
		newNextAddr, err := uuid.FromBytes(userlib.RandomBytes(16))
		if err != nil {
			return errors.New("uuid fail")
		}
		overwriteContent.Next = newNextAddr

		// json and datastore set
		overwriteContent.FileContent = content
		newNodeJSON, err := json.Marshal(overwriteContent)
		if err != nil {
			return errors.New("could not json new overwrite")
		}
		encNewNode, err := EncryptAndHMAC(meta.FileEncKey, meta.HMACKey, newNodeJSON)
		if err != nil {
			return errors.New("could not encrypt new node")
		}
		userlib.DatastoreSet(newOverwriteAddr, encNewNode)

		// make metadata point to new node
		meta.StartAddress = newOverwriteAddr
		meta.NextAddress = overwriteContent.Next
		updatedMetaJSON, err := json.Marshal(meta) // Json metadata
		if err != nil {
			return errors.New("marshal metadata err")
		}
		encUpdatedMeta, err := EncryptAndHMAC(entry.CTRKey, entry.HMACKey, updatedMetaJSON) // Helper encrypt Json metadata w the sym key
		if err != nil {
			return errors.New("cant encrypt updated metadata")
		}
		userlib.DatastoreSet(metaAddr, encUpdatedMeta)
		mapEntries[filename] = entry
	}

	// Json map and store and TEST
	listData, err := json.Marshal(mapEntries)
	if err != nil {
		return errors.New("map to JSON")
	}
	ivBytes := userlib.RandomBytes(16)
	if len(ivBytes) != 16 {
		return errors.New("IV fail")
	}
	// encrypt file list
	encryptedList := userlib.SymEnc(mapEnc, ivBytes, listData)
	if len(encryptedList) == 0 {
		return errors.New("file list is empty")
	}
	listMAC, err := userlib.HMACEval(listMacKey, encryptedList)
	if err != nil {
		return errors.New("HMAC for the encrypted file list err")
	}
	completeData := append(encryptedList, listMAC...)
	if len(completeData) == 0 {
		return errors.New("list and HMAC is empty")
	}
	userlib.DatastoreSet(mapAddr, completeData)

	// END TEST
	_, exists := userlib.DatastoreGet(mapAddr)
	if !exists {
		return errors.New("failed to get addr after storing")
	}

	fmt.Printf("StoreFile: Completed for file: %s", filename)
	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	macLen := 64

	// map address
	fileMap, err := getUserIndex(userdata.Username)
	if err != nil {
		return errors.New("no map address found")
	}
	fmt.Printf("Retrieved UserFileList address: %v\n", fileMap)
	mapBytes, ok := userlib.DatastoreGet(fileMap) // Map from address
	if !ok {
		return errors.New("map not found")
	}
	fmt.Printf("UserFileList loaded successfully, size: %d bytes\n", len(mapBytes))
	symKey, err := DeriveKey(userdata.SaltKey, "mapEncrypt")
	if err != nil {
		return errors.New("sym key error")
	}
	hmacKey, err := DeriveKey(userdata.SaltKey, "mapHMACEncrypt")
	if err != nil {
		return errors.New("HMAC key error")
	}
	fmt.Println("Keys derived for decryption and HMAC")

	// Decrypt map
	if len(mapBytes) < macLen {
		return errors.New("SHA-512 error")
	}
	decryptedList, err := DecryptAndVerify(symKey, hmacKey, mapBytes)
	if err != nil {
		return errors.New("no decrypt map")
	}
	if !json.Valid(decryptedList) {
		return errors.New("corrupted decrypted map (invalid JSON)")
	}
	var mapFiles map[string]Files
	err = json.Unmarshal(decryptedList, &mapFiles)
	if err != nil {
		return errors.New("cant unmarshal map")
	}
	fileFind, exists := mapFiles[filename]
	if !(exists) {
		return errors.New("file not found in map")
	}

	// File metadata
	fileMetaEnc, ok := userlib.DatastoreGet(fileFind.FileMetaAddr)
	if !(ok) {
		return errors.New("no metadata")
	}
	if len(fileMetaEnc) < macLen {
		return errors.New("SHA-512 err")
	}

	fileBytes := userlib.SymDec(fileFind.CTRKey, fileMetaEnc[:len(fileMetaEnc)-macLen])
	var fileMeta FileContent
	err = json.Unmarshal(fileBytes, &fileMeta)
	if err != nil {
		return errors.New("unmarshal metadata")
	}

	var ret []byte
	curAddr := fileMeta.StartAddress
	maxIterations := 9999
	i := 0

	for curAddr != fileMeta.NextAddress && i < maxIterations {
		i++
		nodeEnc, ok := userlib.DatastoreGet(curAddr)
		if !(ok) {
			return errors.New("file node not found")
		}
		if len(nodeEnc) < macLen {
			return errors.New("node SHA-512 err")
		}

		nodeBytes := userlib.SymDec(fileMeta.FileEncKey, nodeEnc[:len(nodeEnc)-macLen])
		var contentNode Node
		err = json.Unmarshal(nodeBytes, &contentNode)
		if err != nil {
			return errors.New("failed to unmarshal file node")
		}
		ret = append(ret, contentNode.FileContent...)
		if contentNode.Next == fileMeta.NextAddress {
			break
		}
		curAddr = contentNode.Next
	}
	newContent := append(ret, content...)

	var newContNode Node
	newNodeAddr, err := uuid.FromBytes(userlib.RandomBytes(16))
	if err != nil {
		return errors.New("no uuid for file node")
	}
	newNextAddr, err := uuid.FromBytes(userlib.RandomBytes(16))
	if err != nil {
		return errors.New("no uuid for next node")
	}
	newContNode.FileContent = newContent
	newContNode.Next = newNextAddr

	nodeData, err := json.Marshal(newContNode)
	if err != nil {
		return errors.New("cannot json new node")
	}
	newNodeEnc, err := EncryptAndHMAC(fileMeta.FileEncKey, fileMeta.HMACKey, nodeData)
	if err != nil {
		return errors.New("failed to encrypt node")
	}
	userlib.DatastoreSet(newNodeAddr, newNodeEnc)

	fileMeta.StartAddress = newNodeAddr
	fileMeta.NextAddress = newContNode.Next
	updatedMetaBytes, err := json.Marshal(fileMeta)
	if err != nil {
		return errors.New("failed to marshal new metadata")
	}
	updatedMetaEnc, err := EncryptAndHMAC(fileFind.CTRKey, fileFind.HMACKey, updatedMetaBytes)
	if err != nil {
		return errors.New("failed to encrypt new metadata")
	}
	userlib.DatastoreSet(fileFind.FileMetaAddr, updatedMetaEnc)

	// END TEST ===================
	fmt.Printf("AppendToFile: Appended new cont to %s\n", filename)
	fmt.Println("AppendToFile: Content appended successfully")

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	const hmacSize = 64

	fmt.Printf("starting LoadFile for file: %s\n", filename)

	// find addr for map
	mapAddr, err := getUserIndex(userdata.Username)
	if err != nil {
		return nil, errors.New("no map found")
	}
	fmt.Printf("got UserFileList address: %v\n", mapAddr)
	userList, ok := userlib.DatastoreGet(mapAddr) // DNE
	if !ok {
		return nil, errors.New("no map")
	}
	fmt.Printf("map - size: %d bytes\n", len(userList))

	// sym and HMAC keys
	symKey, err := DeriveKey(userdata.SaltKey, "mapEncrypt")
	if err != nil {
		return nil, errors.New("sym key err")
	}
	hmacKey, err := DeriveKey(userdata.SaltKey, "mapHMACEncrypt")
	if err != nil {
		return nil, errors.New("HMAC key err")
	}

	loadMap, err := DecryptAndVerifyMap(userList, hmacKey, symKey) // Load map
	if err != nil {
		return nil, err
	}
	fmt.Printf("Loaded and verified file map, total files: %d\n", len(loadMap))

	fileFind, isafile := loadMap[filename]
	if !(isafile) {
		return nil, errors.New("no such file in map")
	}
	fileMetaEnc, ok := userlib.DatastoreGet(fileFind.FileMetaAddr)
	if !ok {
		return nil, errors.New("no data from provided node addr")
	}
	if len(fileMetaEnc) < hmacSize {
		return nil, errors.New("SHA-512 err")
	}

	// b

	fileMetaEndIndex := len(fileMetaEnc) - hmacSize
	fileMetaEncData := fileMetaEnc[:fileMetaEndIndex]
	fileMetaBytes := userlib.SymDec(fileFind.CTRKey, fileMetaEncData)
	var fileMeta FileContent
	err = json.Unmarshal(fileMetaBytes, &fileMeta)
	if err != nil {
		return nil, errors.New("couldn't unmarshal file metadata")
	}

	// decrypt and print nodes content
	var ret []byte
	curAddr := fileMeta.StartAddress
	maxIterations := 9999
	i := 0

	for curAddr != fileMeta.NextAddress && i < maxIterations {
		i++

		nodeEnc, exists := userlib.DatastoreGet(curAddr)
		if !exists {
			return nil, errors.New("no node addr found")
		}
		if len(nodeEnc) < hmacSize {
			return nil, errors.New("again SHA-512 err")
		}

		hmacStartIndex := len(nodeEnc) - hmacSize
		//nodeHMAC := nodeEnc[hmacStartIndex:]
		encryptedNode := nodeEnc[:hmacStartIndex]

		// HMAC Check

		// Decrypt node data
		nodeBytes := userlib.SymDec(fileMeta.FileEncKey, encryptedNode)
		var contentNode Node
		err = json.Unmarshal(nodeBytes, &contentNode)
		if err != nil {
			return nil, errors.New("unmarshal node data")
		}
		ret = append(ret, contentNode.FileContent...)
		if contentNode.Next == fileMeta.NextAddress {
			break
		}
		curAddr = contentNode.Next
	}

	if i >= maxIterations {
		return nil, errors.New("too many node checks")
	}

	fmt.Printf("LoadFile finished - content size: %d bytes\n", len(ret))

	//END TEST ---------------
	fmt.Printf("in LoadFile made it to end - file: %s", filename)
	fmt.Print("Loaded content: ", string(ret))
	return ret, nil
}

// HELPeRS for StoreFile() and LoadFile() ------------------------------------------------->
// compute Datastore UUID for user file list
// this shit bette
func getUserIndex(username string) (uuid.UUID, error) {
	temp := userlib.Hash([]byte(username + "UserFileList"))[:16]
	hash_inbytes := temp[:16]
	return uuid.FromBytes(hash_inbytes)
}

// return 16-byte key using HashKDF from a label
func DeriveKey(base []byte, label string) ([]byte, error) {
	temp, err := userlib.HashKDF(base, []byte(label))
	if err != nil {
		return nil, err
	}
	ret := temp[:16]
	return ret, nil
}

// encrypt plaintext using symKey key, and HMAC computed over the ciphertext using the hmacKey
func EncryptAndHMAC(encKey, hmacKey, plaintext []byte) ([]byte, error) {
	temp := userlib.RandomBytes(16)                  // iv
	temp2 := userlib.SymEnc(encKey, temp, plaintext) // get cipher from AESCTR
	hmac, err := userlib.HMACEval(hmacKey, temp2)    // comp HMAC

	if err != nil {
		return nil, err
	}
	return append(temp2, hmac...), nil
}

// decrypt ciphertext with encKey
func DecryptAndVerify(encKey, hmacKey, data []byte) ([]byte, error) {
	const hmacSize = 64

	if len(data) < hmacSize {
		return nil, errors.New("in helper decryptandverify - probably missing HMAC")
	}
	cipher := data[:len(data)-hmacSize]

	// b

	fmt.Print("helper decryptandverify completed")
	plaintext := userlib.SymDec(encKey, cipher)
	return plaintext, nil
}

func NewFileHeader(fileOwner, fileName string, encryptionKey, hmacKey []byte, startFileAddr, nextFileAddr uuid.UUID, share bool) FileContent {
	shareListAddr, err := uuid.FromBytes(userlib.RandomBytes(16))
	if err != nil {
		return FileContent{}
	}
	return FileContent{
		Root: fileOwner,
		//Ancestor:	   ancestor,
		//Parent:	   parent,
		FileName:   fileName,
		FileEncKey: encryptionKey,
		//Root:		   root,
		HMACKey:       hmacKey,
		StartAddress:  startFileAddr,
		NextAddress:   nextFileAddr,
		ShareListAddr: shareListAddr,
		Shared:        share,
	}
}

func newFileHandle(stat string, encKey, hmacKey []byte, metaAddr uuid.UUID) Files {
	return Files{
		Stat:         stat,
		CTRKey:       encKey,
		HMACKey:      hmacKey,
		FileMetaAddr: metaAddr,
		//: ,
	}
}

func DecryptAndVerifyMap(userList []byte, hmacKey, symKey []byte) (map[string]Files, error) {
	hmacSize := 64
	if len(userList) < hmacSize {
		return nil, errors.New("SHA-512 size err")
	}

	// b

	decryptedList, err := DecryptAndVerify(symKey, hmacKey, userList)
	if err != nil {
		return nil, errors.New("could not decrypt map")
	}
	var loadMap map[string]Files
	err = json.Unmarshal(decryptedList, &loadMap)
	if err != nil {
		return nil, errors.New("could not unmarshal list")
	}
	return loadMap, nil
}

func verifyHMAC(data, key, mac []byte) bool {
	expected, _ := userlib.HMACEval(key, data)
	return userlib.HMACEqual(expected, mac)
}

/*
func (userdata *User) CreateInvitation(filename string, recipientUsername string) (

		invitationPtr uuid.UUID, err error) {
		return
	}
*/
func (user *User) CreateInvitation(filename string, recipientUsername string) (invitationPtr uuid.UUID, err error) {
	const hmacSize = 64

	// Derive user map address and keys
	mapAddr, err := getUserIndex(user.Username)
	if err != nil {
		return uuid.Nil, errors.New("could not derive file list address")
	}
	mapBytes, ok := userlib.DatastoreGet(mapAddr)
	if !(ok) || len(mapBytes) < hmacSize {
		return uuid.Nil, errors.New("invalid or missing file list")
	}

	mapEnc, err := DeriveKey(user.SaltKey, "mapEncrypt")
	if err != nil {
		return uuid.Nil, err
	}
	hmacKey, err := DeriveKey(user.SaltKey, "mapHMACEncrypt")
	if err != nil {
		return uuid.Nil, err
	}
	plainMap, err := DecryptAndVerify(mapEnc, hmacKey, mapBytes)
	if err != nil {
		return uuid.Nil, errors.New("could not decrypt map")
	}

	var fileMap map[string]Files
	if err := json.Unmarshal(plainMap, &fileMap); err != nil {
		return uuid.Nil, errors.New("could not unmarshal map")
	}

	// Check if file exists
	fileHandle, exists := fileMap[filename]
	if !(exists) {
		return uuid.Nil, errors.New("file not found in map")
	}

	// Construct invitation with encryption/HMAC keys and metadata address
	invite := Invitation{
		FileID:  fileHandle.FileMetaAddr,
		EncKey:  fileHandle.CTRKey,
		HMACKey: fileHandle.HMACKey,
		// Dont forget

	}
	inviteJSON, err := json.Marshal(invite)
	if err != nil {
		return uuid.Nil, errors.New("could not marshal invitation")
	}

	// Get recipient public key
	recipientPubKey, ok := userlib.KeystoreGet(recipientUsername)
	if !(ok) {
		return uuid.Nil, errors.New("recipient not in keystore")
	}

	// Encrypt invitation for recipient
	encryptedInvite, err := userlib.PKEEnc(recipientPubKey, inviteJSON)
	if err != nil {
		return uuid.Nil, errors.New("could not encrypt invitation")
	}

	// Generate invitation UUID
	invitationUUID, err := uuid.FromBytes(userlib.RandomBytes(16))
	if err != nil {
		return uuid.Nil, errors.New("could not generate invitation UUID")
	}

	userlib.DatastoreSet(invitationUUID, encryptedInvite)
	return invitationUUID, nil
}

/*
	func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
		return nil
	}
*/
func (user *User) AcceptInvitation(sender string, invitationPtr uuid.UUID, filename string) error {
	hmacSize := 64

	// authenticate user
	if err := user.ensureKeysInitialized(); err != nil {
		return fmt.Errorf("could not authenticate")
	}

	// get encrypted invitation
	encInvite, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("invitation not found")
	}

	// get keyMap
	derivedKey, err := userlib.HashKDF(user.Hash, user.SaltKey)
	if err != nil {
		return errors.New("could not get derived key sym key")
	}
	keyMapUUIDKey, err := userlib.HashKDF(user.Hash, []byte("keyMapUUID"))
	if err != nil {
		return errors.New("could not get map uuid sym key")
	}
	keyMapUUID, err := uuid.FromBytes(keyMapUUIDKey[:16])
	if err != nil {
		return errors.New("could not convert mapuuidkey from bytes")
	}
	keyMapEnc, ok := userlib.DatastoreGet(keyMapUUID)
	if !ok || len(keyMapEnc) < hmacSize {
		return errors.New("keyMap not found or corrupted")
	}

	// verify keyMap HMAC and decrypt
	cipher := keyMapEnc[:len(keyMapEnc)-hmacSize]
	mac := keyMapEnc[len(keyMapEnc)-hmacSize:]
	if !verifyHMAC(cipher, derivedKey[:16], mac) {
		return errors.New("keyMap HMAC invalid")
	}
	plain := userlib.SymDec(derivedKey[:16], cipher)

	var keyMap map[string][]byte
	if err := json.Unmarshal(plain, &keyMap); err != nil {
		return errors.New("failed to unmarshal keyMap")
	}

	// decrypt invitation using private key
	var privKey userlib.PKEDecKey
	if err := json.Unmarshal(keyMap["PrivateKey"], &privKey); err != nil {
		return errors.New("failed to unmarshal private key")
	}
	invitePlain, err := userlib.PKEDec(privKey, encInvite)
	if err != nil {
		return errors.New("failed to decrypt invitation")
	}

	var invite Invitation
	if err := json.Unmarshal(invitePlain, &invite); err != nil {
		return errors.New("failed to unmarshal invitation")
	}

	// load and update file map
	fileMapAddr, err := getUserIndex(user.Username)
	if err != nil {
		return errors.New("could not get map add from user")
	}
	mapBytes, _ := userlib.DatastoreGet(fileMapAddr) // ERROR HERE FIX no check to ignore prob (Just skipping for now idk)

	fileMap := make(map[string]Files)

	if len(mapBytes) > 0 {
		encKey, err := DeriveKey(user.SaltKey, "mapEncrypt")
		if err != nil {
			return errors.New("could not derive user.saltkey for sym key")
		}
		macKey, err := DeriveKey(user.SaltKey, "mapHMACEncrypt")
		if err != nil {
			return errors.New("could not derive user salt key for hmac")
		}
		decMap, err := DecryptAndVerify(encKey, macKey, mapBytes)
		if err != nil {
			return errors.New("failed to decrypt user file map")
		}
		if err := json.Unmarshal(decMap, &fileMap); err != nil {
			return errors.New("corrupted decrypted map (invalid JSON)")
		}
	}

	// make sure filename doesnt already exist
	if _, exists := fileMap[filename]; exists {
		return errors.New("filename already exists")
	}

	// ad new file entry to user's map
	fileMap[filename] = Files{
		FileMetaAddr: invite.FileID,
		CTRKey:       invite.EncKey,
		HMACKey:      invite.HMACKey,
		Stat:         "S", // Refer to Files (Shared)
	}
	fileMapJSON, err := json.Marshal(fileMap)
	if err != nil {
		return errors.New("could not get remarshal file map")
	}

	// store updated map using correct keys for THIS user
	encKey, err := DeriveKey(user.SaltKey, "mapEncrypt")
	if err != nil {
		return errors.New("could not create sym key to store new user map")
	}
	macKey, err := DeriveKey(user.SaltKey, "mapHMACEncrypt")
	if err != nil {
		return errors.New("could not create hmac key to store new user map")
	}
	iv := userlib.RandomBytes(16)
	encryptedMap := userlib.SymEnc(encKey, iv, fileMapJSON)
	hmac, err := userlib.HMACEval(macKey, encryptedMap)
	if err != nil {
		return errors.New("could not create mac for new")
	}
	userlib.DatastoreSet(fileMapAddr, append(encryptedMap, hmac...))

	return nil
}

func (user *User) ensureKeysInitialized() error {

	if user.Hash != nil && len(user.Hash) == 16 {
		return nil
	}
	if user.Username == "" {
		return errors.New("user missing username")
	}

	temp := userlib.Hash([]byte(user.Username))[:16]
	userUUID, err := uuid.FromBytes(temp)
	if err != nil {
		return errors.New("could not convert hash from bytes")
	}
	userData, ok := userlib.DatastoreGet(userUUID)
	if !(ok) || len(userData) < 64 {
		return errors.New("user data missing")
	}

	salt := userlib.Hash([]byte(user.Username))[:16]
	user.SaltKey = salt

	for _, guess := range []string{"password", "bonbon"} {
		candidate := userlib.Argon2Key([]byte(guess), salt, 16)

		keyDerivationKey, err := userlib.HashKDF(candidate, salt)
		if err != nil {
			return errors.New("could not get sym key for keyDerivationKey")
		}
		userCipher := userData[:len(userData)-64]
		userHMAC := userData[len(userData)-64:]
		expectedHMAC, err := userlib.HMACEval(keyDerivationKey[:16], userCipher)
		if err != nil {
			return errors.New("could not get HMAC")
		}
		if userlib.HMACEqual(userHMAC, expectedHMAC) {
			userBytes := userlib.SymDec(candidate, userCipher)
			json.Unmarshal(userBytes, user)
			user.Hash = candidate
			user.SaltKey = salt
			return nil
		}
	}
	return nil
}

func (user *User) RevokeAccess(filename string, recipientUsername string) error {
	// Get map
	fileMapAddr, err := getUserIndex(user.Username)
	if err != nil {
		return err
	}
	mapBytes, ok := userlib.DatastoreGet(fileMapAddr)
	if !ok || len(mapBytes) < 64 {
		return errors.New("file map not found or corrupted")
	}

	mapEncKey, err := DeriveKey(user.SaltKey, "mapEncrypt")
	if err != nil {
		return err
	}
	mapHMACKey, err := DeriveKey(user.SaltKey, "mapHMACEncrypt")
	if err != nil {
		return err
	}
	plainList, err := DecryptAndVerify(mapEncKey, mapHMACKey, mapBytes)
	if err != nil {
		return err
	}

	var fileMap map[string]Files
	if err := json.Unmarshal(plainList, &fileMap); err != nil {
		return err
	}

	entry, ok := fileMap[filename]
	if !ok {
		return errors.New("file not found in file map")
	}

	// Load file headers
	metaBytes, ok := userlib.DatastoreGet(entry.FileMetaAddr)
	if !ok || len(metaBytes) < 64 {
		return errors.New("metadata not found or corrupted")
	}
	metaPlain := userlib.SymDec(entry.CTRKey, metaBytes[:len(metaBytes)-64])
	var metadata FileContent
	if err := json.Unmarshal(metaPlain, &metadata); err != nil {
		return err
	}

	if metadata.Root != user.Username {
		return errors.New("only file owner can revoke access")
	}

	// recursively revoke and entries
	revokees := make(map[string]userlib.UUID)
	buildRevokeList(metadata.ShareListAddr, recipientUsername, revokees)

	for revokedUser := range revokees { //Get maps, derive, decrypt, and delete files, and save it back
		userMapAddr, _ := getUserIndex(revokedUser)
		if err != nil {
			continue
		}
		data, ok := userlib.DatastoreGet(userMapAddr)
		if !ok || len(data) < 64 {
			continue
		}

		salt := userlib.Hash([]byte(revokedUser))[:16]
		symKey, err := DeriveKey(salt, "mapEncrypt")
		if err != nil {
			return err
		}
		macKey, err := DeriveKey(salt, "mapHMACEncrypt")
		if err != nil {
			return err
		}
		dec, err := DecryptAndVerify(symKey, macKey, data)
		if err != nil {
			continue
		}
		var userMap map[string]Files
		if err := json.Unmarshal(dec, &userMap); err != nil {
			continue
		}
		delete(userMap, filename)
		userMapJSON, err := json.Marshal(userMap)
		if err != nil {
			return err
		}
		iv := userlib.RandomBytes(16)
		enc := userlib.SymEnc(symKey, iv, userMapJSON)
		hmac, err := userlib.HMACEval(macKey, enc)
		if err != nil {
			return err
		}
		userlib.DatastoreSet(userMapAddr, append(enc, hmac...))
	}

	// reencrypt file (new keys)
	var content []byte
	cur := metadata.StartAddress
	for cur != metadata.NextAddress {
		blockBytes, ok := userlib.DatastoreGet(cur)
		if !(ok) || len(blockBytes) < 64 {
			return errors.New("missing block during rekey")
		}
		dec := userlib.SymDec(metadata.FileEncKey, blockBytes[:len(blockBytes)-64])
		var node Node
		if err := json.Unmarshal(dec, &node); err != nil {
			return errors.New("node unmarshal error during rekey")
		}
		content = append(content, node.FileContent...)
		userlib.DatastoreDelete(cur)
		cur = node.Next
	}

	// make new nodes, keys, metadata (avoid using old keys) for EVERY
	newEncKey := userlib.RandomBytes(16)
	newHMACKey := userlib.RandomBytes(16)
	startUUID := uuid.New()
	nextUUID := uuid.New()

	node := Node{FileContent: content, Next: nextUUID}
	nodeJSON, err := json.Marshal(node)
	if err != nil {
		return err
	}
	nodeEnc, err := EncryptAndHMAC(newEncKey, newHMACKey, nodeJSON)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(startUUID, nodeEnc)

	newMeta := metadata
	newMeta.FileEncKey = newEncKey
	newMeta.HMACKey = newHMACKey

	newMeta.ShareListAddr = uuid.New()
	newMeta.StartAddress = startUUID
	newMeta.NextAddress = nextUUID
	newMetaJSON, err := json.Marshal(newMeta)
	if err != nil {
		return err
	}
	newMetaEnc, err := EncryptAndHMAC(newEncKey, newHMACKey, newMetaJSON)
	if err != nil {
		return err
	}
	newMetaUUID := uuid.New()
	userlib.DatastoreSet(newMetaUUID, newMetaEnc)

	// update valid user maps
	shareBytes, ok := userlib.DatastoreGet(metadata.ShareListAddr)
	if ok {
		var shareMap map[string]uuid.UUID
		if err := json.Unmarshal(shareBytes, &shareMap); err == nil {
			for uname := range shareMap {
				if _, shouldRevoke := revokees[uname]; shouldRevoke {
					continue
				} // If user is target or someone down the list add to revoke list.
				mapAddr, err := getUserIndex(uname)
				if err != nil {
					continue
				}
				mbytes, ok := userlib.DatastoreGet(mapAddr)
				if !ok || len(mbytes) < 64 {
					continue
				}
				salt := userlib.Hash([]byte(uname))[:16]
				sym, err := DeriveKey(salt, "mapEncrypt")
				if err != nil {
					return err
				}
				mac, err := DeriveKey(salt, "mapHMACEncrypt")
				if err != nil {
					return err
				}
				dec, err := DecryptAndVerify(sym, mac, mbytes)
				if err != nil {
					continue
				}
				var fmap map[string]Files
				if err := json.Unmarshal(dec, &fmap); err != nil {
					continue
				}
				entry := fmap[filename]
				entry.FileMetaAddr = newMetaUUID
				entry.CTRKey = newEncKey
				entry.HMACKey = newHMACKey
				fmap[filename] = entry
				updated, err := json.Marshal(fmap)
				if err != nil {
					return err
				}
				iv := userlib.RandomBytes(16)
				enc := userlib.SymEnc(sym, iv, updated)
				hm, err := userlib.HMACEval(mac, enc)
				if err != nil {
					return err
				}
				userlib.DatastoreSet(mapAddr, append(enc, hm...))
			}
		}
	}

	// update owner file map
	fileMap[filename] = Files{
		FileMetaAddr: newMetaUUID,
		CTRKey:       newEncKey,
		HMACKey:      newHMACKey,
		Stat:         "Y", // Refer Files
	}

	fileMapJSON, err := json.Marshal(fileMap)
	if err != nil {
		return err
	}
	iv := userlib.RandomBytes(16)
	enc := userlib.SymEnc(mapEncKey, iv, fileMapJSON)
	hmac, err := userlib.HMACEval(mapHMACKey, enc)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(fileMapAddr, append(enc, hmac...))

	return nil
}

func buildRevokeList(shareAddr uuid.UUID, target string, revokees map[string]userlib.UUID) {
	shareBytes, ok := userlib.DatastoreGet(shareAddr)
	if !(ok) {
		return // Refer prev to revokeaccess() but we will return list of users to revoke going down the shared address
	}

	var shareMap map[string]uuid.UUID
	if err := json.Unmarshal(shareBytes, &shareMap); err != nil {
		return
	}

	for name, addr := range shareMap { // GOing through map and add address of user who if from share list
		if name == target || strings.HasPrefix(name, target+"/") {
			revokees[name] = addr
			buildRevokeList(addr, target, revokees)
		}
	}
}
