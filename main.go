package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
)

func xorBytesAndShift(block, key []byte, shiftBits uint) []byte {
	result := make([]byte, len(block))
	for i := range block {
		xored := block[i] ^ key[i%len(key)]
		result[i] = (xored << shiftBits) | (xored >> (8 - shiftBits))
	}
	return result
}

func xorBytesAndUnshift(block, key []byte, shiftBits uint) []byte {
	result := make([]byte, len(block))
	for i := range block {
		unshifted := (block[i] >> shiftBits) | (block[i] << (8 - shiftBits))
		result[i] = unshifted ^ key[i%len(key)]
	}
	return result
}

func cbcEncrypt(plaintext, key, iv []byte, shiftBits uint) []byte {
	blockSize := len(key)
	plaintext = pkcs7Pad(plaintext, blockSize)
	ciphertext := make([]byte, len(plaintext))

	prev := iv
	for i := 0; i < len(plaintext); i += blockSize {
		block := plaintext[i : i+blockSize]
		block = xorBytesAndShift(block, prev, shiftBits)
		block = xorBytesAndShift(block, key, shiftBits)
		copy(ciphertext[i:i+blockSize], block)
		prev = block
	}

	return ciphertext
}

func cbcDecrypt(ciphertext, key, iv []byte, shiftBits uint) []byte {
	blockSize := len(key)
	plaintext := make([]byte, len(ciphertext))

	prev := iv
	for i := 0; i < len(ciphertext); i += blockSize {
		block := ciphertext[i : i+blockSize]
		decrypted := xorBytesAndUnshift(block, key, shiftBits)
		decrypted = xorBytesAndUnshift(decrypted, prev, shiftBits)
		copy(plaintext[i:i+blockSize], decrypted)
		prev = block
	}

	return pkcs7Unpad(plaintext)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) []byte {
	length := len(data)
	unpadding := int(data[length-1])
	return data[:(length - unpadding)]
}

type EncryptRequest struct {
	Plaintext string `json:"plaintext"`
	Key       string `json:"key"`
	IV        string `json:"iv"`
	ShiftBits uint   `json:"shiftBits"`
	KeyLength int    `json:"keyLength"`
	IVLength  int    `json:"ivLength"`
}

type DecryptRequest struct {
	Ciphertext string `json:"ciphertext"`
	Key        string `json:"key"`
	IV         string `json:"iv"`
	ShiftBits  uint   `json:"shiftBits"`
}

type Response struct {
	Result string `json:"result"`
	Key    string `json:"key,omitempty"`
	IV     string `json:"iv,omitempty"`
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	var req EncryptRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.KeyLength <= 0 || req.IVLength <= 0 {
		http.Error(w, "Key and IV lengths must be positive", http.StatusBadRequest)
		return
	}

	var key, iv []byte
	var keyStr, ivStr string

	if req.Key == "" {
		key, err = generateRandomBytes(req.KeyLength)
		if err != nil {
			http.Error(w, "Failed to generate random key", http.StatusInternalServerError)
			return
		}
		keyStr = hex.EncodeToString(key)
	} else {
		key, err = hex.DecodeString(req.Key)
		if err != nil || len(key) != req.KeyLength {
			http.Error(w, "Invalid key", http.StatusBadRequest)
			return
		}
		keyStr = req.Key
	}

	if req.IV == "" {
		iv, err = generateRandomBytes(req.IVLength)
		if err != nil {
			http.Error(w, "Failed to generate random IV", http.StatusInternalServerError)
			return
		}
		ivStr = hex.EncodeToString(iv)
	} else {
		iv, err = hex.DecodeString(req.IV)
		if err != nil || len(iv) != req.IVLength {
			http.Error(w, "Invalid IV", http.StatusBadRequest)
			return
		}
		ivStr = req.IV
	}

	plaintext := []byte(req.Plaintext)
	ciphertext := cbcEncrypt(plaintext, key, iv, req.ShiftBits)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{
		Result: hex.EncodeToString(ciphertext),
		Key:    keyStr,
		IV:     ivStr,
	})
}

func decryptHandler(w http.ResponseWriter, r *http.Request) {
	var req DecryptRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	key, err := hex.DecodeString(req.Key)
	if err != nil {
		http.Error(w, "Invalid key", http.StatusBadRequest)
		return
	}

	iv, err := hex.DecodeString(req.IV)
	if err != nil {
		http.Error(w, "Invalid IV", http.StatusBadRequest)
		return
	}

	ciphertext, err := hex.DecodeString(req.Ciphertext)
	if err != nil {
		http.Error(w, "Invalid ciphertext", http.StatusBadRequest)
		return
	}

	plaintext := cbcDecrypt(ciphertext, key, iv, req.ShiftBits)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{Result: string(plaintext)})
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tmpl := template.Must(template.New("index").Parse(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CBC Encryption with Bit Shifting</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-100 p-8">
    <div class="max-w-2xl mx-auto bg-white p-6 rounded-lg shadow-md">
        <h1 class="text-2xl font-bold mb-4">CBC Encryption with Bit Shifting</h1>
        <div class="space-y-4">
            <div>
                <label for="plaintext" class="block text-sm font-medium text-gray-700">Plaintext</label>
                <input type="text" id="plaintext" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50">
            </div>
            <div>
                <label for="keyLength" class="block text-sm font-medium text-gray-700">Key Length (bytes)</label>
                <input type="number" id="keyLength" value="16" min="1" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50">
            </div>
            <div>
                <label for="key" class="block text-sm font-medium text-gray-700">Key (hex, leave empty for random)</label>
                <input type="text" id="key" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50">
            </div>
            <div>
                <label for="ivLength" class="block text-sm font-medium text-gray-700">IV Length (bytes)</label>
                <input type="number" id="ivLength" value="16" min="1" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50">
            </div>
            <div>
                <label for="iv" class="block text-sm font-medium text-gray-700">IV (hex, leave empty for random)</label>
                <input type="text" id="iv" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50">
            </div>
            <div>
                <label for="shiftBits" class="block text-sm font-medium text-gray-700">Shift Bits</label>
                <input type="number" id="shiftBits" min="0" max="7" value="1" class="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-indigo-300 focus:ring focus:ring-indigo-200 focus:ring-opacity-50">
            </div>
            <div class="flex space-x-2">
                <button onclick="encrypt()" class="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-opacity-50">Encrypt</button>
                <button onclick="decrypt()" class="px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600 focus:outline-none focus:ring-2 focus:ring-green-500 focus:ring-opacity-50">Decrypt</button>
            </div>
            <div>
                <label for="ciphertext" class="block text-sm font-medium text-gray-700">Ciphertext (Hex)</label>
                <input type="text" id="ciphertext" readonly class="mt-1 block w-full rounded-md border-gray-300 bg-gray-100 shadow-sm">
            </div>
            <div>
                <label for="decryptedText" class="block text-sm font-medium text-gray-700">Decrypted Text</label>
                <input type="text" id="decryptedText" readonly class="mt-1 block w-full rounded-md border-gray-300 bg-gray-100 shadow-sm">
            </div>
        </div>
    </div>
    <script>
        async function encrypt() {
            const response = await fetch('/encrypt', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    plaintext: document.getElementById('plaintext').value,
                    key: document.getElementById('key').value,
                    iv: document.getElementById('iv').value,
                    shiftBits: parseInt(document.getElementById('shiftBits').value),
                    keyLength: parseInt(document.getElementById('keyLength').value),
                    ivLength: parseInt(document.getElementById('ivLength').value),
                }),
            });
            const data = await response.json();
            document.getElementById('ciphertext').value = data.result;
            if (data.key) document.getElementById('key').value = data.key;
            if (data.iv) document.getElementById('iv').value = data.iv;
        }

        async function decrypt() {
            const response = await fetch('/decrypt', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    ciphertext: document.getElementById('ciphertext').value,
                    key: document.getElementById('key').value,
                    iv: document.getElementById('iv').value,
                    shiftBits: parseInt(document.getElementById('shiftBits').value),
                }),
            });
            const data = await response.json();
            document.getElementById('decryptedText').value = data.result;
        }
    </script>
</body>
</html>
		`))
		tmpl.Execute(w, nil)
	})

	http.HandleFunc("/encrypt", encryptHandler)
	http.HandleFunc("/decrypt", decryptHandler)

	fmt.Println("Server is running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
