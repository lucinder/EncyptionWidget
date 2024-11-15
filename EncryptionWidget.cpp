/*
@author lucinder
Encryption widget- microcode that uses a hardcoded key to encrypt or decrypt a given input string.
Intended for supplementary use in a larger project.
Currently using AES 128 with RSA.
Saves raw bytes to a .bin if encrypting, or decrypted text to a .txt if decrypting.
*/

#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <windows.h>
#include <wincrypt.h>

using namespace std;

bool DEBUG = false; // debug flag for my sanity
BYTE keyIV[] = { // extra key in case this doesn't work
    0x69, 0x20, 0x6c, 0x6f, 0x76, 0x65, 0x20, 0x73, 0x74, 0x72, 0x61, 0x79, 0x63, 0x61, 0x74, 0x6a  // key
    };
BYTE pbKeyBlob[] = { // hardcoded RSA key
    // 08 02 00 00 0e 66 00 00
    0x08,0x02,0x00,0x00,0x0e,0x66,0x00,0x00, // BLOB header 
    // 10 00 00 00 
    0x10,0x00,0x00,0x00,                     // key length, in bytes
    0x69, 0x20, 0x6c, 0x6f, 0x76, 0x65, 0x20, 0x73, 0x74, 0x72, 0x61, 0x79, 0x63, 0x61, 0x74, 0x6a  // key iv
    };

struct aes128keyBlob
{
    BLOBHEADER hdr;
    DWORD keySize;
    BYTE bytes[16];
} blob;

const DWORD blockSize = 16; // AES block size
DWORD keyLength = 28; // key length - hardcoded here
string keyFilePath = "key.bin";
string dataBinFilePath = "data.bin";
string dataTxtFilePath = "data.txt";

// helper method to print a BYTE array as hex
void PrintHex(BYTE* data, int size) {
    cout << hex << setfill('0');
    for (int i = 0; i < size; i++) {
        cout << setw(2) << static_cast<unsigned>(data[i]);
    }
    cout << ("\n");
}

// helper method to print system errors
void PrintLastError(){
    DWORD errorCode = GetLastError();
    LPSTR buf = NULL;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, errorCode, 0, buf, 0, nullptr); // err to str
    cout << "Error " << errorCode << " " << (char*)buf << endl; // print error
    LocalFree(buf);
    // exit(1);
}

HCRYPTPROV GetCryptContext(){
    HCRYPTPROV hCryptProv = NULL;
    if (DEBUG) cout << "DEBUG: Trying to get our crypt context." << endl;
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { // try to get our key container
        cout << "ERROR: An error occured when trying to set up key container." << endl;
        PrintLastError();
        return NULL;
    }
    if (DEBUG) cout << "DEBUG: Successfully got crypt context." << endl;
    return hCryptProv;
}

HCRYPTKEY GetKey(HCRYPTPROV &hCryptProv){
    HCRYPTKEY hKey = NULL;
    blob.hdr.bType = PLAINTEXTKEYBLOB;
    blob.hdr.bVersion = CUR_BLOB_VERSION;
    blob.hdr.reserved = 0;
    blob.hdr.aiKeyAlg = CALG_AES_128;
    blob.keySize = 16;
    memcpy(blob.bytes, keyIV, 16);
    if (!CryptImportKey(hCryptProv, (BYTE*)&blob, sizeof(aes128keyBlob), NULL, CRYPT_EXPORTABLE, &hKey)) {
        cout << "ERROR: An error occured when trying to gemerate encryption key." << endl;
        PrintLastError();
        return NULL;
    }
    if (!CryptSetKeyParam(hKey, KP_IV, keyIV, 0)) {
        cout << "ERROR: An error occured when trying to override encryption key contents." << endl;
        PrintLastError();
        return NULL;
    }
    if (DEBUG) cout << "DEBUG: Successfully got our key." << endl;
    return hKey;
}

// encrypt and save to output buffer
bool Encrypt(HCRYPTKEY &hKey, DWORD &dwDataLen, DWORD &dwBlockLen, BYTE* &pbData){
    if (DEBUG) cout << "DEBUG: Entered the Encrypt method." << endl;
    if(!CryptEncrypt(hKey, 0, TRUE, 0, pbData, &dwDataLen, dwBlockLen)){ // encrypt our data
        cout << "ERROR: An error occured when encrypting data." << endl;
        PrintLastError();
        return false;
    }
    return true;
}

// decrypt and save to output buffer
bool Decrypt(HCRYPTKEY &hKey, DWORD &dwDataLen, BYTE* &pbData){
    if (DEBUG) cout << "DEBUG: Entered the Decrypt method." << endl;
    if (DEBUG) cout << "DEBUG: Bytes to decrypt: 0x" << dwDataLen << endl;
    if(!CryptDecrypt(hKey, 0, TRUE, 0, pbData, &dwDataLen)){ // decrypt our data
        cout << "ERROR: An error occured when decrypting data." << endl;
        PrintLastError();
        return false;
    }
    if (DEBUG) cout << "DEBUG: Buffer after decrypting: ";
    if (DEBUG) PrintHex(pbData, dwDataLen);
    return true;
}

// encrypt an input string suing aes/rsa and static key, return true if successful
bool EncryptOrDecrypt(char* &input, const char* &mode){ 
    DWORD dwDataLen = 0;
    DWORD dwBlockLen = 0;
    string inputStr = input;
    BYTE* inputBytes;
    if(*mode == 'd'){ // decryption from raw text requires conversion to hex first
        memset(input, 0, inputStr.length()); // zero our input
        for(int i = 0; i < inputStr.length(); i+=2){
            string byteStr = inputStr.substr(i, 2);
            char byte = (char)strtol(byteStr.c_str(), NULL, 16);
            input[i/2] = byte; // set byte of input
        }
        inputStr = input; // reset input string
        inputBytes = reinterpret_cast<BYTE*>(input);
        if (DEBUG) cout << "DEBUG: Bytes read from argv: ";
        if (DEBUG) PrintHex(inputBytes, inputStr.size());
        dwDataLen = inputStr.size();
    } else {
        inputBytes = reinterpret_cast<unsigned char*>(input);
        dwDataLen = strlen(input);
        // if(dwDataLen % 16 == 0) dwDataLen--;
    }

    if (DEBUG) cout << "DEBUG: Data bytes: ";
    if (DEBUG) PrintHex(inputBytes, dwDataLen);
    if (DEBUG) cout << "DEBUG: Data Length: 0x" << dwDataLen << endl;
    // DWORD dwBlockLen = dwDataLen % 16 == 0 ? dwDataLen + 16 : ((dwDataLen + blockSize - 1) / blockSize) * blockSize; // get block length for encryption
    // trying something else for padding
    DWORD padLen = blockSize - (dwDataLen % blockSize);
    if (*mode == 'e'){ // only add padding if we are encrypting
        if (padLen == 0) {
            padLen = blockSize;  // If data length is already a multiple, add one block of padding
        }
        dwBlockLen = dwDataLen + padLen;
        if (DEBUG) cout << "DEBUG: Buffer Length: 0x" << dwBlockLen << endl;
    } else {
        dwBlockLen = dwDataLen;
    }
    
    BYTE* output = new BYTE[dwBlockLen];
    memset(output, 0x00, dwBlockLen); // zero buffer for padding
    memcpy(output, inputBytes, dwDataLen); // copy input into the buffer
    if (DEBUG) cout << "DEBUG: Buffer to encrypt/decrypt: ";
    if (DEBUG) PrintHex(output, dwBlockLen);
    delete[] inputBytes;

    // get context
    HCRYPTPROV hCryptProv = GetCryptContext();

    // get key
    HCRYPTKEY hKey = GetKey(hCryptProv);
    
    if (DEBUG) cout << "DEBUG: Trying to encrypt or decrypt." << endl;
    // call encrypt or decrypt
    switch(*mode){
        case 'e':
            Encrypt(hKey, dwDataLen, dwBlockLen, output);
            break;
        case 'd':
            Decrypt(hKey, dwBlockLen, output);
            break;
        default:
            cout << "ERROR: Invalid operation. Please choose between 'e' (encrypt) or 'd' (decrypt)." << endl;
            break;
    }
    if (DEBUG) cout << "DEBUG: Successfully encrypted or decrypted data." << endl;

    cout << "Data: ";
    if(*mode == 'e'){ PrintHex(output, dwBlockLen); }
    else { cout << string((char*)output, dwBlockLen) << endl; }

    CryptDestroyKey(hKey);
    CryptReleaseContext(hCryptProv, 0);
    delete[] output;
    return true;
}

// main - take in stuff from argv and send it off to encrypt/decrypt
int main(int argc, char* argv[]){
    if (argc < 2){
        cout << "Usage: EncryptionWidget <e|d> <input> [d]" << endl;
        return 0;
    }
    const char* mode = argv[1];
    char* input = (char*)(argc > 2 ? argv[2] : "");
    DEBUG = (argc > 3 && *argv[3] == 'd') ? true : false;
    EncryptOrDecrypt(input, mode);
    return 0;
}