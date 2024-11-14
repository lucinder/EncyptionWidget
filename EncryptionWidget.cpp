/*
@author lucinder
Encryption widget- microcode that uses a hardcoded key to encrypt or decrypt a given input string.
Intended for supplementary use in a larger project.
Currently using AES 128 with RSA.
Saves raw bytes to a .bin if encrypting, or decrypted text to a .txt if decrypting.
*/

#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <fstream>
#include <string>
#include <iomanip>
#include <direct.h>

using namespace std;

bool DEBUG = false; // debug flag for my sanity
BYTE key[] = { // extra key in case this doesn't work
    0x69, 0x20, 0x6c, 0x6f, 0x76, 0x65, 0x20, 0x73, 0x74, 0x72, 0x61, 0x79, 0x63, 0x61, 0x74, 0x6a  // key
    };
BYTE pbKeyBlob[] = { // hardcoded RSA key
    // 08 02 00 00 0e 66 00 00
    0x08,0x02,0x00,0x00,0x0e,0x66,0x00,0x00, // BLOB header 
    // 10 00 00 00 
    0x10,0x00,0x00,0x00,                     // key length, in bytes
    0x69, 0x20, 0x6c, 0x6f, 0x76, 0x65, 0x20, 0x73, 0x74, 0x72, 0x61, 0x79, 0x63, 0x61, 0x74, 0x6a  // key iv
    };
HCRYPTPROV hCryptProv = NULL;
HCRYPTKEY hKey = NULL;
const DWORD blockSize = 16; // AES block size

void PrintHex(BYTE* data, int size) {
    cout << hex << setfill('0');
    for (int i = 0; i < size; i++) {
        cout << setw(2) << static_cast<unsigned>(data[i]) << " ";
    }
    cout << ("\n");
}

void PrintLastError(){ // helper method to print system errors
    DWORD errorCode = GetLastError();
    LPSTR buf = NULL;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, errorCode, 0, buf, 0, nullptr); // err to str
    cout << "Error " << errorCode << " " << (char*)buf << endl; // print error
    LocalFree(buf);
    exit(1);
}

// encrypt and save to output buffer
bool Encrypt(HCRYPTKEY &hKey, DWORD &dwDataLen, DWORD &dwBlockLen, BYTE* &output){
    if (DEBUG) cout << "DEBUG: Entered the Encrypt method." << endl;
    if(!CryptEncrypt(hKey, 0, TRUE, 0, output, &dwDataLen, dwBlockLen)){ // encrypt our data
        cout << "An error occured when encrypting data.\n";
        PrintLastError();
        return false;
    }
    return true;
}

// decrypt and save to output buffer
bool Decrypt(HCRYPTKEY &hKey, DWORD &dwDataLen, BYTE* &output){
    if (DEBUG) cout << "DEBUG: Entered the Decrypt method." << endl;
    if(!CryptDecrypt(hKey, 0, TRUE, 0, output, &dwDataLen)){ // decrypt our data
        cout << "An error occured when decrypting data.\n";
        PrintLastError();
        return false;
    }
    return true;
}

// write a BYTE array to a file
bool ExportDataToFile(string &filename, BYTE* &pbData, DWORD &size){
    if (DEBUG) cout << "DEBUG: Entered the ExportDataToFile method." << endl;
    if (DEBUG) cout << "DEBUG: Exporting to " << filename << endl;
    ofstream outFile(filename, ios::binary); // open file
    if (!outFile) {
        cout << "An error occured when writing data to file.\n";
        PrintLastError();
        return false;
    }
    if (DEBUG) cout << "DEBUG: Export Size: 0x" << size << endl;
    outFile.write(reinterpret_cast<char*>(pbData), size);
    // outFile.write(reinterpret_cast<char*>(pbData), size); // write to file
    outFile.close();
    return true;
}

bool ImportDataFromFile(string &filename, BYTE* &pbData, DWORD &readSize){
    if (DEBUG) cout << "DEBUG: Entered the ImportDataFromFile method." << endl;
    if (DEBUG) cout << "DEBUG: Importing from " << filename << "." << endl;
    // TODO : fix soft crashing here. exits without explanation for inputs > 16 chars
    char* cwd = _getcwd(NULL, 0);
    if (DEBUG) cout << "DEBUG: Current working directory: " << cwd << endl;
    ifstream inFile(filename, ios::binary | ios::ate);
    if (DEBUG) cout << "DEBUG: Initialized input file." << endl;
    if (!inFile) {
        cout << "An error occured when opening the file " << filename << ".\n";
        PrintLastError();
        return false;
    }
    if (DEBUG) cout << "DEBUG: Successfully loaded input file." << endl;
    streamsize size = inFile.tellg();
    readSize = size;
    if (DEBUG) cout << "DEBUG: Imported File Size: " << readSize << endl;
    inFile.seekg(0, ios::beg);
    pbData = new BYTE[size];
    if (!inFile.read(reinterpret_cast<char*>(pbData), size)) {
        cout << "An error occured when reading data from file.\n";
        PrintLastError();
        inFile.close();
        return false;
    }
    inFile.close();
    return true;
}

// export key to file
bool ExportKey(HCRYPTKEY &hKey){
    if (DEBUG) cout << "DEBUG: Entered the ExportKey method." << endl;
    // get key length
    DWORD keyLength = 0;
    if (!CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, nullptr, &keyLength)) {
        cout << "An error occured when getting key size.\n";
        PrintLastError();
        return false;
    }
    // write key to file
    if (DEBUG) cout << "DEBUG: Key Length: 0x" << keyLength << endl;
    BYTE* pbData = new BYTE[keyLength];
    if (!CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, pbData, &keyLength)) {
        cout << "An error occured when exporting key to BLOB.\n";
        PrintLastError();
        return false;
    }
    cout << "Key: ";
    PrintHex(pbData, keyLength);
    string fn = "key.bin";
    if (DEBUG) cout << "DEBUG: Exporting data." << endl;
    if (!ExportDataToFile(fn, pbData, keyLength)) {
        cout << "Something went wrong while exporting data!" << endl;
        delete[] pbData;
        return false;
    }
    cout << "Exported key to file.\n";
    delete[] pbData;
    return true;
}

// import key
bool ImportKey(HCRYPTKEY &hKey){
    if (DEBUG) cout << "DEBUG: Entered the ImportKey method." << endl;
    BYTE* pbData = NULL;
    DWORD keySize = 0;
    string fn = "key.bin";
    if(!ImportDataFromFile(fn, pbData, keySize)){
        return false;
    }
    if (DEBUG) cout << "DEBUG: Imported Key: ";
    if (DEBUG) PrintHex(pbData, keySize);
    if (!CryptImportKey(hCryptProv, pbData, keySize, 0, CRYPT_EXPORTABLE, &hKey)) { // import pbdata to key object
        cout << "Failed to import key from file. Building hardcoded key instead.\n";
        if (DEBUG) cout << "DEBUG: Key size is " << sizeof(pbKeyBlob) << endl;
        if (!CryptImportKey(hCryptProv, pbKeyBlob, sizeof(pbKeyBlob), 0, CRYPT_EXPORTABLE, &hKey)) { // import pbdata to key object
            cout << "An error occured when importing data to a key object.\n";
            PrintLastError();
            delete[] pbData;
            return false;
        }
    }
    delete[] pbData;
    return true;
}

// encrypt an input string suing aes/rsa and static key, return true if successful
bool EncryptOrDecrypt(char* input, const char* mode){ 
    DWORD dwDataLen = 0;
    BYTE* inputBytes = reinterpret_cast<unsigned char*>(input);
    if(*mode == 'f'){ // read from file
        string fn = (strlen(input) > 0) ? input : "data.bin"; // get input path from argv if it exists
        if (DEBUG) cout << "DEBUG: Import Filename = " << fn <<endl;
        if(!ImportDataFromFile(fn,inputBytes,dwDataLen)){
            return false;
        }
        if (DEBUG) cout << "DEBUG: Imported Data: ";
        if (DEBUG) PrintHex(inputBytes, dwDataLen);
    } else if (*mode == 'd') {
        dwDataLen = sizeof(inputBytes) + 1;
    } else {
        dwDataLen = strlen(input) + 1;
    }
    DWORD dwBlockLen = ((dwDataLen + blockSize - 1) / blockSize) * blockSize; // get block length for encryption
    if (DEBUG) cout << "DEBUG: Data Length: 0x" << dwBlockLen << endl;
    BYTE* output = new BYTE[dwDataLen];
    memset(output, 0, dwBlockLen); // zero buffer for padding
    memcpy(output, inputBytes, dwDataLen); // copy input into the buffer

    if (DEBUG) cout << "DEBUG: Trying to get our crypt context." << endl;
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) { // try to get our key container
        cout << "An error occured when trying to set up key container.\n";
        PrintLastError();
        return false;
    }
    if (DEBUG) cout << "DEBUG: Successfully got crypt context." << endl;
    if (DEBUG) cout << "DEBUG: Trying to import key." << endl;
    if(!ImportKey(hKey)){
        // generate a new key if we don't have one already - please use this for encryption only!
        cout << "Generating a new key instead.\n";
        if (!CryptGenKey(hCryptProv, CALG_AES_128, CRYPT_EXPORTABLE, &hKey)) {
            cout << "An error occured when trying to gemerate encryption key.\n";
            PrintLastError();
            return false;
        }
        if (!CryptSetKeyParam(hKey, KP_IV, key, 0)) {
            cout << "An error occured when trying to override encryption key contents.\n";
            PrintLastError();
            return false;
        }
    }
    if (DEBUG) cout << "DEBUG: Successfully imported key." << endl;
    if (DEBUG) cout << "DEBUG: Trying to encrypt or decrypt." << endl;
    // call encrypt or decrypt
    switch(*mode){
        case 'e':
            Encrypt(hKey, dwDataLen, dwBlockLen, output);
            break;
        case 'd':
            Decrypt(hKey, dwDataLen, output);
            break;
        case 'f':
            Decrypt(hKey, dwDataLen, output);
            break;
        default:
            cout << "Invalid operation. Please choose between 'e' (encrypt), 'd' (decrypt), or 'f' (auto decrypt from file).\n";
            break;
    }

    // key exporting to file!
    if(*mode == 'e') {
        if (!ExportKey(hKey)) { 
            cout << "Something went wrong while exporting key." << endl;
            return false;
        }
    } // export key ONLY if we're encrypting

    CryptDestroyKey(hKey);
    CryptReleaseContext(hCryptProv, 0);
    cout << "Data: ";
    if(*mode == 'e'){ PrintHex(output, strlen(input)); }
    else { cout << output << endl; }

    // encrypted output export to file
    string fn = (*mode == 'e') ? "data.bin" : "data.txt";
    if (DEBUG) cout << "DEBUG: Export Filename = " << fn <<endl;
    if (!ExportDataToFile(fn, output, dwBlockLen)) return false;
    cout << "Exported data to file." << endl;
    delete[] output;
    return true;
}

// main - take in stuff from argv and send it off to encrypt/decrypt
int main(int argc, char *argv[]){
    if (argc < 2){
        cout << "Usage: EncryptionWidget <e|d|f> <input> [d]\n";
        return 0;
    }
    const char* mode = argv[1];
    char* input = (char*)(argc > 2 ? argv[2] : "");
    DEBUG = (argc > 3 && *argv[3] == 'd') ? true : false;
    EncryptOrDecrypt(input, mode);
    return 0;
}