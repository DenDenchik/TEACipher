#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
using namespace std;
const int NumRounds = 32;
const int BlockSize = 8;

//Шифрование одного блока
void encrypt(uint32_t v[2], const uint32_t key[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = 0;
    const uint32_t Delta = 0x9E3779B9;
    for (int i = 0; i < NumRounds; ++i) {
        sum += Delta;
        v0 += ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
        v1 += ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
    }
    v[0] = v0;
    v[1] = v1;
}

//Дешифровка одного блока
void decrypt(uint32_t v[2], const uint32_t key[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    const uint32_t Delta = 0x9E3779B9;
    uint32_t sum = Delta * NumRounds;
    for (int i = 0; i < NumRounds; ++i) {
        v1 -= ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
        v0 -= ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
        sum -= Delta;
    }
    v[0] = v0;
    v[1] = v1;
}

//Чтение
vector<uint8_t> readFile(const string& filename) {
    vector<uint8_t> data;
    ifstream file(filename, ios::binary);
    if (!file.is_open()) {
        throw runtime_error("Ошибка открытия файла");
    }
    file.seekg(0, ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, ios::beg);
    data.resize(fileSize);
    file.read(reinterpret_cast<char*>(data.data()), fileSize);
    if (file.fail()) {
        throw runtime_error("Ошибка чтения файла");
    }
    file.close();
    return data;
}

//Запись
void writeFile(const string& filename, const vector<uint8_t>& data) {
    ofstream file(filename, ios::binary);
    if (!file.is_open()) {
        throw runtime_error("Ошибка открытия файла");
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    if (file.fail()) {
        throw runtime_error("Ошибка записи файла");
    }
    file.close();
}

//Шифрование всего сообщения
vector<uint8_t> encryptMessage(const vector<uint32_t>& key) {
    string inputFilename = "input.txt";
    vector<uint8_t> data = readFile(inputFilename);
    size_t paddedSize = (data.size() + (BlockSize - 1)) / BlockSize * BlockSize;
    data.resize(paddedSize);
    for (size_t i = 0; i < data.size(); i += BlockSize) {
        uint32_t* block = reinterpret_cast<uint32_t*>(&data[i]);
        encrypt(block, key.data());
    }
    return data;
}

//Дешифровка всего сообщения
vector<uint8_t> decryptMessage(const vector<uint32_t>& key) {
    string inputFilename = "encrypted.txt";
    vector<uint8_t> data = readFile(inputFilename);
    for (size_t i = 0; i < data.size(); i += BlockSize) {
        uint32_t* block = reinterpret_cast<uint32_t*>(&data[i]);
        decrypt(block, key.data());
    }
    while (!data.empty() && data.back() == 0)
        data.pop_back();
    return data;
}

//Чтение ключа
vector<uint32_t> readKey(const string& filename) {
    vector<uint32_t> keyData;
    ifstream file(filename, ios::binary);
    if (!file.is_open()) {
        throw runtime_error("Ошибка открытия файла с ключом");
    }
    while (!file.eof()) {
        uint32_t keyPart;
        file.read(reinterpret_cast<char*>(&keyPart), sizeof(keyPart));
        keyData.push_back(keyPart);
    }
    file.close();
    return keyData;
}

int main() {
    setlocale(LC_ALL, "Russian");
    string keyFilename = "key.txt";
    try {
        vector<uint32_t> key = readKey(keyFilename);
        vector<uint8_t> data = encryptMessage(key);
        writeFile("encrypted.txt", data);
        cout << "Сообщение зашифровано в файл encrypted.txt." << endl;
        data = decryptMessage(key);
        writeFile("decrypted.txt", data);
        cout << "Сообщение расшифровано в файл decrypted.txt." << endl;
    }
    catch (const exception& e) {
        cerr << "Ошибка: " << e.what() << endl;
    }
    system("pause");
    return 0;
}
