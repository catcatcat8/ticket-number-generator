#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <iomanip>

#include <openssl/sha.h>

using namespace std;

/* Получение хеша SHA-256 */
string sha256(const string str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

/* Получение варианта учеником */
int get_variant(string hash, unsigned long int code_hash, int vars) {
    string hash_b = hash.substr(0, 8);  //берем первые 8 символов хеша
    unsigned long int our_hash = stol(hash_b, 0, 16);
    unsigned long int result_hash = our_hash ^ code_hash;  //XOR с параметром распределения
    int variant = (result_hash % vars) + 1;  //получение варианта в заданном диапазоне
    return variant;
}

int main(int argc, char* argv[]) {

    if (!(string(argv[1]) == "--file" && string(argv[3]) == "--numbilets" && string(argv[5]) == "--parameter")) {
        cout << "Проверьте правильность введенных вами данных!\n";
        return 1;
    }
    string fio, path_file = argv[2];
    int numbilets = atoi(argv[4]), par = atoi(argv[6]);

    ifstream ff(path_file);
    if (!ff)  {
        cout << "Указанный файл не существует!\n";
        return 1;
    }

    string par_string = to_string(par);
    string code_hash = sha256(par_string);
    string code_hash_sub = code_hash.substr(0, 8);  // берем первые 8 символов хеша от параметра распределения
    unsigned long int our_code_hash = stol(code_hash_sub, 0, 16);  // string -> int
    while (getline(ff, fio)) {
        string fio_hash = sha256(fio);
        int cur_var = get_variant(fio_hash, our_code_hash, numbilets);
        cout << fio << ": " << cur_var << endl;
    }
    ff.close();
    return 0;
}
