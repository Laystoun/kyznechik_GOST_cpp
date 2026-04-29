#include <iostream>
#include <string>
#include <fstream>
#include <cassert>
#include <array>
#include <chrono>
#include "pkcs.h"
#include "kyznechik.h"
#include <omp.h>
#include <clocale>
#include <filesystem>
#include <random>
#include "SHA256.h"

#ifdef _WIN32
    #include <io.h>
    #include <fcntl.h>
#endif

#include <cwctype>
#include <algorithm>

template <bool with_logs>
void encrypt_file(Kyznechik &kyz, std::wstring drop_path = L"-1")
{
    #ifdef _WIN32
        _setmode(_fileno(stdin), _O_U16TEXT);
    #endif

    std::wstring path;
    std::filesystem::path correct_path;

    if (drop_path == L"-1") {
        std::wcout << "enter PATH #: ";
        std::getline(std::wcin, path);
        correct_path = std::filesystem::path(path);
    } else {
        correct_path = drop_path;
    }

    {
        std::ifstream in{correct_path, std::ios::binary};

        std::filesystem::path outpath = std::filesystem::path(correct_path);
        outpath += L".enc";
        std::fstream out{outpath, std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc};
        assert(in && "In file not found");
        
        std::wcout << "Start encrypt...\n";

        std::vector<uint8_t> buffer(256 * 1024 * 1024);

        double total_sec_time;
        std::chrono::duration<double> total_encrypted_time;
        double encrypted_bytes_handl;
        std::chrono::high_resolution_clock::time_point start_program;
        std::chrono::high_resolution_clock::time_point start;

        if constexpr (with_logs)
        {
            total_sec_time = 0;
            total_encrypted_time = std::chrono::duration<double>::zero();
            encrypted_bytes_handl = 0;
            start_program = std::chrono::high_resolution_clock::now();
        }

        while (in.read(reinterpret_cast<char *>(buffer.data()), buffer.size()) || in.gcount() > 0)
        {
            size_t read_bytes = in.gcount();

            if (in.eof())
            {
                buffer.resize(read_bytes);
                pkcspad(buffer);
                read_bytes = buffer.size();
            }

            if constexpr (with_logs)
            {
                start = std::chrono::high_resolution_clock::now();
            }
#pragma omp parallel for
            for (size_t i = 0; i < read_bytes; i += 128)
            {
                kyz.encrypt_block(buffer.data() + i);
            }

            if constexpr (with_logs)
            {
                auto end = std::chrono::high_resolution_clock::now();
                total_encrypted_time += (end - start);
                encrypted_bytes_handl += read_bytes;
            }

            out.write(reinterpret_cast<char *>(buffer.data()), read_bytes);
        }

        in.close();
        out.close();
        std::filesystem::remove(correct_path);

        if constexpr (with_logs)
        {
            auto end_program = std::chrono::high_resolution_clock::now();

            std::chrono::duration<double> total_program_time = end_program - start_program;
            std::wcout << "Program time (s): " << total_program_time.count() << std::endl
                       << "Encrypted SPEED MB/s: " << (encrypted_bytes_handl / (1024 * 1024)) / total_encrypted_time.count() << std::endl
                       << "Encrypted TIME (s): " << total_encrypted_time.count() << std::endl;
        }

        std::wcout << "Directory success encrypted. Close program.\n";
    }
}

template <bool with_logs>
void encrypt_directory(Kyznechik &kyz, std::wstring drop_path = L"-1")
{
    #ifdef _WIN32
        _setmode(_fileno(stdin), _O_U16TEXT);
        _setmode(_fileno(stdout), _O_U16TEXT);
    #endif
    std::filesystem::path correct_path;

    if(drop_path == L"-1") {
        std::wcout << "enter DIRECTORY #: ";
        std::wstring directory;
        std::getline(std::wcin, directory);
        correct_path = std::filesystem::path(directory);
    } else {
        correct_path = drop_path;
    }

    double total_sec_time;
    std::chrono::duration<double> total_encrypted_time;
    double encrypted_bytes_handl;
    std::chrono::high_resolution_clock::time_point start_program;
    std::chrono::high_resolution_clock::time_point start;

    if constexpr (with_logs)
    {
        total_sec_time = 0;
        total_encrypted_time = std::chrono::duration<double>::zero();
        encrypted_bytes_handl = 0;
        start_program = std::chrono::high_resolution_clock::now();
    }
    std::wcout << "Start encrypt...\n";
    for (auto &path : std::filesystem::recursive_directory_iterator(correct_path))
    {
        if (path.is_regular_file() && path.path().extension() != ".enc")
        {
            if constexpr (with_logs)
            {
                start_program = std::chrono::high_resolution_clock::now();
            }

            std::ifstream this_file(path.path(), std::ios::binary);
            std::ofstream out(path.path().parent_path() /= path.path().filename() += ".enc", std::ios::binary);

            assert(this_file && "Error open file...");

            std::vector<uint8_t> buffer(256 * 1024 * 1024);

            while (this_file.read(reinterpret_cast<char *>(buffer.data()), buffer.size()) || this_file.gcount() > 0)
            {
                size_t read_bytes = this_file.gcount();

                if (this_file.eof())
                {
                    buffer.resize(read_bytes);
                    pkcspad(buffer);
                    read_bytes = buffer.size();
                }

                if constexpr (with_logs)
                {
                    start = std::chrono::high_resolution_clock::now();
                }

                #pragma omp parallel for
                for (size_t i = 0; i < read_bytes; i += 128)
                {
                    kyz.encrypt_block(buffer.data() + i);
                }

                if constexpr (with_logs)
                {
                    std::wcout << "has been encrypted: " << path.path() << std::endl;
                }

                if constexpr (with_logs)
                {
                    auto end = std::chrono::high_resolution_clock::now();
                    total_encrypted_time += (end - start);
                    encrypted_bytes_handl += read_bytes;
                }

                out.write(reinterpret_cast<char *>(buffer.data()), read_bytes);    
            }
            this_file.close();
            out.close();
            std::filesystem::remove(path.path());
        }
    }

    if constexpr (with_logs)
    {
        auto end_program = std::chrono::high_resolution_clock::now();

        std::chrono::duration<double> total_program_time = end_program - start_program;
        std::wcout << "Program time (s): " << total_program_time.count() << std::endl
                   << "Encrypted SPEED MB/s: " << (encrypted_bytes_handl / (1024 * 1024)) / total_encrypted_time.count() << std::endl
                   << "Encrypted TIME (s): " << total_encrypted_time.count() << std::endl;
    }
    std::wcout << "Directory success encrypted. Close program.\n";
}

template <bool with_logs>
void decrypt_file(Kyznechik& kyz, std::wstring drop_path = L"-1") {
    #ifdef _WIN32
        _setmode(_fileno(stdin), _O_U16TEXT);
    #endif

    std::wstring path;
    std::filesystem::path correct_path;

    if (drop_path == L"-1") {
        std::wcout << "enter PATH #: ";
        std::getline(std::wcin, path);
        correct_path = std::filesystem::path(path);
    } else {
        correct_path = drop_path;
    }

    {
        std::ifstream in{correct_path, std::ios::binary};

        std::filesystem::path outpath = std::filesystem::path(correct_path).replace_extension();
        std::fstream out{outpath, std::ios::binary | std::ios::in | std::ios::out | std::ios::trunc};
        assert(in && "In file not found");
        
        std::wcout << "Start decrypt...\n";

        std::vector<uint8_t> buffer(256 * 1024 * 1024);

        double total_sec_time;
        std::chrono::duration<double> total_encrypted_time;
        double encrypted_bytes_handl;
        std::chrono::high_resolution_clock::time_point start_program;
        std::chrono::high_resolution_clock::time_point start;

        if constexpr (with_logs)
        {
            total_sec_time = 0;
            total_encrypted_time = std::chrono::duration<double>::zero();
            encrypted_bytes_handl = 0;
            start_program = std::chrono::high_resolution_clock::now();
        }

        while (in.read(reinterpret_cast<char *>(buffer.data()), buffer.size()) || in.gcount() > 0)
        {
            size_t read_bytes = in.gcount();

            bool is_last = in.eof();

            if constexpr (with_logs)
            {
                start = std::chrono::high_resolution_clock::now();
            }
#pragma omp parallel for
            for (size_t i = 0; i < read_bytes; i += 16)
            {
                kyz.decrypt_block(buffer.data() + i);
            }

            if (is_last)
            {
                buffer.resize(read_bytes);
                pkcsunpad(buffer);
                read_bytes = buffer.size();
            }

            if constexpr (with_logs)
            {
                auto end = std::chrono::high_resolution_clock::now();
                total_encrypted_time += (end - start);
                encrypted_bytes_handl += read_bytes;
            }

            out.write(reinterpret_cast<char *>(buffer.data()), read_bytes);
        }

        in.close();
        out.close();
        std::filesystem::remove(correct_path);

        if constexpr (with_logs)
        {
            auto end_program = std::chrono::high_resolution_clock::now();

            std::chrono::duration<double> total_program_time = end_program - start_program;
            std::wcout << "Program time (s): " << total_program_time.count() << std::endl
                       << "Decrypt SPEED MB/s: " << (encrypted_bytes_handl / (1024 * 1024)) / total_encrypted_time.count() << std::endl
                       << "Decrypt TIME (s): " << total_encrypted_time.count() << std::endl;
        }

        std::wcout << "File success encrypted. Close program.\n";
    }
}

template <bool with_logs>
void decrypt_directory(Kyznechik &kyz, std::wstring drop_path = L"-1")
{
    #ifdef _WIN32
        _setmode(_fileno(stdin), _O_U16TEXT);
        _setmode(_fileno(stdout), _O_U16TEXT);
    #endif
    std::filesystem::path correct_path;

    if(drop_path == L"-1") {
        std::wcout << "enter DIRECTORY #: ";
        std::wstring directory;
        std::getline(std::wcin, directory);
        correct_path = std::filesystem::path(directory);
    } else {
        correct_path = drop_path;
    }

    double total_sec_time;
    std::chrono::duration<double> total_encrypted_time;
    double encrypted_bytes_handl;
    std::chrono::high_resolution_clock::time_point start_program;
    std::chrono::high_resolution_clock::time_point start;

    if constexpr (with_logs)
    {
        total_sec_time = 0;
        total_encrypted_time = std::chrono::duration<double>::zero();
        encrypted_bytes_handl = 0;
        start_program = std::chrono::high_resolution_clock::now();
    }
    std::wcout << "Start decrypt...\n";
    for (auto &path : std::filesystem::recursive_directory_iterator(correct_path))
    {
        if (path.is_regular_file() && path.path().extension() == ".enc")
        {
            if constexpr (with_logs)
            {
                start_program = std::chrono::high_resolution_clock::now();
            }

            std::ifstream this_file(path.path(), std::ios::binary);
            std::ofstream out(path.path().parent_path() /= path.path().stem(), std::ios::binary);

            assert(this_file && "Error open file...");

            std::vector<uint8_t> buffer(256 * 1024 * 1024);

            while (this_file.read(reinterpret_cast<char *>(buffer.data()), buffer.size()) || this_file.gcount() > 0)
            {
                size_t read_bytes = this_file.gcount();
                bool is_last = this_file.eof();

                if constexpr (with_logs)
                {
                    start = std::chrono::high_resolution_clock::now();
                }

                #pragma omp parallel for
                for (size_t i = 0; i < read_bytes; i += 16)
                {
                    kyz.decrypt_block(buffer.data() + i);
                }

                if (is_last)
                {
                    buffer.resize(read_bytes);
                    pkcsunpad(buffer);
                    read_bytes = buffer.size();
                }

                if constexpr (with_logs)
                {
                    std::wcout << "has been decrypted: " << path.path() << std::endl;
                }

                if constexpr (with_logs)
                {
                    auto end = std::chrono::high_resolution_clock::now();
                    total_encrypted_time += (end - start);
                    encrypted_bytes_handl += read_bytes;
                }

                out.write(reinterpret_cast<char *>(buffer.data()), read_bytes);
            }
        
            this_file.close();
            out.close();
            std::filesystem::remove(path.path());
        }
    }

    if constexpr (with_logs)
    {
        auto end_program = std::chrono::high_resolution_clock::now();

        std::chrono::duration<double> total_program_time = end_program - start_program;
        std::wcout << "Program time (s): " << total_program_time.count() << std::endl
                   << "Decrypt SPEED MB/s: " << (encrypted_bytes_handl / (1024 * 1024)) / total_encrypted_time.count() << std::endl
                   << "Decrypt TIME (s): " << total_encrypted_time.count() << std::endl;
    }
    std::wcout << "Directory success decrypted. Close program.\n";
}

void print_rounded_keys(Kyznechik& kyz) {
        
        std::wcout << "MASTER KEY: ";
        for (int m_key = 0; m_key < 32; m_key++) {
            std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(kyz.master_key[m_key]);
        }
        std::wcout << std::endl << std::endl;
    
        std::wcout << "Rounded keys: \n"
                   << std::endl;

        for (int i = 0; i < 10; i++)
        {
            std::wcout << i << ": ";
            for (int j = 0; j < 16; j++)
            {
                std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(kyz.ROUND_KEYS[i][j]);
            }
            std::wcout << std::endl;
        }
        std::wcout << std::endl;
}

void create_pbkdf_password(Kyznechik& kyz, bool is_decrypt) {
            
    #ifdef _WIN32
        _setmode(_fileno(stdin), _O_U16TEXT);
    #endif

    std::wcin.ignore(std::numeric_limits<std::streamsize>::max(), L'\n');
    std::wcin.clear();

    std::array<uint8_t, 32> this_hash = {0};
    std::wcout << "Password: ";
    std::wstring wpassword;
    std::getline(std::wcin, wpassword);
    std::string password (wpassword.begin(), wpassword.end());
    if (is_decrypt) {
        std::string d_pass = password.substr(0, password.size() - 64);
        std::string d_salt = password.substr(password.size() - 64);
        // 
        d_pass.append(d_salt.begin(), d_salt.end());
        std::wcout << "Hashing password and salt (PIM => 500.000 iterations)" << std::endl;
        
        SHA256 sha;
        for (int i = 0; i < 500000; i++) {
            if (i == 0) {
                sha.update(d_pass);
            } else {
                std::string this_hex = SHA256::toString(this_hash);
                sha.update(this_hex);
            }
            this_hash = sha.digest();
        }
        for (int f_key = 0; f_key < 32; f_key++) {
            kyz.master_key[f_key] = this_hash[f_key];
        }
        kyz.init();
        
        std::wcin.ignore(std::numeric_limits<std::streamsize>::max(), L'\n');
        std::wcin.clear();

        return;
    } else {
        std::random_device rd;
        SHA256 sha;
        std::vector<uint8_t> d_salt(32);
        std::string d_pass {password.begin(), password.end()};
        std::string d_salt_hex;
        for (int s_fill = 0; s_fill < 32; s_fill++) {
            d_salt[s_fill] = static_cast<uint8_t>(rd());
            std::ostringstream oss;
            oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(d_salt[s_fill]);
            d_salt_hex += oss.str();
        }
        d_pass.append(d_salt_hex);
        std::wcout << "Hashing password and salt (PIM => 500.000 iterations)" << std::endl;
        for (int h = 0; h < 500000; h++) {
            if (h == 0) {
                sha.update(d_pass);
            } else {
                std::string this_hex = SHA256::toString(this_hash);
                sha.update(this_hex);
            }
            this_hash = sha.digest();
        }
        for (int m_key = 0; m_key < 32; m_key++) {
            kyz.master_key[m_key] = this_hash[m_key];
        }
        
        std::wcin.ignore(std::numeric_limits<std::streamsize>::max(), L'\n');
        std::wcin.clear();
        // 9342565319640as@b89921dc166a49fae43bfb055f00367213c280a5f6b773929193c77deb76888c
        kyz.init();
        
        std::wcout << "Save for decrypt: " << wpassword;
        std::wcout << std::wstring(d_salt_hex.begin(), d_salt_hex.end());
        std::wcout << std::endl << std::endl;
    }
}

#ifdef _WIN32
int wmain(int argc, wchar_t *argv[])
#else
int main(int argc, char *argv[])
#endif
{
    setlocale(LC_ALL, "");
    #ifdef _WIN32
        _setmode(_fileno(stdin), _O_U16TEXT);
        _setmode(_fileno(stdout), _O_U16TEXT);
    #endif
    
    Kyznechik kyz;
    
    kyz.init();

    if (argc > 1) {
        std::wstring drop_logs;
        std::wcout << "With logs? (Y/N): ";
        std::wcin >> drop_logs;
        std::wcin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        bool is_logs = false;
        std::transform(drop_logs.begin(), drop_logs.end(), drop_logs.begin(), [](wchar_t c) { return std::towlower(c); });

        is_logs = (drop_logs == L"y" ? true : false);
        std::filesystem::path drop_path(argv[1]);

        if(!std::filesystem::exists(drop_path)) {
            std::cout << "Path don't exists...";
            return -1;
        }

        if(std::filesystem::is_directory(drop_path)) {
            if(is_logs) {
                create_pbkdf_password(kyz, false);
                print_rounded_keys(kyz);
                encrypt_directory<true>(kyz, drop_path.wstring());
            } else {
                create_pbkdf_password(kyz, false);
                std::wcout << "Start encrypt...\n";
                encrypt_directory<false>(kyz, drop_path.wstring());
                std::wcout << "Encrypt end. Close program";
            }
        } else if (std::filesystem::is_regular_file(drop_path)) {
            if(is_logs) {
                create_pbkdf_password(kyz, false);
                print_rounded_keys(kyz);
                std::wcout << "Start encrypt file...\n";
                encrypt_file<true>(kyz, drop_path.wstring());
                std::wcout << "End encrypt... Close program.";
            } else {
                create_pbkdf_password(kyz, false);
                std::wcout << "Start encrypt file...\n";
                encrypt_file<false>(kyz, drop_path.wstring());
                std::wcout << "End encrypt file. Close program.";
            }
        }
    }
    else
    {
        //print_rounded_keys(kyz);
        std::wstring select;
        std::wcout << L"<=== ENCRYPT ===>\n\n1. File\n2. Directory\n\n<=== DECRYPT ===>\n\n3. File\n4. Directory\n\n( 1/2/3/4 ): ";

        std::getline(std::wcin, select);
        //std::wcin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (select == L"1")
        {
            create_pbkdf_password(kyz, false);
            print_rounded_keys(kyz);
            encrypt_file<true>(kyz);
        }
        if (select == L"2")
        {
            create_pbkdf_password(kyz, false);
            print_rounded_keys(kyz);

            encrypt_directory<true>(kyz);
        }
        if (select == L"3")
        {
            create_pbkdf_password(kyz, true);
            print_rounded_keys(kyz);
            decrypt_file<true>(kyz);
        }
        if (select == L"4")
        {
            create_pbkdf_password(kyz, true);
            print_rounded_keys(kyz);
            decrypt_directory<true>(kyz);
        }
    }

    std::wstring a;
    std::wcin >> a;

    return 0;
}