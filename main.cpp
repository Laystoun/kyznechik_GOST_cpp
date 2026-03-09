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

        if constexpr (with_logs)
        {
            auto end_program = std::chrono::high_resolution_clock::now();

            std::chrono::duration<double> total_program_time = end_program - start_program;
            std::wcout << "Program time (s): " << total_program_time.count() << std::endl
                       << "Encrypted SPEED MB/s: " << (encrypted_bytes_handl / (1024 * 1024)) / total_encrypted_time.count() << std::endl
                       << "Encrypted TIME (s): " << total_encrypted_time.count() << std::endl;
        }
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

    for (auto &path : std::filesystem::recursive_directory_iterator(correct_path))
    {
        if (path.is_regular_file())
        {
            if constexpr (with_logs)
            {
                start_program = std::chrono::high_resolution_clock::now();
            }

            std::ifstream this_file(path.path(), std::ios::binary);
            std::ofstream out(path.path().parent_path() /= path.path().stem() += ".enc", std::ios::binary);

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
}

void print_rounded_keys(Kyznechik& kyz) {
        std::wcout << "Rounded keys: \n"
                   << std::endl;

        for (int i = 0; i < 10; i++)
        {
            std::cout << i << ": ";
            for (int j = 0; j < 16; j++)
            {
                std::wcout << std::hex << kyz.ROUND_KEYS[i][j];
            }
            std::wcout << std::endl;
        }
        std::wcout << std::endl;
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
                print_rounded_keys(kyz);
                encrypt_directory<true>(kyz, drop_path.wstring());
            } else {
                std::wcout << "Start encrypt...\n";
                encrypt_directory<false>(kyz, drop_path.wstring());
                std::wcout << "Encrypt end. Close program";
            }
        } else if (std::filesystem::is_regular_file(drop_path)) {
            if(is_logs) {
                print_rounded_keys(kyz);
                std::wcout << "Start encrypt file...\n";
                encrypt_file<true>(kyz, drop_path.wstring());
                std::wcout << "End encrypt... Close program.";
            } else {
                std::wcout << "Start encrypt file...\n";
                encrypt_file<false>(kyz, drop_path.wstring());
                std::wcout << "End encrypt file. Close program.";
            }
        }
    }
    else
    {
        print_rounded_keys(kyz);
        std::wstring select;
        std::wcout << L"What to encrypt?\n1. File (LOGS)\n2. File (NO LOGS)\n\n3. Directory (LOGS)\n4. Directory (NO LOGS)\n( 1/2/3/4 ): ";

        std::wcin >> select;

        std::wcin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        if (select == L"1")
        {
            encrypt_file<true>(kyz);
        }
        if (select == L"2")
        {
            encrypt_file<false>(kyz);
        }
        if (select == L"3")
        {
            encrypt_directory<true>(kyz);
        }
        if (select == L"4")
        {
            encrypt_directory<false>(kyz);
        }
    }

    std::wstring a;
    std::wcin >> a;

    return 0;
}