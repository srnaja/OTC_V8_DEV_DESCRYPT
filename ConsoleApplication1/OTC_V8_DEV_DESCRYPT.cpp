#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <queue>
#include <condition_variable>
#include <atomic>
#include <chrono>
#include <zlib.h>
#include <filesystem>

namespace fs = std::filesystem;

const int MAX_CPU_THREADS = std::max(1, (int)std::thread::hardware_concurrency() - 1);
const bool DEBUG_PRINTS = false;

class ResourceManager {
public:
    bool decryptBuffer(std::string& buffer, uint32_t delta = 0x9e3779b9) {
        if (buffer.size() < 24) {
            return false;
        }

        if (buffer.substr(0, 4) != "ENC3") {
            return false;
        }

        uint64_t key = *reinterpret_cast<const uint64_t*>(&buffer[4]);
        uint32_t compressed_size = *reinterpret_cast<const uint32_t*>(&buffer[12]);
        uint32_t size = *reinterpret_cast<const uint32_t*>(&buffer[16]);
        uint32_t adler = *reinterpret_cast<const uint32_t*>(&buffer[20]);

        if (compressed_size > buffer.size() - 24) {
            return false;
        }

        std::string encryptedPart = buffer.substr(24, compressed_size);
        bdecrypt(reinterpret_cast<uint8_t*>(&encryptedPart[0]), compressed_size, key, delta);

        std::string new_buffer;
        new_buffer.resize(size);
        unsigned long new_buffer_size = size;

        int zresult = uncompress(
            reinterpret_cast<uint8_t*>(&new_buffer[0]), &new_buffer_size,
            reinterpret_cast<const uint8_t*>(encryptedPart.data()), compressed_size
        );

        if (zresult != Z_OK) {
            return false;
        }

        uint32_t computed_adler = adler32(0L, Z_NULL, 0);
        computed_adler = adler32(computed_adler,
            reinterpret_cast<const Bytef*>(new_buffer.data()),
            new_buffer_size);

        if (computed_adler != adler) {
            return false;
        }

        buffer = new_buffer;
        return true;
    }

private:
    void bdecrypt(uint8_t* buffer, int len, uint64_t k, uint32_t delta) {
        uint32_t const key[4] = {
            (uint32_t)(k >> 32),
            (uint32_t)(k & 0xFFFFFFFF),
            0x1A2B3C4D,
            0xD1F2E3C4
        };

        uint32_t y, z, sum;
        uint32_t* v = (uint32_t*)buffer;
        unsigned p, rounds, e;
        int n = (len - len % 4) / 4;

        if (n < 2) return;

        rounds = 6 + 52 / n;
        sum = rounds * delta;
        y = v[0];

        do {
            e = (sum >> 2) & 3;
            for (p = n - 1; p > 0; p--) {
                z = v[p - 1];
                y = v[p] -= (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z)));
            }
            z = v[n - 1];
            y = v[0] -= (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (key[(0 & 3) ^ e] ^ z)));
            sum -= delta;
        } while (--rounds);
    }
};

class TaskManager {
public:
    TaskManager(const std::vector<std::string>& files) : total_files(files.size()) {
        for (const auto& f : files) {
            file_queue.push(f);
        }
    }

    void start() {
        std::cout << "Iniciando processamento com " << MAX_CPU_THREADS << " threads\n";
        std::cout << "Total de arquivos: " << total_files << "\n\n";

        for (int i = 0; i < MAX_CPU_THREADS; i++) {
            workers.emplace_back(&TaskManager::workerThread, this);
        }

        progress_monitor = std::thread(&TaskManager::progressReporter, this);
    }

    void waitComplete() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            processing_complete = true;
        }
        cv.notify_all();

        for (auto& t : workers) {
            if (t.joinable()) t.join();
        }

        if (progress_monitor.joinable()) {
            progress_monitor.join();
        }
    }

    size_t getSuccessCount() const { return success_count; }
    size_t getFailedCount() const { return failed_count; }
    size_t getSkippedCount() const { return skipped_count; }

private:
    void workerThread() {
        while (true) {
            std::string filename;
            {
                std::unique_lock<std::mutex> lock(queue_mutex);
                if (file_queue.empty()) break;
                filename = file_queue.front();
                file_queue.pop();
                files_processed++;
            }

            processFile(filename);
        }
    }

    void processFile(const std::string& filename) {
        std::ifstream file(filename, std::ios::binary | std::ios::ate);
        if (!file) {
            std::lock_guard<std::mutex> lock(log_mutex);
            std::cerr << "ERRO: Falha ao abrir: " << filename << "\n";
            failed_count++;
            return;
        }

        size_t size = file.tellg();
        file.seekg(0);
        std::string data(size, '\0');
        if (!file.read(&data[0], size)) {
            std::lock_guard<std::mutex> lock(log_mutex);
            std::cerr << "ERRO: Falha ao ler: " << filename << "\n";
            failed_count++;
            return;
        }

        if (data.size() < 24 || data.substr(0, 4) != "ENC3") {
            skipped_count++;
            return;
        }

        ResourceManager rm;

        if (rm.decryptBuffer(data, 0x9e3779b9)) {
            if (saveDecrypted(data, filename, 0x9e3779b9)) {
                success_count++;
            }
            else {
                failed_count++;
            }
            return;
        }

        std::vector<uint32_t> common_deltas = {
            0x9e3779b9, 0x9e3779b8, 0x9e3779ba,
            0x61c88647, 0x12345678, 0x87654321,
            0xDEADBEEF, 0xCAFEBABE, 0x00000000,
            0xFFFFFFFF, 0x18ef, 0x12E3F4A5
        };

        for (uint32_t delta : common_deltas) {
            std::string test_data = data;
            if (rm.decryptBuffer(test_data, delta)) {
                if (saveDecrypted(test_data, filename, delta)) {
                    success_count++;
                    return;
                }
            }
        }

        std::lock_guard<std::mutex> lock(log_mutex);
        std::cerr << "FALHA: Não foi possível descriptografar: " << filename << "\n";
        failed_count++;
    }

    bool saveDecrypted(const std::string& data, const std::string& filename, uint32_t delta) {
        fs::path original_path(filename);
        fs::path backup_path = original_path;
        backup_path.replace_extension(original_path.extension().string() + ".backup");

        try {
            fs::copy_file(original_path, backup_path, fs::copy_options::overwrite_existing);

            std::ofstream out(original_path, std::ios::binary);
            if (!out) {
                std::lock_guard<std::mutex> lock(log_mutex);
                std::cerr << "ERRO: Falha ao salvar: " << original_path << "\n";
                return false;
            }

            out.write(data.data(), data.size());
            out.close();

            fs::remove(backup_path);

            std::lock_guard<std::mutex> lock(log_mutex);
            std::cout << "SUCESSO: " << original_path.filename()
                << " (delta: 0x" << std::hex << delta << std::dec << ")\n";
            return true;

        }
        catch (const std::exception& e) {
            std::lock_guard<std::mutex> lock(log_mutex);
            std::cerr << "ERRO: " << e.what() << " em: " << filename << "\n";
            return false;
        }
    }

    void progressReporter() {
        auto last_report = std::chrono::steady_clock::now();

        while (!processing_complete || !file_queue.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_report).count() >= 2) {
                last_report = now;

                size_t processed, remaining;
                {
                    std::unique_lock<std::mutex> lock(queue_mutex);
                    processed = files_processed;
                    remaining = file_queue.size();
                }

                float progress = (float)processed / total_files * 100.0f;

                std::cout << "\r[PROGRESSO] " << processed << "/" << total_files
                    << " (" << std::fixed << std::setprecision(1) << progress << "%)"
                    << " | Sucesso: " << success_count
                    << " | Falhas: " << failed_count
                    << " | Ignorados: " << skipped_count
                    << "         "; 
                std::cout.flush();
            }
        }

        std::cout << "\r[FINAL] Processados: " << files_processed << "/" << total_files
            << " | Sucesso: " << success_count
            << " | Falhas: " << failed_count
            << " | Ignorados: " << skipped_count
            << "                 \n"; 
    }

    std::queue<std::string> file_queue;
    std::mutex queue_mutex;
    std::mutex log_mutex;
    std::condition_variable cv;
    std::vector<std::thread> workers;
    std::thread progress_monitor;

    std::atomic<size_t> files_processed{ 0 };
    std::atomic<size_t> success_count{ 0 };
    std::atomic<size_t> failed_count{ 0 };
    std::atomic<size_t> skipped_count{ 0 };
    std::atomic<bool> processing_complete{ false };

    const size_t total_files;
};

std::vector<std::string> getFilesToProcess() {
    std::vector<std::string> files;

    try {
        fs::path current_path = fs::current_path();
        std::cout << "Procurando arquivos em: " << current_path << "\n";

        const std::vector<std::string> target_dirs = { "data", "modules", "mods", "layouts" };

        fs::path init_file = current_path / "init.lua";
        if (fs::exists(init_file) && fs::is_regular_file(init_file)) {
            files.push_back(init_file.string());
        }

        for (const auto& dir_name : target_dirs) {
            fs::path dir_path = current_path / dir_name;

            if (fs::exists(dir_path) && fs::is_directory(dir_path)) {
                for (const auto& entry : fs::recursive_directory_iterator(dir_path)) {
                    if (entry.is_regular_file()) {
                        std::string file_path = entry.path().string();

                        if (file_path.find("game_bot") != std::string::npos &&
                            file_path.find("default_config") != std::string::npos) {
                            continue;
                        }

                        files.push_back(file_path);
                    }
                }
            }
        }

        std::cout << "Encontrados " << files.size() << " arquivos para processar\n";

    }
    catch (const std::exception& e) {
        std::cerr << "Erro ao acessar diretório: " << e.what() << "\n";
    }

    return files;
}

int main(int argc, char** argv) {
    std::vector<std::string> files;

    std::cout << "=== Decryptor de Arquivos ENC3 ===\n";

    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            if (fs::exists(argv[i])) {
                if (fs::is_directory(argv[i])) {
                    for (const auto& entry : fs::recursive_directory_iterator(argv[i])) {
                        if (entry.is_regular_file()) {
                            files.push_back(entry.path().string());
                        }
                    }
                }
                else {
                    files.push_back(argv[i]);
                }
            }
            else {
                std::cerr << "Arquivo/Diretório não encontrado: " << argv[i] << "\n";
            }
        }
    }
    else {
        files = getFilesToProcess();
    }

    if (files.empty()) {
        std::cout << "Nenhum arquivo encontrado para processar.\n";
        std::system("pause");
        return 0;
    }

    TaskManager manager(files);
    manager.start();
    manager.waitComplete();

    std::cout << "\nProcessamento concluído!\n";

    std::system("pause");
    return 0;
}