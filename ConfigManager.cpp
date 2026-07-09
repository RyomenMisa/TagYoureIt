#include "ConfigManager.h"
#include "Logger.h"
#include <fstream>
#include <algorithm>
#include <string>

ConfigManager& ConfigManager::GetInstance() {
    static ConfigManager instance;
    return instance;
}

ConfigManager::ConfigManager() {
    // Базовые настройки по умолчанию
    riskThreshold = 60;
}

ConfigManager::~ConfigManager() {}

std::wstring ConfigManager::ToLower(std::wstring str) const {
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
    return str;
}

void ConfigManager::LoadConfig(const std::wstring& filePath) {
    std::wifstream configFile(filePath);

    if (!configFile.is_open()) {
        Logger::GetInstance().Log(LogLevel::WARNING, L"Файл конфигурации (config.ini) не найден. Используются настройки сенсоров по умолчанию.");
        return;
    }

    std::wstring line;
    while (std::getline(configFile, line)) {
        if (line.empty()) continue;

        if (line.find(L"MAX_RISK=") != std::wstring::npos) {
            try {
                std::wstring val = line.substr(9);
                riskThreshold = std::stoi(val);
                Logger::GetInstance().Log(LogLevel::INFO, L"Установлен порог риска: " + val);
            }
            catch (...) {
                Logger::GetInstance().Log(LogLevel::WARNING, L"Ошибка чтения MAX_RISK, использую базу.");
            }
        }
        else if (line.find(L"WHITELIST=") != std::wstring::npos) {
            std::wstring proc = line.substr(10);
            whiteList.push_back(ToLower(proc));
            Logger::GetInstance().Log(LogLevel::INFO, L"Добавлен в белый список: " + proc);
        }
    }
    configFile.close();
}

int ConfigManager::GetRiskThreshold() const {
    return riskThreshold;
}

bool ConfigManager::IsWhitelisted(const std::wstring& processName) const {
    std::wstring lowerName = ToLower(processName);
    for (const auto& allowed : whiteList) {
        if (lowerName == allowed) {
            return true;
        }
    }
    return false;
}

void ConfigManager::LoadThreatRules(const std::wstring& filePath) {
    std::wifstream file(filePath);
    if (!file.is_open()) {
        Logger::GetInstance().Log(LogLevel::WARNING, L"[CONFIG] Не удалось открыть базу правил угроз: " + filePath);
        return;
    }

    std::wstring line;
    BehaviorRule currentRule;
    bool inRuleBlock = false;

    while (std::getline(file, line)) {
        
        line.erase(line.find_last_not_of(L" \r\n\t") + 1);
        line.erase(0, line.find_first_not_of(L" \r\n\t"));

        if (line.empty()) continue;

        if (line == L"[RULE]") {
            if (inRuleBlock) {
                threatRules.push_back(currentRule);
            }
            currentRule = BehaviorRule();
            inRuleBlock = true;
            continue;
        }

        size_t delim = line.find(L'=');
        if (delim != std::wstring::npos) {
            std::wstring key = line.substr(0, delim);
            std::wstring value = line.substr(delim + 1);

            if (key == L"NAME" || key == L"RuleName") currentRule.ruleName = value;
            else if (key == L"PARENT" || key == L"ParentName") currentRule.parentName = ToLower(value);
            else if (key == L"CHILD" || key == L"ChildName") currentRule.childName = ToLower(value);
            else if (key == L"SCORE" || key == L"RiskScore") {
                try {
                    currentRule.score = std::stoi(value);
                }
                catch (...) {
                    currentRule.score = 100; 
                }
            }
        }
    }

    
    if (inRuleBlock) {
        threatRules.push_back(currentRule);
    }

    file.close();

    // Теперь этот лог пойдет в твой розовый интерфейс!
    Logger::GetInstance().Log(LogLevel::INFO, L"[CONFIG] База угроз (rules.txt) успешно загружена. Найдено правил: " + std::to_wstring(threatRules.size()));
}

const std::vector<BehaviorRule>& ConfigManager::GetBehaviorRules() const {
    return threatRules;
}