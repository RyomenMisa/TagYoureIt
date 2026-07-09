#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <iostream>

// Структура поведенческого правила EDR
struct BehaviorRule {
    std::wstring ruleName;
    std::wstring parentName;
    std::wstring childName;
    int score = 0;
};

class ConfigManager {
public:
    static ConfigManager& GetInstance();
    void LoadConfig(const std::wstring& filePath);

    // Новый метод для загрузки внешней базы правил
    void LoadThreatRules(const std::wstring& filePath);

    int GetRiskThreshold() const;
    bool IsWhitelisted(const std::wstring& processName) const;

    // Получить все загруженные правила поведения
    const std::vector<BehaviorRule>& GetBehaviorRules() const;

private:
    ConfigManager();
    ~ConfigManager();

    int riskThreshold;
    std::vector<std::wstring> whiteList;
    std::vector<BehaviorRule> threatRules; // Хранилище правил

    std::wstring ToLower(std::wstring str) const;
};
