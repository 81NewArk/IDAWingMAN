#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>

#include <string>
#include <iostream>
#include <rapidjson/document.h>
#include <rapidjson/writer.h>
#include <rapidjson/stringbuffer.h>
#include <curl/curl.h>
#include <thread>
#include <mutex>

// Add Windows-specific headers and link directives
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")
#endif

using namespace rapidjson;
using namespace std;

mutex mtx;

// Global flag to track WSA initialization
static bool g_wsaInitialized = false;

Document Read_SettingJson() {
    char plugin_dir[QMAXPATH];
    getsysfile(plugin_dir, sizeof(plugin_dir), "plugins/SettingJson.json", nullptr);

    linput_t* file = open_linput(plugin_dir, false);
    if (!file) {
        msg("WingMan Error: Failed to open configuration file: %s\n", plugin_dir);
        return Document();
    }

    qoff64_t fileSize = qlsize(file);
    if (fileSize == 0) {
        close_linput(file);
        msg("WingMan Error: Configuration file is empty.\n");
        return Document();
    }

    string content;
    content.resize(fileSize);
    lread(file, &content[0], fileSize);
    close_linput(file);

    Document document;
    ParseResult result = document.Parse(content.c_str());
    if (!result) {
        msg("WingMan Error: Failed to parse JSON file. Error code: %u\n", result.Code());
        return Document();
    }

    msg("WingMan Configuration file loaded successfully.\n");
    msg(u8R"(
---------------------------------------------------------------------
|        __        __ _                 __  __                      |
|        \ \      / /(_) _ __    __ _  |  \/  |  __ _  _ __         |
|         \ \ /\ / / | || '_ \  / _` | | |\/| | / _` || '_ \        |
|          \ V  V /  | || | | || (_| | | |  | || (_| || | | |       |
|           \_/\_/   |_||_| |_| \__, | |_|  |_| \__,_||_| |_|       |
|                               |___/                               |
|-------------------------------------------------------------------|
|      Author      :  81NewArk81                                    |
|-------------------------------------------------------------------|
|                                                                   |
|      GitHub      :  https://github.com/81NewArk/IDAWingMAN        |
|                                                                   |
|-------------------------------------------------------------------|
|      Description                                                  |
|-------------------------------------------------------------------|
|          WingMan is an IDA Pro plugin designed to assist with     |
|      disassembly and analysis tasks.                              |
|          Using the plugin, please ensure that the SettingJson.    |
|      file in the plugins directory is properly configured.        |
|          Support the POST method for integrating with large       |
|      models that comply with the OpenAI SDK.                      |
|           Hotkey: Ctrl + Q .                                      |
---------------------------------------------------------------------
)");
    return document;
}

string Get_BaseURL(const Document& settings) {
    if (!settings.HasMember("Base_URL") || !settings["Base_URL"].IsString()) {
        msg("WingMan Error: Missing or invalid 'Base_URL' in configuration\n");
        return "";
    }
    return settings["Base_URL"].GetString();
}

string Get_Headers(const Document& settings) {
    if (!settings.HasMember("Headers") || !settings["Headers"].IsObject()) {
        msg("WingMan Error: Missing or invalid 'Headers' in configuration\n");
        return "";
    }
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    settings["Headers"].Accept(writer);
    return buffer.GetString();
}

string Get_Payload(const Document& settings) {
    if (!settings.HasMember("Payload") || !settings["Payload"].IsObject()) {
        msg("WingMan Error: Missing or invalid 'Payload' in configuration\n");
        return "";
    }
    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    settings["Payload"].Accept(writer);
    return buffer.GetString();
}

Value Construct_Payload_Messages(const string& message, Document::AllocatorType& allocator) {
    Value messages(kArrayType);

    Value systemMessage(kObjectType);
    systemMessage.AddMember("role", "system", allocator);
    systemMessage.AddMember("content", "You are a helpful assistant.", allocator);
    messages.PushBack(systemMessage, allocator);

    Value userMessage(kObjectType);
    userMessage.AddMember("role", "user", allocator);
    userMessage.AddMember("content", StringRef(message.c_str()), allocator);
    messages.PushBack(userMessage, allocator);

    return messages;
}

string Construct_Payload(const string& message, const Document& settings) {
    string payload = Get_Payload(settings);
    if (payload.empty()) {
        return "";
    }
    Document document;
    document.Parse(payload.c_str());

    if (!document.HasMember("messages") || !document["messages"].IsArray()) {
        msg("WingMan Error: 'messages' field not found in payload\n");
        return "";
    }

    Document::AllocatorType& allocator = document.GetAllocator();
    document["messages"] = Construct_Payload_Messages(message, allocator);

    StringBuffer buffer;
    Writer<StringBuffer> writer(buffer);
    document.Accept(writer);
    return buffer.GetString();
}

string Extract_Content(const string& jsonContent) {
    Document document;
    ParseResult result = document.Parse(jsonContent.c_str());
    if (!result) {
        msg("WingMan Error: Failed to parse response JSON. Error code: %u\n", result.Code());
        return "WingMan Error: Failed to parse response JSON.";
    }
    if (!document.HasMember("choices") || !document["choices"].IsArray() || document["choices"].Empty()) {
        msg("WingMan Error: Invalid response format\n");
        return "WingMan Error: Invalid response format";
    }
    const Value& choices = document["choices"];
    if (!choices[0].HasMember("message") || !choices[0]["message"].HasMember("content")) {
        msg("WingMan Error: Missing 'message' or 'content' field in response\n");
        return "WingMan Error: Missing 'message' or 'content' field in response";
    }
    return choices[0]["message"]["content"].GetString();
}

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

string Send_Post(const string& url, const string& payload, const string& headers) {
    CURL* curl;
    CURLcode res;
    string readBuffer;

    curl = curl_easy_init();
    if (curl) {
        struct curl_slist* headers_list = nullptr;
        Document headersDoc;
        headersDoc.Parse(headers.c_str());
        for (Value::ConstMemberIterator itr = headersDoc.MemberBegin(); itr != headersDoc.MemberEnd(); ++itr) {
            string header = itr->name.GetString();
            header += ": ";
            header += itr->value.GetString();
            headers_list = curl_slist_append(headers_list, header.c_str());
        }

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers_list);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);  // Disable SSL verification (for debugging only)
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);  // Disable SSL verification (for debugging only)
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);         // Enable verbose output

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            lock_guard<mutex> guard(mtx);
            msg("WingMan Error: Failed to send POST request. CURL error: %s\n", curl_easy_strerror(res));
        }
        else {
            lock_guard<mutex> guard(mtx);
        }

        curl_slist_free_all(headers_list);
        curl_easy_cleanup(curl);
    }
    else {
        lock_guard<mutex> guard(mtx);
        msg("WingMan Error: Failed to initialize CURL.\n");
    }

    return readBuffer;
}

void Process_Request(const string& url, const string& payload, const string& headers) {
    string response_json = Send_Post(url, payload, headers);
    lock_guard<mutex> guard(mtx);
    msg("\n------------------------------------------------------------------\n\n\nWingMan  Response:\n------------------------------------------------------------------\n%s\n\n", Extract_Content(response_json).c_str());
}

struct plugin_ctx_t : public plugmod_t {
    plugin_ctx_t() {
#ifdef _WIN32
        // Initialize Winsock
        if (!g_wsaInitialized) {
            WSADATA wsaData;
            if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
                msg("WingMan Error: WSAStartup failed\n");
                return;
            }
            g_wsaInitialized = true;
        }
#endif
        // Initialize CURL globally
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }

    ~plugin_ctx_t() {
        // Cleanup CURL
        curl_global_cleanup();
#ifdef _WIN32
        // Cleanup Winsock
        if (g_wsaInitialized) {
            WSACleanup();
            g_wsaInitialized = false;
        }
#endif
    }

    bool idaapi run(size_t) override {
        msg("WingMan Loading configuration...\n");

        Document settings = Read_SettingJson();
        if (settings.IsNull()) {
            msg("WingMan Error: Configuration loading failed.\n");
            return false;
        }

        string url = Get_BaseURL(settings);
        if (url.empty()) {
            msg("WingMan Error: Failed to get Base URL from configuration.\n");
            return false;
        }

        string headers = Get_Headers(settings);
        if (headers.empty()) {
            msg("WingMan Error: Failed to get Headers from configuration.\n");
            return false;
        }

        qstring disasm_code;
        ea_t start_ea, end_ea;
        bool has_selection = read_range_selection(nullptr, &start_ea, &end_ea);
        if (has_selection) {
            for (ea_t ea = start_ea; ea < end_ea; ea = next_head(ea, end_ea)) {
                qstring disasm_line;
                if (generate_disasm_line(&disasm_line, ea, GENDSM_REMOVE_TAGS)) {
                    tag_remove(&disasm_line);
                    disasm_code.cat_sprnt("%a: %s\n", ea, disasm_line.c_str());
                }
            }

            if (disasm_code.empty()) {
                msg("WingMan Error: No code selected.\n");
                return false;
            }
        }

        qstring input_qstr;
        if (ask_text(&input_qstr, 2048, "", "Enter Prompt:")) {
            string user_input = input_qstr.c_str();
            string prompt = has_selection ? "Disassembly:\n" + string(disasm_code.c_str()) + "\n" + user_input : user_input;

            msg("\nPrompt:\n------------------------------------------------------------------\n%s\n\n", prompt.c_str());

            string payload = Construct_Payload(prompt, settings);
            msg("------------------------------------------------------------------\nPlease wait for Ai to think......\n------------------------------------------------------------------\n\n");
            thread request_thread(Process_Request, url, payload, headers);
            request_thread.detach();
        }
        else {
            msg("WingMan No prompt entered\n");
        }

        return true;
    }
};

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_UNL | PLUGIN_MULTI,
    []()->plugmod_t* { return new plugin_ctx_t; },
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    "WingMan",
    "Ctrl+Q"
};
