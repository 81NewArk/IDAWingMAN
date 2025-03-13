# WingMan
WingMan is an IDA Pro plugin designed to assist with
disassembly and analysis tasks. 

## SettingJson.json
Using the plugin, please ensure that the **SettingJson**.

file in the **<Your_IDA_Path>\plugins** directory is properly configured.

Support the POST method for integrating with large models that comply with the OpenAI SDK.


### Connect with Deepseek Demo:
```
{
    "Base_URL": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
    "Headers": {
        "Content-Type": "application/json",
	"Accept":"application/json",
        "Authorization": "Bearer <Your key>"
    },
    "Payload": {
        "model": "deepseek-r1",
        "frequency_penalty": 0,
        "max_tokens": 512,
        "stream": false,
        "messages": []
    }
}
```


## Hotkey: 
Ctrl + Q 

## References
<https://github.com/allthingsida/ida-cmake>

<https://vaclive.party/software/ida-pro/releases/>

<https://docs.hex-rays.com/9.0>



