#include "application.h"
#include "board.h"
#include "display.h"
#include "system_info.h"
#include "ml307_ssl_transport.h"
#include "audio_codec.h"
#include "ble_relay_manager.h"
#include "mqtt_protocol.h"
#include "websocket_protocol.h"
#include "font_awesome_symbols.h"
#include "iot/thing_manager.h"
#include "assets/lang_config.h"

#include <cstring>
#include <cstdint>
#include <esp_log.h>
#include <cJSON.h>
#include <driver/gpio.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>

#define TAG "Application"

namespace {
constexpr int kListeningIdleTimeoutMs = 12000;
constexpr int64_t kListeningVoiceActivityThreshold = 700;
constexpr char kListeningIdleGoodbye[] = "我先休息啦，需要时再叫我。";
}

static const char* const STATE_STRINGS[] = {
    "unknown",
    "starting",
    "wifi_configuring",
    "ble_configuring",
    "idle",
    "connecting",
    "listening",
    "speaking",
    "upgrading",
    "activating",
    "fatal_error",
    "invalid_state"
};

Application::Application() {
    event_group_ = xEventGroupCreate();
    background_task_ = new BackgroundTask(4096 * 8);

    esp_timer_create_args_t clock_timer_args = {
        .callback = [](void* arg) {
            Application* app = (Application*)arg;
            app->OnClockTimer();
        },
        .arg = this,
        .dispatch_method = ESP_TIMER_TASK,
        .name = "clock_timer",
        .skip_unhandled_events = true
    };
    esp_timer_create(&clock_timer_args, &clock_timer_handle_);
    esp_timer_start_periodic(clock_timer_handle_, 1000000);
}

Application::~Application() {
    if (clock_timer_handle_ != nullptr) {
        esp_timer_stop(clock_timer_handle_);
        esp_timer_delete(clock_timer_handle_);
    }
    if (background_task_ != nullptr) {
        delete background_task_;
    }
    vEventGroupDelete(event_group_);
}


void Application::Alert(const char* status, const char* message, const char* emotion, const std::string_view& sound) {
    ESP_LOGW(TAG, "Alert %s: %s [%s]", status, message, emotion);
    auto display = Board::GetInstance().GetDisplay();
    display->SetStatus(status);
    display->SetEmotion(emotion);
    display->SetChatMessage("system", message);
    if (!sound.empty()) {
        ResetDecoder();
        PlaySound(sound);
    }
}

void Application::DismissAlert() {
    if (device_state_ == kDeviceStateIdle) {
        auto display = Board::GetInstance().GetDisplay();
        display->SetStatus(Lang::Strings::STANDBY);
        display->SetEmotion("neutral");
        display->SetChatMessage("system", "");
    }
}

void Application::PlaySound(const std::string_view& sound) {
    // Wait for the previous sound to finish
    {
        std::unique_lock<std::mutex> lock(mutex_);
        audio_decode_cv_.wait(lock, [this]() {
            return audio_decode_queue_.empty();
        });
    }
    background_task_->WaitForCompletion();

    // The assets are encoded at 16000Hz, 60ms frame duration
    SetDecodeSampleRate(16000, 60);
    const char* data = sound.data();
    size_t size = sound.size();
    for (const char* p = data; p < data + size; ) {
        auto p3 = (BinaryProtocol3*)p;
        p += sizeof(BinaryProtocol3);

        auto payload_size = ntohs(p3->payload_size);
        std::vector<uint8_t> opus;
        opus.resize(payload_size);
        memcpy(opus.data(), p3->payload, payload_size);
        p += payload_size;

        std::lock_guard<std::mutex> lock(mutex_);
        audio_decode_queue_.emplace_back(std::move(opus));
    }
}

void Application::ToggleChatState() {
    if (!protocol_) {
        ESP_LOGE(TAG, "Protocol not initialized");
        return;
    }

    if (device_state_ == kDeviceStateIdle) {
        Schedule([this]() {
            SetDeviceState(kDeviceStateConnecting);
            if (!protocol_->OpenAudioChannel()) {
                return;
            }

            SetListeningMode(realtime_chat_enabled_ ? kListeningModeRealtime : kListeningModeAutoStop);
        });
    } else if (device_state_ == kDeviceStateSpeaking) {
        Schedule([this]() {
            AbortSpeaking(kAbortReasonNone);
        });
    } else if (device_state_ == kDeviceStateListening) {
        Schedule([this]() {
            protocol_->CloseAudioChannel();
        });
    }
}

void Application::StartListening() {
    if (!protocol_) {
        ESP_LOGE(TAG, "Protocol not initialized");
        return;
    }
    
    if (device_state_ == kDeviceStateIdle) {
        Schedule([this]() {
            if (!protocol_->IsAudioChannelOpened()) {
                SetDeviceState(kDeviceStateConnecting);
                if (!protocol_->OpenAudioChannel()) {
                    return;
                }
            }

            SetListeningMode(kListeningModeManualStop);
        });
    } else if (device_state_ == kDeviceStateSpeaking) {
        Schedule([this]() {
            AbortSpeaking(kAbortReasonNone);
            SetListeningMode(kListeningModeManualStop);
        });
    }
}

void Application::StopListening() {
    const std::array<int, 3> valid_states = {
        kDeviceStateListening,
        kDeviceStateSpeaking,
        kDeviceStateIdle,
    };
    // If not valid, do nothing
    if (std::find(valid_states.begin(), valid_states.end(), device_state_) == valid_states.end()) {
        return;
    }

    Schedule([this]() {
        if (device_state_ == kDeviceStateListening) {
            protocol_->SendStopListening();
            SetDeviceState(kDeviceStateIdle);
        }
    });
}

void Application::Start() {
    auto& board = Board::GetInstance();
    runtime_ready_ = false;
    SetDeviceState(kDeviceStateStarting);

    /* Setup the display */
    auto display = board.GetDisplay();

    /* Setup the audio codec */
    auto codec = board.GetAudioCodec();
    opus_decoder_ = std::make_unique<OpusDecoderWrapper>(codec->output_sample_rate(), 1, OPUS_FRAME_DURATION_MS);
    opus_encoder_ = std::make_unique<OpusEncoderWrapper>(16000, 1, OPUS_FRAME_DURATION_MS);
    if (realtime_chat_enabled_) {
        ESP_LOGI(TAG, "Realtime chat enabled, setting opus encoder complexity to 0");
        opus_encoder_->SetComplexity(0);
    } else if (board.GetBoardType() == "ml307") {
        ESP_LOGI(TAG, "ML307 board detected, setting opus encoder complexity to 5");
        opus_encoder_->SetComplexity(5);
    } else {
        ESP_LOGI(TAG, "WiFi board detected, setting opus encoder complexity to 3");
        opus_encoder_->SetComplexity(3);
    }

    if (codec->input_sample_rate() != 16000) {
        input_resampler_.Configure(codec->input_sample_rate(), 16000);
        reference_resampler_.Configure(codec->input_sample_rate(), 16000);
    }
    codec->Start();

    xTaskCreatePinnedToCore([](void* arg) {
        Application* app = (Application*)arg;
        app->AudioLoop();
        vTaskDelete(NULL);
    }, "audio_loop", 4096 * 2, this, 8, &audio_loop_task_handle_, realtime_chat_enabled_ ? 1 : 0);

    /* Wait for the network to be ready */
    board.StartNetwork();

    ota_ = std::make_unique<Ota>();
    
    // Check for new firmware version
    display->SetStatus(Lang::Strings::CHECKING_NEW_VERSION);
    for (int i = 0; i < 10; ++i) {
        if (ota_->CheckVersion() == ESP_OK) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    if (ota_->HasNewVersion()) {
        UpgradeFirmware(ota_->GetFirmwareUrl(), ota_->GetFirmwareVersion());
    }
    
    ota_->MarkCurrentVersionValid();

    // Activation
    while (ota_->HasActivationCode() || ota_->HasActivationChallenge()) {
        display->SetStatus(Lang::Strings::ACTIVATION);
        if (ota_->HasActivationCode()) {
            ShowActivationCode(ota_->GetActivationCode(), ota_->GetActivationMessage());
        }
        if (ota_->Activate() == ESP_OK) {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(3000));
    }

    // Initialize the protocol
    display->SetStatus(Lang::Strings::LOADING_PROTOCOL);
    if (ota_->HasWebsocketConfig()) {
        protocol_ = std::make_unique<WebsocketProtocol>();
    } else if (ota_->HasMqttConfig()) {
        if (board.GetConnectivityMode() == ConnectivityMode::kBleRelay) {
            Alert(Lang::Strings::ERROR, Lang::Strings::BLE_RELAY_UNSUPPORTED, "sad", Lang::Sounds::P3_EXCLAMATION);
            SetDeviceState(kDeviceStateBleConfiguring);
            MainEventLoop();
            return;
        }
        protocol_ = std::make_unique<MqttProtocol>();
    } else {
#ifdef CONFIG_CONNECTION_TYPE_WEBSOCKET
        protocol_ = std::make_unique<WebsocketProtocol>();
#else
        protocol_ = std::make_unique<MqttProtocol>();
#endif
    }
    protocol_->OnNetworkError([this](const std::string& message) {
        auto& board = Board::GetInstance();
        if (board.GetConnectivityMode() == ConnectivityMode::kBleRelay && !board.IsNetworkReady()) {
            SetDeviceState(kDeviceStateBleConfiguring);
        } else {
            SetDeviceState(kDeviceStateIdle);
        }
        Alert(Lang::Strings::ERROR, message.c_str(), "sad", Lang::Sounds::P3_EXCLAMATION);
    });
    protocol_->OnIncomingAudio([this](std::vector<uint8_t>&& data) {
        const int max_packets_in_queue = 300 / OPUS_FRAME_DURATION_MS;
        std::lock_guard<std::mutex> lock(mutex_);
        if (audio_decode_queue_.size() < max_packets_in_queue) {
            audio_decode_queue_.emplace_back(std::move(data));
        }
    });
    protocol_->OnAudioChannelOpened([this, codec, &board]() {
        board.SetPowerSaveMode(false);
        if (protocol_->server_sample_rate() != codec->output_sample_rate()) {
            ESP_LOGW(TAG, "Server sample rate %d does not match device output sample rate %d, resampling may cause distortion",
                protocol_->server_sample_rate(), codec->output_sample_rate());
        }
        SetDecodeSampleRate(protocol_->server_sample_rate(), protocol_->server_frame_duration());
        auto& thing_manager = iot::ThingManager::GetInstance();
        protocol_->SendIotDescriptors(thing_manager.GetDescriptorsJson());
        std::string states;
        if (thing_manager.GetStatesJson(states, false)) {
            protocol_->SendIotStates(states);
        }
    });
    protocol_->OnAudioChannelClosed([this, &board]() {
        board.SetPowerSaveMode(true);
        Schedule([this]() {
            if (listening_idle_timed_out_) {
                return;
            }
            auto display = Board::GetInstance().GetDisplay();
            display->SetChatMessage("system", "");
            auto& current_board = Board::GetInstance();
            if (current_board.GetConnectivityMode() == ConnectivityMode::kBleRelay && !current_board.IsNetworkReady()) {
                SetDeviceState(kDeviceStateBleConfiguring);
            } else {
                SetDeviceState(kDeviceStateIdle);
            }
        });
    });
    protocol_->OnIncomingJson([this, display](const cJSON* root) {
        // Parse JSON data
        auto type = cJSON_GetObjectItem(root, "type");
        if (strcmp(type->valuestring, "tts") == 0) {
            auto state = cJSON_GetObjectItem(root, "state");
            if (strcmp(state->valuestring, "start") == 0) {
                Schedule([this]() {
                    aborted_ = false;
                    if (device_state_ == kDeviceStateIdle || device_state_ == kDeviceStateListening) {
                        SetDeviceState(kDeviceStateSpeaking);
                    }
                });
            } else if (strcmp(state->valuestring, "stop") == 0) {
                Schedule([this]() {
                    background_task_->WaitForCompletion();
                    if (device_state_ == kDeviceStateSpeaking) {
                        if (listening_mode_ == kListeningModeManualStop) {
                            SetDeviceState(kDeviceStateIdle);
                        } else {
                            SetDeviceState(kDeviceStateListening);
                        }
                    }
                });
            } else if (strcmp(state->valuestring, "sentence_start") == 0) {
                auto text = cJSON_GetObjectItem(root, "text");
                if (text != NULL) {
                    ESP_LOGI(TAG, "<< %s", text->valuestring);
                    Schedule([this, display, message = std::string(text->valuestring)]() {
                        display->SetChatMessage("assistant", message.c_str());
                    });
                }
            }
        } else if (strcmp(type->valuestring, "stt") == 0) {
            auto text = cJSON_GetObjectItem(root, "text");
            if (text != NULL) {
                ESP_LOGI(TAG, ">> %s", text->valuestring);
                Schedule([this, display, message = std::string(text->valuestring)]() {
                    display->SetChatMessage("user", message.c_str());
                });
            }
        } else if (strcmp(type->valuestring, "llm") == 0) {
            auto emotion = cJSON_GetObjectItem(root, "emotion");
            if (emotion != NULL) {
                Schedule([this, display, emotion_str = std::string(emotion->valuestring)]() {
                    display->SetEmotion(emotion_str.c_str());
                });
            }
        } else if (strcmp(type->valuestring, "iot") == 0) {
            auto commands = cJSON_GetObjectItem(root, "commands");
            if (commands != NULL) {
                auto& thing_manager = iot::ThingManager::GetInstance();
                for (int i = 0; i < cJSON_GetArraySize(commands); ++i) {
                    auto command = cJSON_GetArrayItem(commands, i);
                    thing_manager.Invoke(command);
                }
            }
        } else if (strcmp(type->valuestring, "system") == 0) {
            auto command = cJSON_GetObjectItem(root, "command");
            if (command != NULL) {
                ESP_LOGI(TAG, "System command: %s", command->valuestring);
                if (strcmp(command->valuestring, "reboot") == 0) {
                    // Do a reboot if user requests a OTA update
                    Schedule([this]() {
                        Reboot();
                    });
                } else {
                    ESP_LOGW(TAG, "Unknown system command: %s", command->valuestring);
                }
            }
        } else if (strcmp(type->valuestring, "alert") == 0) {
            auto status = cJSON_GetObjectItem(root, "status");
            auto message = cJSON_GetObjectItem(root, "message");
            auto emotion = cJSON_GetObjectItem(root, "emotion");
            if (status != NULL && message != NULL && emotion != NULL) {
                Alert(status->valuestring, message->valuestring, emotion->valuestring, Lang::Sounds::P3_VIBRATION);
            } else {
                ESP_LOGW(TAG, "Alert command requires status, message and emotion");
            }
        }
    });
    protocol_->Start();

#if CONFIG_USE_AUDIO_PROCESSOR
    audio_processor_.Initialize(codec, realtime_chat_enabled_);
    audio_processor_.OnOutput([this](std::vector<int16_t>&& data) {
        background_task_->Schedule([this, data = std::move(data)]() mutable {
            if (protocol_->IsAudioChannelBusy()) {
                return;
            }
            opus_encoder_->Encode(std::move(data), [this](std::vector<uint8_t>&& opus) {
                Schedule([this, opus = std::move(opus)]() {
                    protocol_->SendAudio(opus);
                });
            });
        });
    });
    audio_processor_.OnVadStateChange([this](bool speaking) {
        if (device_state_ == kDeviceStateListening) {
            Schedule([this, speaking]() {
                if (speaking) {
                    voice_detected_ = true;
                    MarkListeningActivity();
                } else {
                    voice_detected_ = false;
                }
                auto led = Board::GetInstance().GetLed();
                led->OnStateChanged();
            });
        }
    });
#endif

#if CONFIG_USE_WAKE_WORD_DETECT
    wake_word_detect_.Initialize(codec);
    wake_word_detect_.OnWakeWordDetected([this](const std::string& wake_word) {
        Schedule([this, &wake_word]() {
            if (device_state_ == kDeviceStateIdle) {
                SetDeviceState(kDeviceStateConnecting);
                wake_word_detect_.EncodeWakeWordData();

                if (!protocol_->OpenAudioChannel()) {
                    wake_word_detect_.StartDetection();
                    return;
                }
                
                std::vector<uint8_t> opus;
                // Encode and send the wake word data to the server
                while (wake_word_detect_.GetWakeWordOpus(opus)) {
                    protocol_->SendAudio(opus);
                }
                // Set the chat state to wake word detected
                protocol_->SendWakeWordDetected(wake_word);
                ESP_LOGI(TAG, "Wake word detected: %s", wake_word.c_str());
                SetListeningMode(realtime_chat_enabled_ ? kListeningModeRealtime : kListeningModeAutoStop);
            } else if (device_state_ == kDeviceStateSpeaking) {
                AbortSpeaking(kAbortReasonWakeWordDetected);
            }
        });
    });
    wake_word_detect_.StartDetection();
#endif

    // Wait for the new version check to finish
    SetDeviceState(kDeviceStateIdle);
    runtime_ready_ = true;
    std::string message = std::string(Lang::Strings::VERSION) + ota_->GetCurrentVersion();
    display->ShowNotification(message.c_str());
    display->SetChatMessage("system", "");
    // Play the success sound to indicate the device is ready
    ResetDecoder();
    PlaySound(Lang::Sounds::P3_SUCCESS);
    
    // Enter the main event loop
    MainEventLoop();
}

void Application::OnClockTimer() {
    clock_ticks_++;
    CheckListeningIdleTimeout();

    // Print the debug info every 10 seconds
    if (clock_ticks_ % 10 == 0) {
        // SystemInfo::PrintRealTimeStats(pdMS_TO_TICKS(1000));
        
        // Print current stats and time
        time_t now;
        char strftime_buf[64];
        struct tm timeinfo;
        time(&now);
        localtime_r(&now, &timeinfo);
        if (timeinfo.tm_year > (2020 - 1900)) {
            strftime(strftime_buf, sizeof(strftime_buf), "%Y-%m-%d %H:%M:%S", &timeinfo);
            // Get milliseconds
            struct timeval tv;
            gettimeofday(&tv, NULL);
            ESP_LOGI(TAG, "Current Time: %s.%03ld", strftime_buf, tv.tv_usec / 1000);
        }

        int free_sram = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        int min_free_sram = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
        ESP_LOGI(TAG, "Free internal: %u minimal internal: %u", free_sram, min_free_sram);
    }
}

// Add a async task to MainLoop
void Application::Schedule(std::function<void()> callback) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        main_tasks_.push_back(std::move(callback));
    }
    xEventGroupSetBits(event_group_, SCHEDULE_EVENT);
}

// The Main Event Loop controls the chat state and websocket connection
// If other tasks need to access the websocket or chat state,
// they should use Schedule to call this function
void Application::MainEventLoop() {
    while (true) {
        auto bits = xEventGroupWaitBits(event_group_, SCHEDULE_EVENT, pdTRUE, pdFALSE, portMAX_DELAY);

        if (bits & SCHEDULE_EVENT) {
            std::unique_lock<std::mutex> lock(mutex_);
            std::list<std::function<void()>> tasks = std::move(main_tasks_);
            lock.unlock();
            for (auto& task : tasks) {
                task();
            }
        }
    }
}

// The Audio Loop is used to input and output audio data
void Application::AudioLoop() {
    auto codec = Board::GetInstance().GetAudioCodec();
    while (true) {
        OnAudioInput();
        if (codec->output_enabled()) {
            OnAudioOutput();
        }
    }
}

void Application::OnAudioOutput() {
    if (busy_decoding_audio_) {
        return;
    }

    auto now = std::chrono::steady_clock::now();
    auto codec = Board::GetInstance().GetAudioCodec();
    const int max_silence_seconds = 10;

    std::unique_lock<std::mutex> lock(mutex_);
    if (audio_decode_queue_.empty()) {
        // Disable the output if there is no audio data for a long time
        if (device_state_ == kDeviceStateIdle) {
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(now - last_output_time_).count();
            if (duration > max_silence_seconds) {
                codec->EnableOutput(false);
            }
        }
        return;
    }

    if (device_state_ == kDeviceStateListening) {
        audio_decode_queue_.clear();
        audio_decode_cv_.notify_all();
        return;
    }

    auto opus = std::move(audio_decode_queue_.front());
    audio_decode_queue_.pop_front();
    lock.unlock();
    audio_decode_cv_.notify_all();

    busy_decoding_audio_ = true;
    background_task_->Schedule([this, codec, opus = std::move(opus)]() mutable {
        busy_decoding_audio_ = false;
        if (aborted_) {
            return;
        }

        std::vector<int16_t> pcm;
        if (!opus_decoder_->Decode(std::move(opus), pcm)) {
            return;
        }
        // Resample if the sample rate is different
        if (opus_decoder_->sample_rate() != codec->output_sample_rate()) {
            int target_size = output_resampler_.GetOutputSamples(pcm.size());
            std::vector<int16_t> resampled(target_size);
            output_resampler_.Process(pcm.data(), pcm.size(), resampled.data());
            pcm = std::move(resampled);
        }
        codec->OutputData(pcm);
        last_output_time_ = std::chrono::steady_clock::now();
    });
}

void Application::OnAudioInput() {
#if CONFIG_USE_WAKE_WORD_DETECT
    if (wake_word_detect_.IsDetectionRunning()) {
        std::vector<int16_t> data;
        int samples = wake_word_detect_.GetFeedSize();
        if (samples > 0) {
            ReadAudio(data, 16000, samples);
            wake_word_detect_.Feed(data);
            return;
        }
    }
#endif
#if CONFIG_USE_AUDIO_PROCESSOR
    if (audio_processor_.IsRunning()) {
        std::vector<int16_t> data;
        int samples = audio_processor_.GetFeedSize();
        if (samples > 0) {
            ReadAudio(data, 16000, samples);
            audio_processor_.Feed(data);
            return;
        }
    }
#else
    if (device_state_ == kDeviceStateListening) {
        std::vector<int16_t> data;
        ReadAudio(data, 16000, 30 * 16000 / 1000);
        if (HasVoiceActivity(data)) {
            MarkListeningActivity();
        }
        background_task_->Schedule([this, data = std::move(data)]() mutable {
            if (protocol_->IsAudioChannelBusy()) {
                return;
            }
            opus_encoder_->Encode(std::move(data), [this](std::vector<uint8_t>&& opus) {
                Schedule([this, opus = std::move(opus)]() {
                    protocol_->SendAudio(opus);
                });
            });
        });
        return;
    }
#endif
    vTaskDelay(pdMS_TO_TICKS(30));
}

void Application::ReadAudio(std::vector<int16_t>& data, int sample_rate, int samples) {
    auto codec = Board::GetInstance().GetAudioCodec();
    if (codec->input_sample_rate() != sample_rate) {
        data.resize(samples * codec->input_sample_rate() / sample_rate);
        if (!codec->InputData(data)) {
            return;
        }
        if (codec->input_channels() == 2) {
            auto mic_channel = std::vector<int16_t>(data.size() / 2);
            auto reference_channel = std::vector<int16_t>(data.size() / 2);
            for (size_t i = 0, j = 0; i < mic_channel.size(); ++i, j += 2) {
                mic_channel[i] = data[j];
                reference_channel[i] = data[j + 1];
            }
            auto resampled_mic = std::vector<int16_t>(input_resampler_.GetOutputSamples(mic_channel.size()));
            auto resampled_reference = std::vector<int16_t>(reference_resampler_.GetOutputSamples(reference_channel.size()));
            input_resampler_.Process(mic_channel.data(), mic_channel.size(), resampled_mic.data());
            reference_resampler_.Process(reference_channel.data(), reference_channel.size(), resampled_reference.data());
            data.resize(resampled_mic.size() + resampled_reference.size());
            for (size_t i = 0, j = 0; i < resampled_mic.size(); ++i, j += 2) {
                data[j] = resampled_mic[i];
                data[j + 1] = resampled_reference[i];
            }
        } else {
            auto resampled = std::vector<int16_t>(input_resampler_.GetOutputSamples(data.size()));
            input_resampler_.Process(data.data(), data.size(), resampled.data());
            data = std::move(resampled);
        }
    } else {
        data.resize(samples);
        if (!codec->InputData(data)) {
            return;
        }
    }
}

void Application::AbortSpeaking(AbortReason reason) {
    ESP_LOGI(TAG, "Abort speaking");
    aborted_ = true;
    protocol_->SendAbortSpeaking(reason);
}

void Application::SetListeningMode(ListeningMode mode) {
    listening_mode_ = mode;
    auto now = std::chrono::steady_clock::now();
    listening_started_time_ = now;
    last_listening_activity_time_ = now;
    listening_idle_timed_out_ = false;
    SetDeviceState(kDeviceStateListening);
}

void Application::MarkListeningActivity() {
    if (device_state_ != kDeviceStateListening) {
        return;
    }
    last_listening_activity_time_ = std::chrono::steady_clock::now();
}

void Application::CheckListeningIdleTimeout() {
    if (device_state_ != kDeviceStateListening ||
        listening_mode_ != kListeningModeAutoStop ||
        listening_idle_timed_out_) {
        return;
    }

    auto now = std::chrono::steady_clock::now();
    auto reference = last_listening_activity_time_ > listening_started_time_
        ? last_listening_activity_time_
        : listening_started_time_;
    auto idle_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now - reference).count();
    if (idle_ms < kListeningIdleTimeoutMs) {
        return;
    }

    listening_idle_timed_out_ = true;
    Schedule([this]() {
        HandleListeningIdleTimeout();
    });
}

void Application::HandleListeningIdleTimeout() {
    if (device_state_ != kDeviceStateListening || protocol_ == nullptr) {
        return;
    }
    ESP_LOGI(TAG, "Listening idle timeout, closing audio channel");
    protocol_->SendStopListening();
    protocol_->CloseAudioChannel();
    SetDeviceState(kDeviceStateIdle);

    auto display = Board::GetInstance().GetDisplay();
    display->SetChatMessage("assistant", kListeningIdleGoodbye);
    ResetDecoder();
    PlaySound(Lang::Sounds::P3_SUCCESS);
}

bool Application::HasVoiceActivity(const std::vector<int16_t>& data) const {
    if (data.empty()) {
        return false;
    }
    int64_t sum_abs = 0;
    for (auto sample : data) {
        sum_abs += sample >= 0 ? sample : -static_cast<int64_t>(sample);
    }
    return (sum_abs / static_cast<int64_t>(data.size())) > kListeningVoiceActivityThreshold;
}

void Application::NotifyBleRelayDeviceState() {
    auto& board = Board::GetInstance();
    if (board.GetConnectivityMode() != ConnectivityMode::kBleRelay) {
        return;
    }

    auto& relay = BleRelayManager::GetInstance();
    if (!relay.IsConnected()) {
        return;
    }

    const bool ready = device_state_ == kDeviceStateIdle ||
        device_state_ == kDeviceStateConnecting ||
        device_state_ == kDeviceStateListening ||
        device_state_ == kDeviceStateSpeaking;

    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "event", "device_state");
    cJSON_AddStringToObject(root, "state", STATE_STRINGS[device_state_]);
    cJSON_AddBoolToObject(root, "ready", ready);

    // Battery information
    int battery_level = -1;
    bool charging = false;
    bool discharging = false;
    if (board.GetBatteryLevel(battery_level, charging, discharging)) {
        cJSON_AddNumberToObject(root, "battery_level", battery_level);
        cJSON_AddBoolToObject(root, "battery_charging", charging);
    }

    // Volume information
    auto codec = board.GetAudioCodec();
    if (codec != nullptr) {
        cJSON_AddNumberToObject(root, "volume", codec->output_volume());
    }

    char* text = cJSON_PrintUnformatted(root);
    if (text != nullptr) {
        ESP_LOGI(TAG, "Publishing BLE device state: state=%s ready=%s battery=%d", STATE_STRINGS[device_state_], ready ? "true" : "false", battery_level);
        relay.SendJsonFrame(BleRelayFrameType::kSocketEvent, 0, 0, text);
        cJSON_free(text);
    }
    cJSON_Delete(root);
}

void Application::SetDeviceState(DeviceState state) {
    if (device_state_ == state) {
        return;
    }
    
    clock_ticks_ = 0;
    auto previous_state = device_state_;
    device_state_ = state;
    ESP_LOGI(TAG, "STATE: %s", STATE_STRINGS[device_state_]);
    // The state is changed, wait for all background tasks to finish
    background_task_->WaitForCompletion();

    auto& board = Board::GetInstance();
    auto display = board.GetDisplay();
    auto led = board.GetLed();
    led->OnStateChanged();
    switch (state) {
        case kDeviceStateUnknown:
        case kDeviceStateIdle:
            display->SetStatus(Lang::Strings::STANDBY);
            display->SetEmotion("neutral");
#if CONFIG_USE_AUDIO_PROCESSOR
            audio_processor_.Stop();
#endif
#if CONFIG_USE_WAKE_WORD_DETECT
            wake_word_detect_.StartDetection();
#endif
            break;
        case kDeviceStateWifiConfiguring:
            display->SetStatus(Lang::Strings::WIFI_CONFIG_MODE);
            display->SetEmotion("neutral");
#if CONFIG_USE_AUDIO_PROCESSOR
            audio_processor_.Stop();
#endif
#if CONFIG_USE_WAKE_WORD_DETECT
            wake_word_detect_.StartDetection();
#endif
            break;
        case kDeviceStateBleConfiguring:
            display->SetStatus(Lang::Strings::BLE_RELAY_MODE);
            display->SetEmotion("neutral");
#if CONFIG_USE_AUDIO_PROCESSOR
            audio_processor_.Stop();
#endif
#if CONFIG_USE_WAKE_WORD_DETECT
            wake_word_detect_.StartDetection();
#endif
            break;
        case kDeviceStateConnecting:
            display->SetStatus(Lang::Strings::CONNECTING);
            display->SetEmotion("neutral");
            display->SetChatMessage("system", "");
            break;
        case kDeviceStateListening:
            if (previous_state != kDeviceStateListening) {
                auto now = std::chrono::steady_clock::now();
                listening_started_time_ = now;
                last_listening_activity_time_ = now;
                listening_idle_timed_out_ = false;
            }
            display->SetStatus(Lang::Strings::LISTENING);
            display->SetEmotion("neutral");

            // Update the IoT states before sending the start listening command
            UpdateIotStates();

            // Make sure the audio processor is running
#if CONFIG_USE_AUDIO_PROCESSOR
            if (!audio_processor_.IsRunning()) {
#else
            if (true) {
#endif
                // Send the start listening command
                protocol_->SendStartListening(listening_mode_);
                if (listening_mode_ == kListeningModeAutoStop && previous_state == kDeviceStateSpeaking) {
                    // FIXME: Wait for the speaker to empty the buffer
                    vTaskDelay(pdMS_TO_TICKS(120));
                }
                opus_encoder_->ResetState();
#if CONFIG_USE_WAKE_WORD_DETECT
                wake_word_detect_.StopDetection();
#endif
#if CONFIG_USE_AUDIO_PROCESSOR
                audio_processor_.Start();
#endif
            }
            break;
        case kDeviceStateSpeaking:
            display->SetStatus(Lang::Strings::SPEAKING);

            if (listening_mode_ != kListeningModeRealtime) {
#if CONFIG_USE_AUDIO_PROCESSOR
                audio_processor_.Stop();
#endif
#if CONFIG_USE_WAKE_WORD_DETECT
                wake_word_detect_.StartDetection();
#endif
            }
            ResetDecoder();
            break;
        default:
            // Do nothing
            break;
    }

    NotifyBleRelayDeviceState();
}

void Application::ResetDecoder() {
    std::lock_guard<std::mutex> lock(mutex_);
    opus_decoder_->ResetState();
    audio_decode_queue_.clear();
    audio_decode_cv_.notify_all();
    last_output_time_ = std::chrono::steady_clock::now();
    
    auto codec = Board::GetInstance().GetAudioCodec();
    codec->EnableOutput(true);
}

void Application::SetDecodeSampleRate(int sample_rate, int frame_duration) {
    if (opus_decoder_->sample_rate() == sample_rate && opus_decoder_->duration_ms() == frame_duration) {
        return;
    }

    opus_decoder_.reset();
    opus_decoder_ = std::make_unique<OpusDecoderWrapper>(sample_rate, 1, frame_duration);

    auto codec = Board::GetInstance().GetAudioCodec();
    if (opus_decoder_->sample_rate() != codec->output_sample_rate()) {
        ESP_LOGI(TAG, "Resampling audio from %d to %d", opus_decoder_->sample_rate(), codec->output_sample_rate());
        output_resampler_.Configure(opus_decoder_->sample_rate(), codec->output_sample_rate());
    }
}

void Application::UpdateIotStates() {
    auto& thing_manager = iot::ThingManager::GetInstance();
    std::string states;
    if (thing_manager.GetStatesJson(states, true)) {
        protocol_->SendIotStates(states);
    }
}

void Application::Reboot() {
    ESP_LOGI(TAG, "Rebooting...");
    esp_restart();
}

void Application::WakeWordInvoke(const std::string& wake_word) {
    if (device_state_ == kDeviceStateIdle) {
        ToggleChatState();
        Schedule([this, wake_word]() {
            if (protocol_) {
                protocol_->SendWakeWordDetected(wake_word); 
            }
        }); 
    } else if (device_state_ == kDeviceStateSpeaking) {
        Schedule([this]() {
            AbortSpeaking(kAbortReasonNone);
        });
    } else if (device_state_ == kDeviceStateListening) {   
        Schedule([this]() {
            if (protocol_) {
                protocol_->CloseAudioChannel();
            }
        });
    }
}

bool Application::CanEnterSleepMode() {
    if (device_state_ != kDeviceStateIdle) {
        return false;
    }

    if (protocol_ && protocol_->IsAudioChannelOpened()) {
        return false;
    }

    // Now it is safe to enter sleep mode
    return true;
}

bool Application::UpgradeFirmware(const std::string& url, const std::string& version) {
    auto& board = Board::GetInstance();
    auto display = board.GetDisplay();

    std::string upgrade_url = url;
    std::string version_info = version.empty() ? "(Manual upgrade)" : version;

    if (protocol_ && protocol_->IsAudioChannelOpened()) {
        ESP_LOGI(TAG, "Closing audio channel before firmware upgrade");
        protocol_->CloseAudioChannel();
    }
    ESP_LOGI(TAG, "Starting firmware upgrade from URL: %s", upgrade_url.c_str());

    Alert(Lang::Strings::OTA_UPGRADE, Lang::Strings::UPGRADING, "download", Lang::Sounds::P3_UPGRADE);
    
    SetDeviceState(kDeviceStateUpgrading);

    std::string message = std::string(Lang::Strings::NEW_VERSION) + version_info;
    display->SetChatMessage("system", message.c_str());

    if (audio_loop_task_handle_) {
        vTaskSuspend(audio_loop_task_handle_);
    }

    vTaskDelay(pdMS_TO_TICKS(1000));

    bool upgrade_success = Ota::Upgrade(upgrade_url, [display](int progress, size_t speed) {
        char buffer[64];
        snprintf(buffer, sizeof(buffer), "%d%% %uKB/s", progress, speed / 1024);
        Application::GetInstance().Schedule([display, buffer_str = std::string(buffer)]() {
             display->SetChatMessage("system", buffer_str.c_str());
        });
    });

    if (audio_loop_task_handle_) {
        vTaskResume(audio_loop_task_handle_);
    }

    if (!upgrade_success) {
        ESP_LOGE(TAG, "Firmware upgrade failed");
        Alert(Lang::Strings::ERROR, Lang::Strings::UPGRADE_FAILED, "circle_xmark", Lang::Sounds::P3_EXCLAMATION);
        vTaskDelay(pdMS_TO_TICKS(3000));
        SetDeviceState(kDeviceStateIdle); 
        return false;
    } else {
        ESP_LOGI(TAG, "Firmware upgrade successful, rebooting...");
        display->SetChatMessage("system", "Upgrade successful, rebooting...");
        vTaskDelay(pdMS_TO_TICKS(1000));
        Reboot();
        return true;
    }
}

void Application::ShowActivationCode(const std::string& code, const std::string& message) {
    struct digit_sound {
        char digit;
        const std::string_view& sound;
    };
    static const std::array<digit_sound, 10> digit_sounds{{
        digit_sound{'0', Lang::Sounds::P3_0},
        digit_sound{'1', Lang::Sounds::P3_1}, 
        digit_sound{'2', Lang::Sounds::P3_2},
        digit_sound{'3', Lang::Sounds::P3_3},
        digit_sound{'4', Lang::Sounds::P3_4},
        digit_sound{'5', Lang::Sounds::P3_5},
        digit_sound{'6', Lang::Sounds::P3_6},
        digit_sound{'7', Lang::Sounds::P3_7},
        digit_sound{'8', Lang::Sounds::P3_8},
        digit_sound{'9', Lang::Sounds::P3_9}
    }};

    Alert(Lang::Strings::ACTIVATION, message.c_str(), "link", Lang::Sounds::P3_ACTIVATION);

    for (const auto& digit : code) {
        auto it = std::find_if(digit_sounds.begin(), digit_sounds.end(),
            [digit](const digit_sound& ds) { return ds.digit == digit; });
        if (it != digit_sounds.end()) {
            PlaySound(it->sound);
        }
    }
}

void Application::ShowPairCode(const std::string& code, const std::string& message) {
    struct digit_sound {
        char digit;
        const std::string_view& sound;
    };
    static const std::array<digit_sound, 10> digit_sounds{{
        digit_sound{'0', Lang::Sounds::P3_0},
        digit_sound{'1', Lang::Sounds::P3_1},
        digit_sound{'2', Lang::Sounds::P3_2},
        digit_sound{'3', Lang::Sounds::P3_3},
        digit_sound{'4', Lang::Sounds::P3_4},
        digit_sound{'5', Lang::Sounds::P3_5},
        digit_sound{'6', Lang::Sounds::P3_6},
        digit_sound{'7', Lang::Sounds::P3_7},
        digit_sound{'8', Lang::Sounds::P3_8},
        digit_sound{'9', Lang::Sounds::P3_9}
    }};

    auto display = Board::GetInstance().GetDisplay();
    display->SetStatus(Lang::Strings::BLE_RELAY_MODE);
    display->SetEmotion("link");
    display->SetChatMessage("system", message.c_str());

    auto codec = Board::GetInstance().GetAudioCodec();
    ESP_LOGI(TAG, "ShowPairCode code=%s output_enabled=%s output_volume=%d",
        code.c_str(), codec->output_enabled() ? "true" : "false", codec->output_volume());
    if (!codec->output_enabled()) {
        ESP_LOGW(TAG, "Audio output was disabled before pair code playback, enabling it");
        codec->EnableOutput(true);
    }

    ResetDecoder();
    for (const auto& digit : code) {
        auto it = std::find_if(digit_sounds.begin(), digit_sounds.end(),
            [digit](const digit_sound& ds) { return ds.digit == digit; });
        if (it != digit_sounds.end()) {
            ESP_LOGI(TAG, "ShowPairCode playing digit=%c", digit);
            PlaySound(it->sound);
        }
    }
}
