#include <Arduino.h>
#include <ArduinoJson.h>
#include <ESP8266HTTPClient.h>
#include <ESP8266WiFi.h>
#include <Ticker.h>
#include <TimeLib.h>
#include <unordered_map>
#include <vector>
using namespace std;
extern "C" {
#include <user_interface.h>
}

#define DATA_LENGTH 112
#define DISABLE 0
#define ENABLE 1
#define TYPE_MANAGEMENT 0x00
#define TYPE_CONTROL 0x01
#define TYPE_DATA 0x02
#define SUBTYPE_PROBE_REQUEST 0x04

String deviceMAC = "";
const char *ssid = "3Durak";
const char *password = "3durak2015";
WiFiClient client;
HTTPClient http;
String encodedMAC;
String macToStr(const uint8_t *mac) {
    String result;
    for (int i = 0; i < 6; ++i) {
        char buf[3];
        sprintf(buf, "%02X", mac[i]);
        result += buf;
        if (i < 5)
            result += ':';
    }
    return result;
}
typedef struct Packet {
    String MAC;
    time_t timestamp;
    float RSSI;
    String SSID;
    //String selfMAC;

} Packet;

vector<Packet> sniffedPackets;
vector<Packet> sniffedRouters;

unordered_map<string, Packet> sweepMap;
struct RxControl {
    signed rssi : 8;  // signal intensity of packet
    unsigned rate : 4;
    unsigned is_group : 1;
    unsigned : 1;
    unsigned sig_mode : 2;        // 0:is 11n packet; 1:is not 11n packet;
    unsigned legacy_length : 12;  // if not 11n packet, shows length of packet.
    unsigned damatch0 : 1;
    unsigned damatch1 : 1;
    unsigned bssidmatch0 : 1;
    unsigned bssidmatch1 : 1;
    unsigned MCS : 7;         // if is 11n packet, shows the modulation and code used (range from 0 to 76)
    unsigned CWB : 1;         // if is 11n packet, shows if is HT40 packet or not
    unsigned HT_length : 16;  // if is 11n packet, shows length of packet.
    unsigned Smoothing : 1;
    unsigned Not_Sounding : 1;
    unsigned : 1;
    unsigned Aggregation : 1;
    unsigned STBC : 2;
    unsigned FEC_CODING : 1;  // if is 11n packet, shows if is LDPC packet or not.
    unsigned SGI : 1;
    unsigned rxend_state : 8;
    unsigned ampdu_cnt : 8;
    unsigned channel : 4;  //which channel this packet in.
    unsigned : 12;
};

struct SnifferPacket {
    struct RxControl rx_ctrl;
    uint8_t data[DATA_LENGTH];
    uint16_t cnt;
    uint16_t len;
};

// Declare each custom function (excluding built-in, such as setup and loop) before it will be called.
// https://docs.platformio.org/en/latest/faq.html#convert-arduino-file-to-c-manually
static void showMetadata(SnifferPacket *snifferPacket);
static void ICACHE_FLASH_ATTR sniffer_callback(uint8_t *buffer, uint16_t length);
static void printDataSpan(uint16_t start, uint16_t size, uint8_t *data);
static void getMAC(char *addr, uint8_t *data, uint16_t offset);
void channelHop();

static void showMetadata(SnifferPacket *snifferPacket) {
    unsigned int frameControl = ((unsigned int)snifferPacket->data[1] << 8) + snifferPacket->data[0];

    uint8_t version = (frameControl & 0b0000000000000011) >> 0;
    uint8_t frameType = (frameControl & 0b0000000000001100) >> 2;
    uint8_t frameSubType = (frameControl & 0b0000000011110000) >> 4;
    uint8_t toDS = (frameControl & 0b0000000100000000) >> 8;
    uint8_t fromDS = (frameControl & 0b0000001000000000) >> 9;

    // Only look for probe request packets
    if (frameType != TYPE_MANAGEMENT ||
        frameSubType != SUBTYPE_PROBE_REQUEST)
        return;

    Serial.print("RSSI: ");
    Serial.print(snifferPacket->rx_ctrl.rssi, DEC);

    Serial.print(" Ch: ");
    Serial.print(wifi_get_channel());

    char addr[] = "00:00:00:00:00:00";
    getMAC(addr, snifferPacket->data, 10);
    Serial.print(" Peer MAC: ");

    String str(addr);
    Serial.print(str.c_str());
    Packet sniffedPacket;
    sniffedPacket.MAC = str;
    sniffedPacket.RSSI = snifferPacket->rx_ctrl.rssi;
    sniffedPacket.timestamp = now();

    //sniffedPacket.selfMAC = deviceMAC;

    string moc = str.c_str();
    sweepMap[moc] = sniffedPacket;

    uint8_t SSID_length = snifferPacket->data[25];
    String SSID;
    for (int i = 0; i < DATA_LENGTH && i < SSID_length; i++) {
        SSID += (char)snifferPacket->data[26 + i];
    }
    sniffedPacket.SSID = SSID;

    //Serial.print(" SSID: ");
    //printDataSpan(26, SSID_length, snifferPacket->data);

    Serial.println();
    Serial.println(SSID);
}

/**
 * Callback for promiscuous mode
 */
static void ICACHE_FLASH_ATTR sniffer_callback(uint8_t *buffer, uint16_t length) {
    struct SnifferPacket *snifferPacket = (struct SnifferPacket *)buffer;
    showMetadata(snifferPacket);
}

static void printDataSpan(uint16_t start, uint16_t size, uint8_t *data) {
    for (uint16_t i = start; i < DATA_LENGTH && i < start + size; i++) {
        Serial.write(data[i]);
    }
}

static void getMAC(char *addr, uint8_t *data, uint16_t offset) {
    sprintf(addr, "%02x:%02x:%02x:%02x:%02x:%02x", data[offset + 0], data[offset + 1], data[offset + 2], data[offset + 3], data[offset + 4], data[offset + 5]);
}

#define CHANNEL_HOP_INTERVAL_MS 1000
static os_timer_t channelHop_timer;
static os_timer_t sendInfo_timer;
/**
 * Callback for channel hoping
 */
void channelHop() {
    // hoping channels 1-13
    uint8 new_channel = wifi_get_channel() + 1;

    if (new_channel > 13) {
        Serial.print("Sweep size : ");
        Serial.println(sweepMap.size());
        for (auto it : sweepMap) {
            if (it.second.SSID == "") {
                sniffedPackets.push_back(it.second);
            } else {
                sniffedRouters.push_back(it.second);
            }
        }
        sweepMap.clear();
        Serial.print("Total sniffed : ");
        Serial.println(sniffedPackets.size());
        new_channel = 1;
    }
    wifi_set_channel(new_channel);
}
int infoFlag = 0;
void sendInfo() {
    infoFlag = 1;
}
Ticker ticker;

void promiscousSetup() {
    wifi_set_opmode(STATION_MODE);
    wifi_set_channel(1);
    wifi_promiscuous_enable(DISABLE);
    delay(10);
    wifi_set_promiscuous_rx_cb(sniffer_callback);
    delay(10);
    wifi_promiscuous_enable(ENABLE);  // setup the channel hoping callback timer
    os_timer_disarm(&channelHop_timer);

    os_timer_setfn(&channelHop_timer, (os_timer_func_t *)channelHop, NULL);
    os_timer_arm(&channelHop_timer, CHANNEL_HOP_INTERVAL_MS, 1);
}

String urlencode(String str) {
    String encodedString = "";
    char c;
    char code0;
    char code1;
    char code2;
    for (int i = 0; i < str.length(); i++) {
        c = str.charAt(i);
        if (c == ' ') {
            encodedString += '+';
        } else if (isalnum(c)) {
            encodedString += c;
        } else {
            code1 = (c & 0xf) + '0';
            if ((c & 0xf) > 9) {
                code1 = (c & 0xf) - 10 + 'A';
            }
            c = (c >> 4) & 0xf;
            code0 = c + '0';
            if (c > 9) {
                code0 = c - 10 + 'A';
            }
            code2 = '\0';
            encodedString += '%';
            encodedString += code0;
            encodedString += code1;
            //encodedString+=code2;
        }
        yield();
    }
    return encodedString;
}

void setup() {
    // set the WiFi chip to "promiscuous" mode aka monitor mode
    Serial.begin(115200);
    delay(10);
    unsigned char mac[6];
    WiFi.macAddress(mac);
    deviceMAC += macToStr(mac);
    encodedMAC = urlencode(deviceMAC);
    Serial.println(encodedMAC);
    WiFi.begin(ssid, password);
    while (WiFi.status() != WL_CONNECTED) {
        delay(500);
        Serial.print(".");
    }
    Serial.println("");
    Serial.println("WiFi connected");

    StaticJsonDocument<200> deviceDoc;
    deviceDoc["MAC"] = deviceMAC;
    String deviceJSON;
    serializeJson(deviceDoc, deviceJSON);
    http.begin("http://192.168.1.120:1323/sniffers");
    http.addHeader("Content-type", "application/json");
    int deviceCode = http.POST(deviceJSON);
    Serial.println("device post status: ");
    Serial.println(deviceCode);
    http.end();

    http.begin("http://192.168.1.120:1323/time");
    http.GET();
    String payload = http.getString();
    http.end();
    StaticJsonDocument<200> doc;
    deserializeJson(doc, payload);
    int currentTime = doc["now"];
    setTime(currentTime);
    sniffedPackets.reserve(500);
    // delay(100000);
    promiscousSetup();
    ticker.attach(20, sendInfo);
}

void loop() {
    if (infoFlag == 1) {
        Serial.println("Guncel Vakit");
        Serial.println(now());
        ticker.detach();
        os_timer_disarm(&channelHop_timer);
        wifi_promiscuous_enable(DISABLE);

        Serial.println("Connecting to ");
        Serial.println(ssid);
        WiFi.begin(ssid, password);
        while (WiFi.status() != WL_CONNECTED) {
            delay(500);
            Serial.print(".");
        }
        Serial.println("");
        Serial.println("WiFi connected");
        // http.begin("http://192.168.1.120:1323/packet");
        // http.addHeader("Content-Type", "application/json");

        // DynamicJsonDocument pkt(126);

        // for (int i = 0; i < sniffedPackets.size(); i++) {
        //     JsonObject obj = pkt.to<JsonObject>();
        //     Packet sniffedPacket = sniffedPackets[i];

        //     obj["MAC"] = sniffedPacket.MAC;
        //     obj["RSSI"] = sniffedPacket.RSSI;
        //     obj["timestamp"] = sniffedPacket.timestamp;
        //     obj["selfMAC"] = deviceMAC;

        //     String json;
        //     serializeJson(obj, json);
        //     int httpCode = http.POST(json);
        //     Serial.println(httpCode);
        // }

        // http.end();

        http.begin("http://192.168.1.120:1323/sniffers/" + encodedMAC + "/packets-collection");
        unsigned numberOfPackets = sniffedPackets.size();

        DynamicJsonDocument doc(numberOfPackets + 1 + (numberOfPackets * 126));
        JsonArray ar = doc.to<JsonArray>();

        DynamicJsonDocument pkt(126);

        for (int i = 0; i < sniffedPackets.size(); i++) {
            JsonObject obj = pkt.to<JsonObject>();
            Packet sniffedPacket = sniffedPackets[i];

            obj["MAC"] = sniffedPacket.MAC;
            obj["RSSI"] = sniffedPacket.RSSI;
            obj["timestamp"] = sniffedPacket.timestamp;
            obj["snifferMAC"] = deviceMAC;

            ar.add(obj);
        }
        String json;
        serializeJson(ar, json);

        http.addHeader("Content-type", "application/json");
        int httpCode = http.POST(json);
        Serial.println("packets post status: ");
        Serial.println(httpCode);
        http.end();
        http.begin("http://192.168.1.120:1323/sniffers/" + encodedMAC + "/routers");
        numberOfPackets = sniffedRouters.size();

        DynamicJsonDocument routerDoc(numberOfPackets + 1 + (numberOfPackets * 126));
        JsonArray routerArray = routerDoc.to<JsonArray>();

        DynamicJsonDocument routerPacket(126);

        for (int i = 0; i < sniffedRouters.size(); i++) {
            JsonObject obj = pkt.to<JsonObject>();
            Packet sniffedRouter = sniffedRouters[i];

            obj["MAC"] = sniffedRouter.MAC;
            obj["timestamp"] = sniffedRouter.timestamp;

            routerArray.add(obj);
        }
        String routerJson;
        serializeJson(routerArray, routerJson);

        http.addHeader("Content-type", "application/json");
        httpCode = http.POST(json);
        Serial.println("packets post status: ");
        Serial.println(httpCode);
        http.end();

        sniffedPackets.clear();
        sniffedRouters.clear();

        infoFlag = 0;
        ticker.attach(20, sendInfo);
        WiFi.disconnect(true);
        while (WiFi.isConnected()) {
            Serial.println("Disconnecting");
            Serial.print(".");
            delay(100);
        }
        Serial.println("Disconnected successfulyy.");

        promiscousSetup();
    }
}
