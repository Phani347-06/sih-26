#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <OneWire.h>
#include <DallasTemperature.h>
#include <time.h>
#include <mbedtls/md.h>

// ==================== SENSOR PINS ====================
#define TURBIDITY_PIN 34
#define DS18B20_PIN 4

// ==================== WIFI DETAILS ====================
const char* WIFI_SSID = "IRON MAN";
const char* WIFI_PASSWORD = "12345678";

// Enter Laptop 2's current IPv4 address
const char* SERVER_URL = "http://10.124.3.219:5000/api/sensor";

// Must match SECRET_KEY in receiver.py exactly
const char* HMAC_KEY = "R7mQ2vL9xK4pT8nW5cY1aB6dF3hJ0sZq";

const char* DEVICE_ID = "ESP32_SENSOR_01";

// ==================== DS18B20 SETUP ====================
OneWire oneWire(DS18B20_PIN);
DallasTemperature temperatureSensor(&oneWire);

// ==================== VARIABLES ====================
uint32_t sequenceNumber = 0;

const time_t MIN_VALID_TIMESTAMP = 1700000000;

// ==================== SYNCHRONIZE TIME ====================
bool synchronizeTime() {
  if (time(nullptr) >= MIN_VALID_TIMESTAMP) {
    return true;
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("Cannot synchronize time: Wi-Fi disconnected.");
    return false;
  }

  Serial.println("Synchronizing time with NTP servers...");

  // IST offset: UTC + 5 hours 30 minutes.
  // time(nullptr) still returns the Unix timestamp.
  configTime(19800, 0, "pool.ntp.org", "time.google.com");

  unsigned long syncStart = millis();
  time_t now = time(nullptr);

  while (now < MIN_VALID_TIMESTAMP &&
         millis() - syncStart < 15000UL) {
    delay(500);
    Serial.print(".");
    now = time(nullptr);
  }

  Serial.println();

  if (now < MIN_VALID_TIMESTAMP) {
    Serial.println("ERROR: Time synchronization failed.");
    Serial.println("Check hotspot internet access and NTP connectivity.");
    return false;
  }

  Serial.println("Time synchronized successfully.");
  Serial.print("Unix timestamp: ");
  Serial.println((long long)now);

  return true;
}

// ==================== GENERATE HMAC-SHA256 ====================
String generateHMAC(const String& message) {
  unsigned char hmacResult[32];

  const mbedtls_md_info_t* mdInfo =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  if (mdInfo == nullptr) {
    Serial.println("ERROR: SHA256 initialization failed!");
    return "";
  }

  int result = mbedtls_md_hmac(
      mdInfo,
      (const unsigned char*)HMAC_KEY,
      strlen(HMAC_KEY),
      (const unsigned char*)message.c_str(),
      message.length(),
      hmacResult
  );

  if (result != 0) {
    Serial.println("ERROR: HMAC generation failed!");
    return "";
  }

  String hmacHex;
  hmacHex.reserve(64);

  for (int i = 0; i < 32; i++) {
    if (hmacResult[i] < 16) {
      hmacHex += "0";
    }

    hmacHex += String(hmacResult[i], HEX);
  }

  hmacHex.toLowerCase();
  return hmacHex;
}

// ==================== CONNECT TO WIFI ====================
void connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) {
    return;
  }

  Serial.println("\nConnecting to Wi-Fi...");

  WiFi.disconnect(true, false);
  delay(100);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  int attempts = 0;

  while (WiFi.status() != WL_CONNECTED && attempts < 30) {
    delay(500);
    Serial.print(".");
    attempts++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\nWi-Fi connected successfully!");

    Serial.print("ESP32 IP Address: ");
    Serial.println(WiFi.localIP());

    Serial.print("Server URL: ");
    Serial.println(SERVER_URL);

    synchronizeTime();
  } else {
    Serial.println("\nWi-Fi connection failed!");
    Serial.println("Check Wi-Fi name, password, and hotspot settings.");
  }
}

// ==================== SEND SENSOR DATA ====================
void sendSensorData() {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("Wi-Fi disconnected. Reconnecting...");
    connectWiFi();

    if (WiFi.status() != WL_CONNECTED) {
      return;
    }
  }

  // Retry time synchronization whenever time is invalid.
  if (!synchronizeTime()) {
    Serial.println("Sensor data will not be transmitted.");
    Serial.println("=================================");
    return;
  }

  // Read turbidity sensor.
  int turbidityRaw = analogRead(TURBIDITY_PIN);

  // Read DS18B20 temperature.
  temperatureSensor.requestTemperatures();
  float temperatureC = temperatureSensor.getTempCByIndex(0);

  Serial.println("\n========== SENSOR DATA ==========");
  Serial.print("Turbidity Raw Value: ");
  Serial.println(turbidityRaw);

  if (temperatureC == DEVICE_DISCONNECTED_C) {
    Serial.println("DS18B20 Error: Sensor not detected!");
    Serial.println("Fix the DS18B20 connection before transmission.");
    Serial.println("=================================");
    return;
  }

  Serial.print("Temperature: ");
  Serial.print(temperatureC, 2);
  Serial.println(" °C");

  // Get current Unix timestamp after reading sensors.
  time_t now = time(nullptr);

  if (now < MIN_VALID_TIMESTAMP) {
    Serial.println("ERROR: Valid time not available.");
    Serial.println("Sensor data will not be transmitted.");
    Serial.println("=================================");
    return;
  }

  // Increment sequence number for each message.
  sequenceNumber++;

  // ==================== CREATE JSON ====================
  // Requires ArduinoJson 7.
  JsonDocument jsonDocument;

  jsonDocument["device_id"] = DEVICE_ID;
  jsonDocument["timestamp"] = (long long)now;
  jsonDocument["sequence"] = sequenceNumber;

  JsonObject sensors = jsonDocument["sensors"].to<JsonObject>();
  sensors["turbidity_raw"] = turbidityRaw;
  sensors["temperature_c"] = temperatureC;

  String jsonData;
  serializeJson(jsonDocument, jsonData);

  // ==================== GENERATE HMAC ====================
  String hmacSignature = generateHMAC(jsonData);

  if (hmacSignature.length() != 64) {
    Serial.println("ERROR: Could not generate HMAC.");
    return;
  }

  Serial.println("\nJSON Payload:");
  Serial.println(jsonData);

  Serial.print("HMAC-SHA256: ");
  Serial.println(hmacSignature);

  // ==================== SEND HTTP POST ====================
  HTTPClient http;
  http.setTimeout(5000);

  if (!http.begin(SERVER_URL)) {
    Serial.println("ERROR: Could not initialize HTTP request.");
    Serial.println("=================================");
    return;
  }

  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-HMAC-SHA256", hmacSignature);

  Serial.println("\nSending data to Laptop 2...");
  int httpResponseCode = http.POST(jsonData);

  if (httpResponseCode > 0) {
    Serial.print("HTTP Response Code: ");
    Serial.println(httpResponseCode);

    String response = http.getString();

    Serial.print("Server Response: ");
    Serial.println(response);

    if (httpResponseCode == 200) {
      Serial.println("SUCCESS: Data authenticated by server!");
    } else {
      Serial.println("Server rejected or could not process the data.");
    }
  } else {
    Serial.print("HTTP request failed: ");
    Serial.println(http.errorToString(httpResponseCode));
  }

  http.end();
  Serial.println("=================================");
}

// ==================== SETUP ====================
void setup() {
  Serial.begin(115200);
  analogReadResolution(12);
  temperatureSensor.begin();

  Serial.println("\n================================");
  Serial.println(" ESP32 SENSOR SECURITY SYSTEM");
  Serial.println(" Turbidity + DS18B20");
  Serial.println(" Wi-Fi + JSON + HMAC-SHA256");
  Serial.println("================================");

  Serial.print("DS18B20 sensors detected: ");
  Serial.println(temperatureSensor.getDeviceCount());

  connectWiFi();
}

// ==================== MAIN LOOP ====================
void loop() {
  if (WiFi.status() == WL_CONNECTED) {
    sendSensorData();

    // Wait between transmission attempts.
    delay(5000);
  } else {
    Serial.println("Wi-Fi not connected. Attempting reconnection...");
    connectWiFi();

    if (WiFi.status() != WL_CONNECTED) {
      delay(10000);
    }
  }
}