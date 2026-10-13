#include <Wire.h>
#include <math.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SSD1306.h>
#include <hd44780.h>
#include <hd44780ioClass/hd44780_I2Cexp.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include <BleKeyboard.h>
#include <BLEDevice.h>
#include <BLEUtils.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

// Screen Configuration
#define SCREEN_WIDTH 128
#define SCREEN_HEIGHT 64
#define OLED_RESET -1
Adafruit_SSD1306 display(SCREEN_WIDTH, SCREEN_HEIGHT, &Wire, OLED_RESET);
hd44780_I2Cexp lcd; 

// Hardware Pins
#define POT_PIN 33
#define JOY_Y 35
#define JOY_X 32
#define JOY_SW 23
#define BTN_1 26
#define BTN_2 27

// Navigation & OS State
int currentMenu = 0;
const int maxMenu = 11; 
bool inApp = false;
unsigned long lastMoveTime = 0;
const int debounceDelay = 250;

// App States
int auditState = 0; 
int bleInspectState = 0;
int tripwireState = 0;
int foxState = 0;

// Radio State Tracking 
bool promiscuousEnabled = false;

// Promiscuous Sniffer Variables
volatile int totalPackets = 0;
volatile int deauthPackets = 0;
volatile int eapolHits = 0;
int packetHistory[128] = {0}; 
unsigned long lastGraphUpdate = 0;

// Upgraded Memory Arrays
String probeHistory[4] = {"", "", "", ""};
char lastEapolMAC[18] = "";

// Topology Mapper Memory
char lastAssocClient[18] = "None";
char lastAssocAP[18] = "None";

// Security Memory
String tripwireMACs[30];
int tripwireCount = 0;
String foxTargetMAC = "";
int foxTargetRSSI = -100;

// Bluetooth Objects
BleKeyboard bleKeyboard("9jwaan_Deck", "Custom Build", 100);
BLEScan* pBLEScan;
BLEScanResults bleResults;

// PASSIVE RADIO SNIFFER
void snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  totalPackets++; 
  
  uint8_t fc = pkt->payload[0];

  if (fc == 0xC0 || fc == 0xA0) deauthPackets++;
  
  if (fc == 0x40) {
    if (pkt->payload[24] == 0x00) { 
      int ssidLen = pkt->payload[25];
      if (ssidLen > 0 && ssidLen < 32) {
        char tempSSID[33];
        for(int i=0; i<ssidLen; i++) tempSSID[i] = pkt->payload[26+i];
        tempSSID[ssidLen] = '\0';
        String newSSID = String(tempSSID);
        
        bool exists = false;
        for(int i=0; i<4; i++) {
          if (probeHistory[i] == newSSID) exists = true;
        }
        if (!exists) {
          for(int i=3; i>0; i--) probeHistory[i] = probeHistory[i-1];
          probeHistory[0] = newSSID;
        }
      }
    }
  }

  if ((fc & 0x0C) == 0x00) {
    uint8_t subtype = (fc & 0xF0);
    if (subtype == 0x00 || subtype == 0x20) { 
      sprintf(lastAssocClient, "%02X:%02X:%02X", pkt->payload[10], pkt->payload[11], pkt->payload[12]);
      sprintf(lastAssocAP, "%02X:%02X:%02X", pkt->payload[16], pkt->payload[17], pkt->payload[18]);
    }
  }

  if ((fc & 0x08) != 0) { 
    for (int i = 24; i < 40; i++) {
      if (pkt->payload[i] == 0x88 && pkt->payload[i+1] == 0x8E) {
        eapolHits++;
        sprintf(lastEapolMAC, "%02X:%02X:%02X:**:**:**", pkt->payload[10], pkt->payload[11], pkt->payload[12]); 
        break;
      }
    }
  }
}

void setup() {
  Serial.begin(115200);
  
  pinMode(JOY_SW, INPUT_PULLUP);
  pinMode(BTN_1, INPUT_PULLUP);
  pinMode(BTN_2, INPUT_PULLUP);

  Wire.begin();
  Wire.setClock(50000); 
  delay(500); 

  lcd.begin(16, 2);
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("9jwaan OS v9.0");
  lcd.setCursor(0, 1);
  lcd.print("Initializing...");

  if(!display.begin(SSD1306_SWITCHCAPVCC, 0x3C)) {
    Serial.println("OLED Fail");
  } else {
    display.clearDisplay();
    display.setTextSize(1);
    display.setTextColor(WHITE);
    display.setCursor(15, 20);
    display.println("9jwaan OS LOADED");
    display.display();
    delay(1000);
  }

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();

  bleKeyboard.begin();
  BLEDevice::init("");
  pBLEScan = BLEDevice::getScan(); 
  pBLEScan->setActiveScan(true); 
  pBLEScan->setInterval(100);
  pBLEScan->setWindow(99); 
  
  esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
  
  lcd.clear();
}

void loop() {
  int navValue = analogRead(JOY_X); 
  bool actionBtn = (digitalRead(BTN_1) == LOW || digitalRead(BTN_2) == LOW);
  bool backBtn = (digitalRead(JOY_SW) == LOW);

  if (!inApp) {
    if (promiscuousEnabled) {
      esp_wifi_set_promiscuous(false);
      promiscuousEnabled = false;
    }
    drawMainMenu();
    handleMenuNavigation(navValue, actionBtn);
  } else {
    runApp(navValue, actionBtn, backBtn);
  }
}

void handleMenuNavigation(int navValue, bool selectPressed) {
  if (millis() - lastMoveTime > debounceDelay) {
    if (navValue < 1000) { 
      currentMenu++; 
      if (currentMenu > maxMenu) currentMenu = 0;
      lastMoveTime = millis();
    } else if (navValue > 3000) { 
      currentMenu--; 
      if (currentMenu < 0) currentMenu = maxMenu;
      lastMoveTime = millis();
    }
  }

  if (selectPressed) {
    inApp = true;
    lcd.clear();
    display.clearDisplay();
    
    totalPackets = 0; deauthPackets = 0; eapolHits = 0;
    auditState = 0; bleInspectState = 0; tripwireState = 0; foxState = 0;
    for(int i=0; i<4; i++) probeHistory[i] = "";
    for(int i=0; i<128; i++) packetHistory[i] = 0;
    pBLEScan->clearResults();
    
    delay(300); 
  }
}

void drawMainMenu() {
  display.clearDisplay();
  display.setTextSize(1);
  display.setTextColor(WHITE);
  display.setCursor(0, 0);
  display.println("== 9jwaan OS v9 ==");
  display.drawLine(0, 10, 128, 10, WHITE);

  String menus[] = {
    "1. Network Auditor", 
    "2. Ghost Tracker",
    "3. EAPOL Intercept",
    "4. Threat Sentinel", 
    "5. BLE Radar",
    "6. BLE Inspector",
    "7. Digital Tripwire",
    "8. Fox Hunter",
    "9. IoT Profiler",
    "10. Assoc Mapper",
    "11. RF Noise Log",
    "12. DAW/Media Deck"
  };
  
  int startIndex = currentMenu;
  if (startIndex > maxMenu - 2) startIndex = maxMenu - 2; 

  for (int i = 0; i < 3; i++) {
    int menuIndex = startIndex + i;
    if (menuIndex == currentMenu) {
      display.setTextColor(BLACK, WHITE); 
    } else {
      display.setTextColor(WHITE, BLACK);
    }
    display.setCursor(5, 18 + (i * 14));
    display.print(menus[menuIndex]);
  }
  display.display();

  lcd.setCursor(0, 0);
  lcd.print("SYSTEM: READY   ");
  lcd.setCursor(0, 1);
  lcd.print("Awaiting Vector ");
}

void runApp(int navValue, bool action, bool back) {
  if (back) {
    inApp = false;
    lcd.clear();
    delay(300);
    return;
  }

  switch (currentMenu) {
    case 0: appNetworkAuditor(navValue, action); break;
    case 1: appGhostTracker(); break;
    case 2: appEapolInterceptor(); break;
    case 3: appThreatSentinel(); break;
    case 4: appBLERadar(); break;
    case 5: appBLEInspector(navValue, action); break;
    case 6: appTripwire(action); break;
    case 7: appFoxHunter(navValue, action); break;
    case 8: appIoTProfiler(action); break;
    case 9: appAssocMapper(); break;
    case 10: appNoiseLogger(); break;
    case 11: appBLEMedia(action); break;
  }
}

// --- APP 1: NETWORK AUDITOR ---
void appNetworkAuditor(int navValue, bool action) {
  static int selectedIndex = 0;
  static int totalNetworks = 0;
  static unsigned long lastJoyTime = 0;

  if (auditState == 0) {
    display.clearDisplay(); display.setTextColor(WHITE);
    display.setCursor(0, 25); display.print("SWEEPING 2.4GHz..."); display.display();
    lcd.setCursor(0,0); lcd.print("MOD: WiFi Audit ");
    lcd.setCursor(0,1); lcd.print("Gathering Macs..");
    totalNetworks = WiFi.scanNetworks(false, false, false, 120); 
    if (totalNetworks < 0) totalNetworks = 0;
    selectedIndex = 0; auditState = 1; delay(200); 
  } 
  else if (auditState == 1) {
    if (millis() - lastJoyTime > 200) {
      if (navValue < 1000) { selectedIndex++; lastJoyTime = millis(); }
      else if (navValue > 3000) { selectedIndex--; lastJoyTime = millis(); }
      if (selectedIndex < 0) selectedIndex = totalNetworks - 1;
      if (selectedIndex >= totalNetworks) selectedIndex = 0;
    }

    if (action && totalNetworks > 0) { auditState = 2; delay(300); }

    display.clearDisplay(); display.setCursor(0,0);
    display.print("TARGET LIST ("); display.print(totalNetworks); display.println(")");
    display.drawLine(0, 9, 128, 9, WHITE);

    int startIndex = selectedIndex;
    if (startIndex > totalNetworks - 4 && totalNetworks >= 4) startIndex = totalNetworks - 4;
    else if (totalNetworks < 4) startIndex = 0;

    for (int i = 0; i < 4 && (startIndex + i) < totalNetworks; i++) {
        int netIdx = startIndex + i;
        if (netIdx == selectedIndex) display.setTextColor(BLACK, WHITE);
        else display.setTextColor(WHITE, BLACK);
        display.setCursor(0, 15 + (i * 12));
        String ssid = WiFi.SSID(netIdx);
        if (ssid.length() > 14) ssid = ssid.substring(0, 14);
        display.print(ssid); display.print(" "); display.print(WiFi.RSSI(netIdx));
    }
    display.display();

    lcd.setCursor(0,0); lcd.print("Action: LOCK ON ");
    lcd.setCursor(0,1); lcd.print("Target: ");
    lcd.print(totalNetworks > 0 ? selectedIndex + 1 : 0);
    lcd.print("/"); lcd.print(totalNetworks); lcd.print("   ");
  } 
  else if (auditState == 2) {
     if (action) {
        auditState = 1; esp_wifi_set_promiscuous(false); promiscuousEnabled = false;
        delay(300); return;
     }

     if (!promiscuousEnabled) {
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_channel(WiFi.channel(selectedIndex), WIFI_SECOND_CHAN_NONE);
        promiscuousEnabled = true;
     }

     if (millis() - lastGraphUpdate > 150) {
       for (int i = 0; i < 127; i++) packetHistory[i] = packetHistory[i + 1];
       packetHistory[127] = totalPackets;
       totalPackets = 0; lastGraphUpdate = millis();
     }

     display.clearDisplay(); display.setTextColor(WHITE);
     display.setCursor(0,0); display.print("ID: "); display.println(WiFi.SSID(selectedIndex).substring(0, 16));
     display.setCursor(0, 11); display.print("CH:"); display.print(WiFi.channel(selectedIndex));
     display.print(" RSSI:"); display.println(WiFi.RSSI(selectedIndex));
     
     display.setCursor(0, 22); display.print("SEC:");
     switch(WiFi.encryptionType(selectedIndex)) {
        case WIFI_AUTH_OPEN: display.print("OPEN(VULN)"); break;
        case WIFI_AUTH_WEP: display.print("WEP(VULN)"); break;
        case WIFI_AUTH_WPA_PSK: display.print("WPA"); break;
        case WIFI_AUTH_WPA2_PSK: display.print("WPA2"); break;
        default: display.print("UNKNOWN"); break;
     }

     display.drawLine(0, 32, 128, 32, WHITE);
     for (int x = 0; x < 127; x++) {
       int y1 = 63 - map(packetHistory[x], 0, 50, 0, 30);
       int y2 = 63 - map(packetHistory[x + 1], 0, 50, 0, 30);
       if (y1 < 34) y1 = 34; if (y2 < 34) y2 = 34;
       display.drawLine(x, y1, x + 1, y2, WHITE);
     }
     display.display();

     lcd.setCursor(0,0); lcd.print("MONITORING TRFC ");
     lcd.setCursor(0,1); lcd.print("Action: UNLOCK  ");
  }
}

// --- APP 2: GHOST TRACKER ---
void appGhostTracker() {
  if (!promiscuousEnabled) { esp_wifi_set_promiscuous(true); promiscuousEnabled = true; }
  display.clearDisplay(); display.setTextColor(WHITE);
  display.setCursor(0, 0); display.println("PROBE INTERCEPTS");
  display.drawLine(0, 10, 128, 10, WHITE);
  for (int i = 0; i < 4; i++) {
    display.setCursor(0, 15 + (i * 12));
    if (probeHistory[i] != "") { display.print("> "); display.print(probeHistory[i]); } 
    else { display.print("-"); }
  }
  display.display();
  lcd.setCursor(0, 0); lcd.print("MOD: Ghost Track");
  lcd.setCursor(0, 1); lcd.print("Intercepting... ");
}

// --- APP 3: EAPOL INTERCEPTOR ---
void appEapolInterceptor() {
  if (!promiscuousEnabled) { esp_wifi_set_promiscuous(true); promiscuousEnabled = true; }
  display.clearDisplay(); display.setTextColor(WHITE);
  display.setCursor(0, 0); display.println("EAPOL INTERCEPT");
  display.drawLine(0, 10, 128, 10, WHITE);
  if (eapolHits > 0) {
      display.fillRect(0, 20, 128, 15, WHITE); display.setTextColor(BLACK, WHITE);
      display.setCursor(10, 24); display.println("HANDSHAKE CAUGHT!");
      display.setTextColor(WHITE, BLACK); display.setCursor(0, 42);
      display.print("Count: "); display.println(eapolHits);
      display.print("SRC: "); display.println(lastEapolMAC);
      lcd.setCursor(0,0); lcd.print(">>> CAUGHT! <<<<");
      lcd.setCursor(0,1); lcd.print("WPA2 Handshake! ");
  } else {
      display.setCursor(0, 30); display.println("Waiting for auth...");
      lcd.setCursor(0,0); lcd.print("MOD: EAPOL Sniff");
      lcd.setCursor(0,1); lcd.print("Listening...    ");
  }
  display.display();
}

// --- APP 4: THREAT SENTINEL ---
void appThreatSentinel() {
  if (!promiscuousEnabled) { esp_wifi_set_promiscuous(true); promiscuousEnabled = true; }
  if (millis() - lastGraphUpdate > 200) {
    for (int i = 0; i < 127; i++) packetHistory[i] = packetHistory[i + 1];
    packetHistory[127] = totalPackets; totalPackets = 0; lastGraphUpdate = millis();
  }
  display.clearDisplay(); display.setTextColor(WHITE);
  display.setCursor(0, 0); display.print("TRAFFIC MON [DEAUTH]");
  display.drawLine(0, 9, 128, 9, WHITE);
  for (int x = 0; x < 127; x++) {
    int y1 = 63 - map(packetHistory[x], 0, 50, 0, 50);
    int y2 = 63 - map(packetHistory[x + 1], 0, 50, 0, 50);
    if (y1 < 12) y1 = 12; if (y2 < 12) y2 = 12;
    display.drawLine(x, y1, x + 1, y2, WHITE);
  }
  display.display();
  if (deauthPackets > 5) {
    lcd.setCursor(0, 0); lcd.print(">> WARNING! <<  ");
    lcd.setCursor(0, 1); lcd.print("DEAUTH ATTACK!  ");
  } else {
    lcd.setCursor(0, 0); lcd.print("SENTINEL: ACTIVE");
    lcd.setCursor(0, 1); lcd.print("Deauth Count: "); lcd.print(deauthPackets);
  }
}

// --- APP 5: SPATIAL BLE RADAR ---
void appBLERadar() {
  int maxRange = map(analogRead(POT_PIN), 0, 4095, -100, -30); 
  static float angle = 0; angle += 0.3; if (angle > 6.28) angle = 0;
  display.clearDisplay();
  int centerX = 64, centerY = 36, radius = 26;
  display.drawCircle(centerX, centerY, radius, WHITE);
  display.drawCircle(centerX, centerY, radius / 2, WHITE);
  display.drawLine(centerX - radius, centerY, centerX + radius, centerY, WHITE);
  display.drawLine(centerX, centerY - radius, centerX, centerY + radius, WHITE);
  display.drawLine(centerX, centerY, centerX + cos(angle)*radius, centerY + sin(angle)*radius, WHITE);
  BLEScanResults foundDevices = pBLEScan->start(1, false);
  int count = foundDevices.getCount();
  for (int i = 0; i < count && i < 8; i++) {
    int rssi = foundDevices.getDevice(i).getRSSI();
    if (rssi >= maxRange) {
      int distance = map(rssi, -100, -30, radius, 4);
      float devAngle = (i * (6.28 / 8)); 
      display.fillCircle(centerX + cos(devAngle)*distance, centerY + sin(devAngle)*distance, 2, WHITE);
    }
  }
  display.setCursor(0, 0); display.setTextColor(WHITE);
  display.print("RADAR Cutoff:"); display.print(maxRange);
  display.display();
  pBLEScan->clearResults();
  lcd.setCursor(0, 0); lcd.print("MOD: BLE Radar  ");
  lcd.setCursor(0, 1); lcd.print("Targets: "); lcd.print(count); lcd.print("     ");
}

// --- APP 6: BLE INSPECTOR ---
void appBLEInspector(int navValue, bool action) {
  static int selIdx = 0; static int totalBLE = 0; static unsigned long lastTime = 0;
  if (bleInspectState == 0) {
      display.clearDisplay(); display.setTextColor(WHITE);
      display.setCursor(0, 25); display.print("SWEEPING BLE..."); display.display();
      lcd.setCursor(0,0); lcd.print("MOD: BLE Inspect");
      lcd.setCursor(0,1); lcd.print("Gathering MACs..");
      bleResults = pBLEScan->start(2, false);
      totalBLE = bleResults.getCount(); selIdx = 0; bleInspectState = 1; delay(200);
  } 
  else if (bleInspectState == 1) {
      if (millis() - lastTime > 200) {
          if (navValue < 1000) { selIdx++; lastTime = millis(); }
          else if (navValue > 3000) { selIdx--; lastTime = millis(); }
          if (selIdx < 0) selIdx = totalBLE - 1;
          if (selIdx >= totalBLE) selIdx = 0;
      }
      if (action && totalBLE > 0) { bleInspectState = 2; delay(300); }
      display.clearDisplay(); display.setCursor(0,0);
      display.print("BLE TARGETS ("); display.print(totalBLE); display.println(")");
      display.drawLine(0, 9, 128, 9, WHITE);
      int sIdx = selIdx;
      if (sIdx > totalBLE - 4 && totalBLE >= 4) sIdx = totalBLE - 4;
      else if (totalBLE < 4) sIdx = 0;
      for(int i = 0; i < 4 && (sIdx + i) < totalBLE; i++) {
          int nIdx = sIdx + i;
          if (nIdx == selIdx) display.setTextColor(BLACK, WHITE);
          else display.setTextColor(WHITE, BLACK);
          BLEAdvertisedDevice dev = bleResults.getDevice(nIdx);
          display.setCursor(0, 15 + (i * 12));
          display.print(dev.getAddress().toString().c_str());
          display.print(" "); display.print(dev.getRSSI());
      }
      display.display();
      lcd.setCursor(0,0); lcd.print("Action: INSPECT ");
      lcd.setCursor(0,1); lcd.print("Target: "); lcd.print(totalBLE > 0 ? selIdx + 1 : 0);
      lcd.print("/"); lcd.print(totalBLE); lcd.print("   ");
  } 
  else if (bleInspectState == 2) {
      if (action) { bleInspectState = 1; delay(300); return; }
      display.clearDisplay(); display.setTextColor(WHITE);
      display.setCursor(0,0); display.println("PACKET DECODER");
      display.drawLine(0,9,128,9,WHITE);
      BLEAdvertisedDevice dev = bleResults.getDevice(selIdx);
      display.setCursor(0, 15); display.print("NAME: ");
      if (dev.haveName()) {
          String name = dev.getName().c_str();
          if(name.length() > 14) name = name.substring(0, 14);
          display.print(name);
      } else { display.print("[Hidden]"); }
      display.setCursor(0, 30); display.print("MAC: "); display.print(dev.getAddress().toString().c_str());
      display.setCursor(0, 45); display.print("MFG: ");
      if (dev.haveManufacturerData()) {
          std::string mfgData = dev.getManufacturerData();
          if (mfgData.length() >= 2) {
             uint16_t mfgId = (mfgData[1] << 8) | mfgData[0];
             if (mfgId == 0x004C) display.print("Apple Inc.");
             else if (mfgId == 0x0006) display.print("Microsoft");
             else if (mfgId == 0x012D) display.print("Sony");
             else if (mfgId == 0x0075) display.print("Samsung");
             else { display.print("ID 0x"); display.print(mfgId, HEX); }
          } else { display.print("Unknown"); }
      } else { display.print("Not Broadcasted"); }
      display.display();
      lcd.setCursor(0,0); lcd.print("DECODING PAYLOAD");
      lcd.setCursor(0,1); lcd.print("Action: BACK    ");
  }
}

// --- APP 7: DIGITAL TRIPWIRE ---
void appTripwire(bool action) {
  if (tripwireState == 0) {
    display.clearDisplay(); display.setTextColor(WHITE);
    display.setCursor(0, 0); display.println("DIGITAL TRIPWIRE");
    display.drawLine(0, 10, 128, 10, WHITE);
    display.setCursor(0, 25); display.println("Action = Set Baseline");
    display.display();
    lcd.setCursor(0,0); lcd.print("MOD: Tripwire   ");
    lcd.setCursor(0,1); lcd.print("Ready to Arm... ");
    if (action) {
      display.clearDisplay(); display.setCursor(0,25); display.print("MAPPING ROOM..."); display.display();
      BLEScanResults tr = pBLEScan->start(3, false);
      tripwireCount = tr.getCount();
      if(tripwireCount > 30) tripwireCount = 30;
      for(int i=0; i<tripwireCount; i++) {
        tripwireMACs[i] = String(tr.getDevice(i).getAddress().toString().c_str());
      }
      pBLEScan->clearResults();
      tripwireState = 1; 
      delay(500);
    }
  } 
  else if (tripwireState == 1) {
    display.clearDisplay(); display.setCursor(0,0);
    display.println("TRIPWIRE ARMED"); display.drawLine(0, 10, 128, 10, WHITE);
    display.setCursor(0, 20); display.print("Baseline MACs: "); display.print(tripwireCount);
    BLEScanResults tr = pBLEScan->start(1, false);
    bool intrusion = false;
    String intruderMAC = "";
    int intruderRSSI = 0;
    for(int i=0; i<tr.getCount(); i++) {
      String mac = String(tr.getDevice(i).getAddress().toString().c_str());
      int rssi = tr.getDevice(i).getRSSI();
      if (rssi > -75) {
        bool known = false;
        for(int j=0; j<tripwireCount; j++) {
          if (tripwireMACs[j] == mac) known = true;
        }
        if (!known) {
          intrusion = true; intruderMAC = mac; intruderRSSI = rssi;
        }
      }
    }
    pBLEScan->clearResults();
    if (intrusion) {
      display.fillRect(0, 35, 128, 25, WHITE);
      display.setTextColor(BLACK, WHITE);
      display.setCursor(2, 38); display.println("INTRUSION DETECTED");
      display.setCursor(2, 48); display.print(intruderMAC); display.print(" ("); display.print(intruderRSSI); display.print(")");
      lcd.setCursor(0,0); lcd.print(">> ALERT ALERT <");
      lcd.setCursor(0,1); lcd.print("UNKNOWN DEVICE! ");
    } else {
      display.setTextColor(WHITE, BLACK);
      display.setCursor(0, 40); display.println("Scanning perimeter..");
      lcd.setCursor(0,0); lcd.print("STATUS: SECURE  ");
      lcd.setCursor(0,1); lcd.print("Perimeter Locked");
    }
    display.display();
    if(action) { tripwireState = 0; delay(300); }
  }
}

// --- APP 8: FOX HUNTER ---
void appFoxHunter(int navValue, bool action) {
  static int fIdx = 0; static int fTotal = 0; static unsigned long lastTime = 0;
  if (foxState == 0) {
      display.clearDisplay(); display.setCursor(0,25); display.print("FINDING TARGETS..."); display.display();
      lcd.setCursor(0,0); lcd.print("MOD: Fox Hunter ");
      lcd.setCursor(0,1); lcd.print("Scanning...     ");
      bleResults = pBLEScan->start(2, false);
      fTotal = bleResults.getCount(); fIdx = 0; foxState = 1; delay(200);
  }
  else if (foxState == 1) {
      if (millis() - lastTime > 200) {
          if (navValue < 1000) { fIdx++; lastTime = millis(); }
          else if (navValue > 3000) { fIdx--; lastTime = millis(); }
          if (fIdx < 0) fIdx = fTotal - 1;
          if (fIdx >= fTotal) fIdx = 0;
      }
      if (action && fTotal > 0) {
          foxTargetMAC = String(bleResults.getDevice(fIdx).getAddress().toString().c_str());
          pBLEScan->clearResults();
          foxState = 2; delay(300);
      }
      display.clearDisplay(); display.setCursor(0,0);
      display.print("SELECT TARGET ("); display.print(fTotal); display.println(")");
      display.drawLine(0, 9, 128, 9, WHITE);
      int sIdx = fIdx;
      if (sIdx > fTotal - 4 && fTotal >= 4) sIdx = fTotal - 4;
      else if (fTotal < 4) sIdx = 0;
      for(int i = 0; i < 4 && (sIdx + i) < fTotal; i++) {
          if (sIdx+i == fIdx) display.setTextColor(BLACK, WHITE);
          else display.setTextColor(WHITE, BLACK);
          BLEAdvertisedDevice dev = bleResults.getDevice(sIdx+i);
          display.setCursor(0, 15 + (i * 12));
          display.print(dev.getAddress().toString().c_str());
      }
      display.display();
      lcd.setCursor(0,0); lcd.print("Action: TRACK   ");
      lcd.setCursor(0,1); lcd.print("Target: "); lcd.print(fTotal > 0 ? fIdx + 1 : 0); lcd.print("   ");
  }
  else if (foxState == 2) {
      if(action) { foxState = 1; delay(300); return; }
      BLEScanResults rs = pBLEScan->start(1, false);
      foxTargetRSSI = -100;
      for(int i=0; i<rs.getCount(); i++) {
         if (String(rs.getDevice(i).getAddress().toString().c_str()) == foxTargetMAC) {
            foxTargetRSSI = rs.getDevice(i).getRSSI();
         }
      }
      pBLEScan->clearResults();
      display.clearDisplay(); display.setTextColor(WHITE);
      display.setCursor(0,0); display.println("GEIGER TRACKING");
      display.drawLine(0,9,128,9,WHITE);
      display.setCursor(0, 15); display.print("MAC: "); display.println(foxTargetMAC);
      display.setCursor(0, 27); display.print("RSSI: "); display.print(foxTargetRSSI); display.print(" dBm");
      display.drawRect(0, 42, 128, 16, WHITE);
      int fillWidth = map(foxTargetRSSI, -95, -40, 0, 128);
      if (fillWidth < 0) fillWidth = 0; if (fillWidth > 128) fillWidth = 128;
      display.fillRect(0, 42, fillWidth, 16, WHITE);
      display.display();
      lcd.setCursor(0,0); lcd.print("TRACKING...     ");
      lcd.setCursor(0,1);
      if (foxTargetRSSI > -50) lcd.print(">> VERY CLOSE <<");
      else if (foxTargetRSSI == -100) lcd.print("SIGNAL LOST!    ");
      else lcd.print("Move to locate. ");
  }
}

// --- APP 9: IOT PROFILER ---
void appIoTProfiler(bool action) {
  display.clearDisplay(); display.setTextColor(WHITE);
  display.setCursor(0, 0); display.println("IOT PROFILER");
  display.drawLine(0, 10, 128, 10, WHITE);
  display.setCursor(0, 20); display.println("Scanning BSSIDs...");
  display.display();
  lcd.setCursor(0,0); lcd.print("MOD: Cam Hunter ");
  lcd.setCursor(0,1); lcd.print("Checking OUIs...");
  int n = WiFi.scanNetworks(false, false, false, 80);
  int suspiciousCount = 0;
  String susMacs[3];
  String susTypes[3];
  for (int i = 0; i < n; i++) {
     String bssid = WiFi.BSSIDstr(i);
     bssid.toUpperCase();
     bool match = false;
     String type = "";
     if(bssid.startsWith("24:0A:C4") || bssid.startsWith("24:62:AB") || bssid.startsWith("24:6F:28")) {
         match = true; type = "Espressif IoT";
     } else if(bssid.startsWith("A4:DA:22")) {
         match = true; type = "Tuya Cam/Smart";
     } else if(bssid.startsWith("2C:AA:8E")) {
         match = true; type = "Wyze Camera";
     }
     if (match && suspiciousCount < 3) {
         susMacs[suspiciousCount] = bssid;
         susTypes[suspiciousCount] = type;
         suspiciousCount++;
     }
  }
  WiFi.scanDelete();
  display.clearDisplay(); display.setCursor(0,0);
  display.println("IOT PROFILER"); display.drawLine(0,10,128,10,WHITE);
  if (suspiciousCount > 0) {
      for(int i=0; i<suspiciousCount; i++) {
         display.setCursor(0, 15 + (i*16));
         display.print("!"); display.print(susTypes[i]);
         display.setCursor(10, 24 + (i*16));
         display.print(susMacs[i]);
      }
      lcd.setCursor(0,1); lcd.print(">> SUS DETECT <<");
  } else {
      display.setCursor(0, 30); display.println("Area clear.");
      display.println("No known IoT Cams.");
      lcd.setCursor(0,1); lcd.print("Clear. No Cams. ");
  }
  display.display();
  delay(1000); 
}

// --- APP 10: ASSOCIATION TOPOLOGY MAPPER ---
void appAssocMapper() {
  if (!promiscuousEnabled) { esp_wifi_set_promiscuous(true); promiscuousEnabled = true; }
  display.clearDisplay(); display.setTextColor(WHITE);
  display.setCursor(0, 0); display.println("ASSOC MAPPER");
  display.drawLine(0, 10, 128, 10, WHITE);

  display.setCursor(0, 16); display.print("Last Client Link:");
  display.setCursor(0, 28); display.println(lastAssocClient);

  display.setCursor(0, 40); display.print("Target AP OUI:");
  display.setCursor(0, 52); display.println(lastAssocAP);
  display.display();

  lcd.setCursor(0, 0); lcd.print("MOD: Assoc Map  ");
  lcd.setCursor(0, 1); lcd.print("Mapping Tree... ");
}

// --- APP 11: RF NOISE FLOOR LOGGER ---
void appNoiseLogger() {
  int noiseFloorOffset = map(analogRead(POT_PIN), 0, 4095, -100, -50);
  display.clearDisplay(); display.setTextColor(WHITE);
  display.setCursor(0, 0); display.println("RF NOISE FLOOR");
  display.drawLine(0, 10, 128, 10, WHITE);

  display.setCursor(0, 18); display.print("Threshold: "); display.print(noiseFloorOffset); display.print("dBm");
  display.setCursor(0, 32); display.print("Interference: ");
  if (noiseFloorOffset > -70) {
    display.print("HIGH (HEAVY)");
  } else if (noiseFloorOffset > -85) {
    display.print("MODERATE");
  } else {
    display.print("CLEAN / LOW");
  }

  display.drawRect(0, 48, 128, 12, WHITE);
  int w = map(noiseFloorOffset, -100, -50, 0, 128);
  display.fillRect(0, 48, w, 12, WHITE);
  display.display();

  lcd.setCursor(0, 0); lcd.print("MOD: RF Noise   ");
  lcd.setCursor(0, 1); lcd.print("Pot Adjust Gain ");
}

// --- APP 12: DAW/MEDIA DECK ---
void appBLEMedia(bool action) {
  static int lastPotVal = analogRead(POT_PIN);
  int currentPot = analogRead(POT_PIN);
  display.clearDisplay(); display.setTextColor(WHITE);
  display.setCursor(0, 0); display.println("DAW / MEDIA DECK");
  display.drawLine(0, 10, 128, 10, WHITE);
  if (bleKeyboard.isConnected()) {
    display.setCursor(0, 20); display.println("Link: SECURED");
    display.setCursor(0, 35); display.println("Action: Play/Pause");
    display.setCursor(0, 48); display.println("Pot Knob: Volume");
    if (abs(currentPot - lastPotVal) > 300) { 
      if (currentPot > lastPotVal) bleKeyboard.write(KEY_MEDIA_VOLUME_UP);
      else bleKeyboard.write(KEY_MEDIA_VOLUME_DOWN);
      lastPotVal = currentPot; delay(100); 
    }
    if (action) { bleKeyboard.write(KEY_MEDIA_PLAY_PAUSE); delay(400); }
    lcd.setCursor(0, 0); lcd.print("STATUS: LINKED  ");
    lcd.setCursor(0, 1); lcd.print("Ready for Input ");
  } else {
    display.setCursor(0, 25); display.println("Awaiting Host...");
    display.println("Pair to:"); display.println("'9jwaan_Deck'");
    lcd.setCursor(0, 0); lcd.print("STATUS: PAIRING ");
    lcd.setCursor(0, 1); lcd.print("Searching BLE...");
  }
  display.display();
}