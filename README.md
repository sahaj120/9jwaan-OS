# 9jwaan-OS
A dual-screen passive network telemetry and cyberdeck OS for the ESP32


# 9jwaan OS 

**9jwaan OS** is a custom, dual-screen passive network telemetry operating system built for the ESP32. Designed as an educational prototype for network security and Informatics Practices (IP), it transforms standard microcontroller hardware into a localized counter-surveillance and RF diagnostic deck.

It operates entirely passively. It does not transmit active attacks; instead, it utilizes the ESP32's promiscuous mode to intercept, parse, and map 802.11 and BLE environmental data in real-time.

##  Hardware Requirements
* **Microcontroller:** ESP32 (WROOM or WROVER)
* **Primary Display:** 0.96" I2C OLED (SSD1306)
* **Secondary Display:** 16x2 I2C Character LCD
* **Navigation:** Analog Joystick (mapped to X-axis for vertical scrolling)
* **Analog Input:** 10k Potentiometer (for threshold/gain adjustments)
* **Digital Inputs:** Joystick Switch (Back/Exit), plus 2 Tactile Buttons (Action)

##  Features & Modules

**Network Security & Telemetry**
1. **Targeted Network Auditor:** Sweeps 2.4GHz space, locks onto specific BSSIDs, and graphs real-time traffic while displaying encryption vulnerabilities.
2. **Ghost Tracker (Probe Intercept):** Buffers and extracts SSIDs from hidden 802.11 Probe Requests to reveal what networks nearby smartphones are searching for.
3. **EAPOL Interceptor:** Listens for 4-way WPA2 handshakes in the air, logging the MAC address of the authenticating client.
4. **Threat Sentinel (Deauth Alarm):** Continuously monitors the air for Subtype 12 (0xC0) deauthentication frames, triggering a hardware alarm during WiFi flooding attacks.
5. **Assoc Mapper:** Parses management frames to build live pairing relationships between client MACs and Router BSSIDs.
6. **RF Noise Logger:** Maps background radio interference using the potentiometer to adjust the diagnostic noise floor.

**Bluetooth (BLE) Counter-Surveillance**
7. **Spatial BLE Radar:** Visualizes nearby Bluetooth devices on a live radar GUI, mapping proximity based on RSSI.
8. **BLE Inspector:** Parses raw BLE broadcast payloads to identify device manufacturers (Apple, Sony, Microsoft, etc.) and human-readable names.
9. **Digital Tripwire:** Memorizes the baseline MAC addresses in a room and triggers an alarm when a new unrecognized Bluetooth signature enters the perimeter.
10. **Fox Hunter:** Locks onto a specific BLE target and acts as a localized Geiger counter to track physical proximity.
11. **IoT Profiler:** Scans local BSSIDs against known OUI prefixes (Espressif, Tuya, Wyze) to locate hidden smart-cameras and IoT bugs.

**Utility**
12. **DAW/Media Deck:** Connects to a host PC as a BLE keyboard, turning the hardware into a physical media controller/macro deck (Potentiometer = Volume, Action = Play/Pause).

##  Library Dependencies
Install the following via the Arduino IDE Library Manager or as ZIPs:
* `Adafruit_GFX`
* `Adafruit_SSD1306`
* `hd44780` (by Bill Perry)
* `ESP32-BLE-Keyboard` (by T-vK)

##  Build Notes
* **Partition Scheme:** Ensure you compile using **Huge APP (3MB No OTA / 1MB SPIFFS)**.
* **Axis Rotation:** The UI navigation uses `JOY_X` (`analogRead`) with inverted logic to account for physical joystick mounting rotation.

> **Disclaimer:** This project was developed strictly for educational purposes to demonstrate the invisible data footprint of modern wireless devices. It only passively monitors environmental RF and BLE data.


# 9jwaan OS 📟

![9jwaan OS Demo](assets/demo.gif)

**9jwaan OS** is a custom, dual-screen passive network telemetry operating system built for the ESP32...

## 📸 Interface Gallery

| Spatial BLE Radar | Threat Sentinel | Digital Tripwire |
|:---:|:---:|:---:|
| ![Radar](assets/radar.jpg) | ![Sentinel](assets/sentinel.jpg) | ![Tripwire](assets/tripwire.jpg) |
