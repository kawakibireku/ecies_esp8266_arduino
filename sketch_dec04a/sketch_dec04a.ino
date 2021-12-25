#include <Arduino.h>
#include <uECC.h>
#include <DHT.h>
#include <ESP8266WiFi.h>
// #include <WiFiClientSecure.h>
#include <ESP8266HTTPClient.h>
#include <base64.hpp>
#include <base64.h>
#include <Crypto.h>
#include <SHA256.h>
#include <string.h>
#include <ArduinoJson.h>
#include <AES.h>
#include <AESLib.h>

SHA256 sha256;
AESLib aesLib;
AES aes;

#define DHTPIN D5
#define DHTTYPE DHT22
#define HMAC_KEY_LENGTH 16
#define HASH_SIZE 32
#define AES_KEY_LENGTH 16


extern "C" {
  int RNG(uint8_t *p_dest, unsigned p_size) {
    uint16_t i = 0;
    while (i < p_size) {
      uint32_t v = RANDOM_REG32;
      uint32_t l_amount = min(p_size - i, sizeof(uint32_t));
      memcpy(&p_dest[i], &v, l_amount);
      i += l_amount;
    }

    return 1;
}

} // extern "C

 String urlencode(String str)
  {
      String encodedString="";
      char c;
      char code0;
      char code1;
      char code2;
      for (int i =0; i < str.length(); i++){
        c=str.charAt(i);
        if (c == ' '){
          encodedString+= '+';
        } else if (isalnum(c)){
          encodedString+=c;
        } else{
          code1=(c & 0xf)+'0';
          if ((c & 0xf) >9){
              code1=(c & 0xf) - 10 + 'A';
          }
          c=(c>>4)&0xf;
          code0=c+'0';
          if (c > 9){
              code0=c - 10 + 'A';
          }
          code2='\0';
          encodedString+='%';
          encodedString+=code0;
          encodedString+=code1;
          //encodedString+=code2;
        }
        yield();
      }
      return encodedString;  
  }

// prints given block of given length in HEX
void printBlock(uint8_t* block, int length) {
  Serial.print(" { ");
  for (int i=0; i<length; i++) {
    Serial.print(block[i], HEX);
    Serial.print(" ");
  }
  Serial.println("}");
}


DHT dht(DHTPIN, DHTTYPE);


void setup() {

  Serial.begin(9600);
  Serial.println(F("Startup"));
  WiFi.begin("DEVNILA", "pass4devnila");
      Serial.print("Connecting");
      while (WiFi.status() != WL_CONNECTED)
      {
        delay(500);
        Serial.print(".");
      }
      Serial.println();
  
  Serial.print("Connected, IP address: ");
  Serial.println(WiFi.localIP());

  Serial.print("Testing ecc\n");
  dht.begin();
  uECC_set_rng(&RNG);
}

void loop() {
  const struct uECC_Curve_t * curve = uECC_secp256k1();
  uint8_t private1[32];
  uint8_t public1[64];
  uint8_t public2[64];
  uint8_t compress1[65];
  uint8_t secret1[32];
  byte keyEncrypt[16];
  byte keyHmac[16];
  uint8_t iv[AES_KEY_LENGTH];
  byte keyHash[HASH_SIZE];
  uint8_t encPrivate[100];
  uint8_t encPublic[100];
  uint8_t encPublic2[100];
  uint8_t encSecret[100];
  uint8_t encIV[100];
  uint8_t encHash[100];

  uint8_t prefix[] = {0x04};
 
  float h = dht.readHumidity();
  
  float t = dht.readTemperature();

  float hic = dht.computeHeatIndex(t,h, false);
    Serial.print("Heat Index: ");
    Serial.println(hic);
    Serial.print("Humidity: ");
    Serial.println(h);
    Serial.print("Temperature: ");
    Serial.println(t); 
 
  unsigned long a = millis();
  unsigned long b = millis();

  uECC_make_key(public1, private1, curve);
yield();  
    int lenprivate1 = sizeof(private1);
    encode_base64(private1,lenprivate1,encPrivate);
    Serial.println("PRIVATE KEY ");
    Serial.println((char*)encPrivate);
    int lenpublic1 = sizeof(public1);
    Serial.printf("PUBLIC KEY (%d bytes)", lenpublic1);  
    printBlock(public1, lenpublic1);  
 yield();
    memcpy(compress1,prefix,sizeof(prefix));
    memcpy(compress1+sizeof(prefix),public1,sizeof(public1));
    Serial.printf("PUBLIC KEY + PREFIX (%d bytes)", sizeof(compress1));
    printBlock(compress1,sizeof(compress1));
    Serial.println("PUBLIC KEY "); 
    encode_base64(compress1,sizeof(compress1),encPublic);
    Serial.println((char*)encPublic);  
 yield();
    aesLib.gen_iv(iv);
    Serial.printf("Random IV (%d bytes)", AES_KEY_LENGTH);
    printBlock(iv, AES_KEY_LENGTH);
    encode_base64(iv,sizeof(iv),encIV); 
    Serial.println((char*)encIV);
yield();
  String payload;
  String publickeysend;
  String ivsend;
  // DIFFIE HELLMAN
  if(WiFi.status()== WL_CONNECTED){    
    HTTPClient http;
    publickeysend = (char*)encPublic;
    // publickeysend.replace("+",replace);
    ivsend = (char*)encIV;
    // ivsend.replace("+",replace);

    Serial.println("\nSEND : ");
    Serial.println(publickeysend);
    Serial.println(ivsend);
    yield();
    http.begin("http://antares-dev.xyz:3000/api/diffiehellman");
    http.addHeader("Cache-Control", "no-cache");
    http.addHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
    http.addHeader("Postman-Token","1f017b7e-bf6d-4446-92c0-baef777b5952");
    http.POST("pk="+urlencode(publickeysend)+"&iv="+urlencode(ivsend));
    payload = http.getString();
    delay(5000);
    http.end(); 
  }else{
    Serial.println("ERROR IN WIFI CONNECTION");
  }
yield();
  char * pkserverdecode = new char[payload.length()];
  strcpy(pkserverdecode, payload.c_str());
  decode_base64((uint8_t*)pkserverdecode,public2);
  Serial.println(pkserverdecode);
  int lenpublic2 = sizeof(public2);
  encode_base64(public2,lenpublic2,encPublic2);
  Serial.printf("PUBLIC KEY (%d bytes)", lenpublic2);  
  Serial.println((char*)encPublic2);
  printBlock(public2,lenpublic2);
yield();

StaticJsonBuffer<300> JSONbuffer;
JsonObject& JSONencoder = JSONbuffer.createObject();
JSONencoder["sensorType"] = "ESP8266";
JSONencoder["Temperature"] = t;
JSONencoder["Humidity"] = h;
JSONencoder["HeatIndex"] = hic;
// temperature.add(t);
// JsonArray& humidity = JSONencoder.createNestedArray("Humidity");
// humidity.add(h);
// JsonArray& heatindex = JSONencoder.createNestedArray("HeatIndex");
// heatindex.add(hic);

char msg[300];
JSONencoder.prettyPrintTo(msg,sizeof(msg));
Serial.println(msg);

a = millis();
int r = uECC_shared_secret(public2, private1, secret1, curve);
  b = millis();
  Serial.print("Shared secret 1 in "); Serial.println(b-a);
  int lensecret1 = sizeof(secret1);
  // base64_encode(encSecret, (char *)secret1, lensecret1); 
  encode_base64(secret1,lensecret1,encSecret);
  Serial.println((char*)encSecret);
  printBlock(secret1, lensecret1);

// get SHA-256 hash of our secret key to create 256 bits of "key material"
/* sha256.doUpdate(secret1,sizeof(secret1));
*/
yield();
sha256.update(secret1,sizeof(secret1));
sha256.finalize(keyHash,HASH_SIZE);
encode_base64(keyHash,sizeof(keyHash),encHash);
Serial.printf("Key Hash (%d bytes)", HASH_SIZE);
Serial.println((char*) encHash);
sha256.reset();
  printBlock(keyHash, HASH_SIZE); 
yield();
// keyEncrypt is a pointer pointing to the first 256 bits bits of "key material" stored in keyHash
// keyHmac is a pointer pointing to the second 256 bits of "key material" stored in keyHashMAC
// keyEncrypt = keyHash; // 32 bytes
memcpy(keyEncrypt,keyHash,AES_KEY_LENGTH);
Serial.printf("keyEncrypt  (%d bytes)", sizeof(keyEncrypt));
printBlock(keyEncrypt, sizeof(keyEncrypt));
memcpy(keyHmac,keyHash+HMAC_KEY_LENGTH,HMAC_KEY_LENGTH);
Serial.printf("KeyHmac (%d bytes)", sizeof(keyHmac));
printBlock(keyHmac, sizeof(keyHmac));
Serial.println("On the sending side:");
yield();

int packetSize = strlen(msg)+1;
  msg[packetSize] = '\0';
  Serial.printf("Packet (%d bytes):\n", packetSize);
  Serial.println(msg);
  Serial.print("Packet HEX");
  printBlock((uint8_t*)msg, packetSize+1);  //+1 to add null termination

aes.set_key(keyEncrypt,sizeof(keyEncrypt));
yield();
int encryptedSize = aes.calc_size_n_pad(packetSize);
int EncryptedHmacSize = encryptedSize + HASH_SIZE;
uint8_t EncryptedHmac[EncryptedHmacSize]; 
uint8_t encrypted[encryptedSize];
  // AES 128 CBC no padding

  yield();
    aes.do_aes_encrypt((byte*)msg,packetSize,encrypted,keyEncrypt,128,iv);
    Serial.printf("Encrypted (%d bytes)", encryptedSize);
    printBlock(encrypted, encryptedSize);
    memcpy(EncryptedHmac,encrypted,encryptedSize);
    Serial.printf("EncryptedHmac (%d bytes)", EncryptedHmacSize);
    printBlock(EncryptedHmac, EncryptedHmacSize);
  yield();

  uint8_t computedHmac[HASH_SIZE];
  // sha256.clear();
  sha256.resetHMAC(keyHmac,HMAC_KEY_LENGTH);
  sha256.update(encrypted,encryptedSize);
  sha256.finalizeHMAC(keyHmac,HMAC_KEY_LENGTH,computedHmac,HASH_SIZE);
  yield();
  memcpy(EncryptedHmac+encryptedSize,computedHmac,HASH_SIZE);
  Serial.printf("Computed HMAC (%d bytes)", sha256.hashSize());
  printBlock(computedHmac, sha256.hashSize());
  Serial.printf("encrypted | HMAC (%d bytes)", EncryptedHmacSize);
  printBlock(EncryptedHmac, EncryptedHmacSize);
  yield();
  
int encodedSize = base64_enc_len(EncryptedHmacSize); // get size needed for base64 encoded output
  uint8_t encoded[encodedSize];
  base64_encode((char*)encoded,(char*)EncryptedHmac,EncryptedHmacSize);
  Serial.printf("Base64 encoded to %d bytes\n", encodedSize);
  Serial.printf((char *)encoded);

/* 
int encodencrypt = base64_enc_len(encryptedSize);
int encodehmac = base64_enc_len (HASH_SIZE);
char encipher[encodencrypt];
char encodedhmac[encodehmac];
base64_encode(encipher,(char*)encrypted,encryptedSize);
base64_encode(encodedhmac,(char*)computedHmac,HASH_SIZE);
char sendcipher[encodencrypt+encodehmac];
strcpy(sendcipher, encipher); 
strcat(sendcipher, encodedhmac);*/ 

yield();
String sendcp = (char*)encoded;
Serial.println(sendcp);
delay(2000);
  if(WiFi.status()== WL_CONNECTED){    
    HTTPClient http;

    http.begin("http://antares-dev.xyz:3000/api/add-data");
    http.addHeader("Cache-Control", "no-cache");
    http.addHeader("Content-Type", "application/x-www-form-urlencoded; charset=utf-8");
    http.addHeader("Postman-Token","1f017b7e-bf6d-4446-92c0-baef777b5952");
    http.POST("value="+urlencode(sendcp));
    http.end();

  }else{
    Serial.println("ERROR IN WIFI CONNECTION");
  } 
    sha256.clear();
    delay(3000);
    yield();
}
