#include <Signer.h>

Signer test;
void setup() {
  Serial.begin(115200);
  delay(2000);
  
  BYTE signIt[] = "Hello";
  Serial.print("Signed text: ");
  Serial.println(test.signText(signIt));
  Serial.println();

  test.generateKeys();
  
  Serial.println("PRIVATE KEY GENERATED");
  Serial.println(test.getPrivKey());
  Serial.println();

  Serial.println("PUBLIC KEY GENERATED");
  Serial.println(test.getPubKey());
  Serial.println();
}

void loop() {
  delay(5000);
}
