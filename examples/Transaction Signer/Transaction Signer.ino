#include "Signer.h"
char* PRIV_KEY = "18313e538521dc5462200ebf48fdf9baea011a4d63bdb64f7be3d53736e31293";
static char* CHAIN_ID = "0x03";
static char* GAS_PRICE = "0x3b9aca00";
static char* GAS_LIMIT = "0x186a0";
const char NONCE[] = "0x126836492642972692628956258926529562795627562756275637";
static const char* RECEIVING_ADDRESS = "0x0cf98523C9A14e4c7Fc053ec24723D2009a1999b";

Signer test;

void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);
  setTransactionDetail();
}

void loop() {
  int sensValue = random(50, 100);
  //TODO:Get nonce from Etherscan
  test.setNonce(NONCE);
  test.setTransactionData(String(sensValue,HEX));
  String output = test.generateTransaction();
  Serial.print("Sensor Value now: ");
  Serial.println(sensValue);
  Serial.println("SIGNED TX");
  Serial.println(output);
  delay(10000);
}
void setTransactionDetail()
{
  test.setPrivKey(PRIV_KEY);
  test.setGasPrice(GAS_PRICE);
  test.setGasLimit(GAS_LIMIT);
  test.setReceiveAddr(RECEIVING_ADDRESS);
  test.setChainId(CHAIN_ID);
}
