/*
    Author: Sarthak
*/

#include "Signer.h"

tx transaction;
Keccak keccak;
String PRIVATE_KEY = "";
String PUBLIC_KEY = "";
static const int PRIVATE_KEY_LENGTH = 64;


static const char* REC_ID_FALSE = "0x29";
static const char* REC_ID_TRUE = "0x2a";
boolean key_status = false;

int RNG(uint8_t *dest, unsigned size) {
  randomSeed(millis());
  return random(0,255);
}

Signer::Signer()
{
   uECC_set_rng(&RNG);
}

void Signer:: generateKeys()
{
  const struct uECC_Curve_t * curve = uECC_secp256k1();
  uint8_t privKey[21];
  
  uint8_t pubKey[40];  

  char prKey[43];
  char puKey[81];
  key_status = uECC_make_key(pubKey, privKey, curve);
  if(key_status)
  {
    for(int i = 0; i < 21; ++i) {
        sprintf(prKey+2*i,"%02x", privKey[i]);
    }
    for(int j = 0; j < 40; ++j) {
        sprintf(puKey+2*j,"%02x", pubKey[j]);
    }
    PRIVATE_KEY = String(prKey);
    PUBLIC_KEY = String(puKey);
  }
  
}

String Signer:: signText(BYTE text[])
{
  BYTE hash[SHA256_BLOCK_SIZE];
  char texthash[2*SHA256_BLOCK_SIZE+1];

  Sha256* sha256Instance=new Sha256();
  sha256Instance->update(text, strlen((const char*)text));
  sha256Instance->final(hash);

  for(int i=0; i<SHA256_BLOCK_SIZE; ++i)
    sprintf(texthash+2*i, "%02X", hash[i]);
  
  return String(texthash);
}

String Signer:: getPrivKey()
{
  if(key_status)
    return PRIVATE_KEY;
  else
  {
    return "KEY FAILED";
  }
  
}

String Signer:: getPubKey()
{
  if(key_status)
    return PUBLIC_KEY;
  else
  {
    return "KEY FAILED";
  }
}

boolean Signer::setPrivKey(String privKey)
{
    PRIVATE_KEY = privKey;
    if(PRIVATE_KEY == NULL)
    {
        return false;
    }
    else
    {
        return true;
    }
    
}
boolean Signer::setNonce(String nonce)
{
    transaction.nonce = nonce;
    if(transaction.nonce != "invalid")
    {
    return true;
    }
    else
    {
        return false;
    }
}
boolean Signer::setReceiveAddr(const char recvAddr[])
{
    transaction.to = recvAddr;
    if(transaction.to == "")
    {
        return false;
    }
    else
    {
        return true;
    } 
}
boolean Signer::setValue(String value)
{
    transaction.value = value;
    if(transaction.value == "")
    {
        return false;
    }
    else
    {
        return true;
    } 
}
boolean Signer::setGasPrice(char * gasPrice)
{
    transaction.gasPrice = gasPrice;
}
boolean Signer::setGasLimit(char *gasLimit)
{
    transaction.gasLimit = gasLimit;
}
boolean Signer::setChainId(char *chainId)
{
    transaction.chainId = chainId;
}
String Signer::setTransactionData(String input)
{
  removeHexFormatting(input);
  String dummy = "";
  String output = "";
  for (int i = 0; i < 64 - input.length(); i++)
  {
    output += "0";
  }
  output += input;

 // String transactionData = transaction.data.c_str();
 // transactionData.replace(dummy, output);
  transaction.data = "";
  transaction.data = output.c_str();
  return transaction.data;
}
String Signer::generateTransaction()
{
  if(transaction.nonce == "invalid")
  {
    return "ERROR";
  }
  // Specify ECDSA curve type
  const struct uECC_Curve_t * curve = uECC_secp256k1();
  
  String sUnsginedTransaction = "";
  String sUnsignedHash = "";
  String cstrUnsignedHash = "";
  boolean oddCounter;
  boolean signatureValid = 0;
  uint8_t byteHashInt[32] ={};
  uint8_t bytePrivKey[32] = {};
  uint8_t byte_r[32] = {0};
  uint8_t byte_s[32] = {0};
  uint8_t sigRes[64] = {0};
  int iEccWasSuccess = 0;
    
  sUnsginedTransaction = RlpEncodeTransaction(transaction);

  
  oddCounter = false;
  byte byteUnsignedTransaction[sUnsginedTransaction.length()/2]; 

  // Loop for transformation of hex RLP to bytes. Result is stored in byteUnsignedTransaction.
  for(int i = 0; i < sUnsginedTransaction.length(); i++)
  {
    if (oddCounter)
      {
        String currentSubstr = sUnsginedTransaction.substring(i - 1, i + 1);
        byte currentByte = (byte)byteFromTwoHex(currentSubstr);
        byteUnsignedTransaction[i/2] = currentByte;
      }
      oddCounter =! oddCounter;
  }

  cstrUnsignedHash = keccak(byteUnsignedTransaction, sizeof(byteUnsignedTransaction));

  sUnsignedHash = cstrUnsignedHash.c_str();
  
  oddCounter = false;

  // Loop for transformation of hex encoded hash to bytes. Result is stored in byteHashInt.
  for(int i = 0; i <= sUnsignedHash.length() - 1; i++)
  {
    if (oddCounter)
    {
      String currentSubstr = sUnsignedHash.substring(i - 1, i + 1);
      uint8_t currentByte = (uint8_t)byteFromTwoHex(currentSubstr);
      byteHashInt[i/2] = currentByte;
    }
    oddCounter =! oddCounter;      
  }

  // Loop for transformation of hex encoded Private Key to bytes. Result is stored in bytePrivKey.
  oddCounter = false;
  for(int i = 0; i < PRIVATE_KEY_LENGTH; i++)
  {
    if (oddCounter)
    {
      String currentSubstr = String(PRIVATE_KEY[i-1]) + String(PRIVATE_KEY[i]);
      uint8_t currentByte = (uint8_t)byteFromTwoHex(currentSubstr);
      bytePrivKey[i/2] = currentByte;
    }
    oddCounter =! oddCounter;        
  }

  // The recovery Bit is stored here
  uint8_t recid[1] = {2};
  
  // Try signing maximum ten times
  for(int i = 0; i < 10 && signatureValid == 0; i++)
  {
    iEccWasSuccess = uECC_sign(bytePrivKey, byteHashInt, sizeof(byteHashInt), sigRes, curve, recid);
    
    // Check MSB smaller than half the maximum value. Otherwise, the transaction will be rejected by the Ethereum network.
    if(sigRes[32] < 128)
    {
      signatureValid = 1;
    }
    else
    {
      signatureValid = 0;
      delay(50);
    }
  }  

//   if(iEccWasSuccess == 1)
//   {
//     Serial.println(recid[0]);  
//   }
//   else
//   {
//     return "invalid"; 
//   }

  // Loop to split 64 byte signature result to r and s
  for(int i = 0; i < sizeof(sigRes); i++)
  {
    if(i < 32)
    {
      byte_r[i] = sigRes[i];
    }
    else
    {
      byte_s[i-32] = sigRes[i];
    }
  }
  // Set r, s and v value of transaction
  transaction.r = "0x";
  transaction.r += bytesToHex(byte_r, sizeof(byte_r)).c_str();
  transaction.s = "0x";
  transaction.s += bytesToHex(byte_s, sizeof(byte_s)).c_str();

  if(recid[0] == 0)
  {
    // Value from config for recovery ID of current Ethereum blockchain instance.
    transaction.chainId = REC_ID_FALSE;
  }
  else
  {
    transaction.chainId = REC_ID_TRUE;
  }
  
  
  String signedTransaction = RlpEncodeTransaction(transaction);

  return signedTransaction;
}

String Signer::RlpEncodeString(String input)
{
  String output = "";
  // Pad with leading zero in case input has uneven length.
  if(input.length() % 2 == 1)
  {
    output = "0" + input;
  }
  else
  {
    output = input;
  }
  // Check for empty string as input.
  if (output == "")
  {
    return "80";
  }
  // Check if input was single character.
  else if (output.length() <= 2 && (unsigned char)byteFromTwoHex(output) < 128)
  {
    return output;  
  }
  // If the input is more than one char, encode the string's length.
  else
  {
    // Take half here, as 2 hex values are 1 byte.
    return encodeLength(output.length()/2, 128) + output; 
  }
}


/*
  Calculates the RLP encoding of a transaction object.
  @param pTransaction The transaction that is to be RLP encoded
  @return RLP encoded transaction as a string.
*/
String Signer::RlpEncodeTransaction(tx pTransaction)
{
  // Perform RLP Encoding of single transaction strings and concatenate the result.
  String serializedTransaction =  hexToRLPEncode(pTransaction.nonce.c_str()) + 
                                  hexToRLPEncode(pTransaction.gasPrice.c_str()) + 
                                  hexToRLPEncode(pTransaction.gasLimit.c_str()) + 
                                  hexToRLPEncode(pTransaction.to.c_str()) + 
                                  hexToRLPEncode(pTransaction.value.c_str()) + 
                                  hexToRLPEncode(pTransaction.data.c_str()) +
                                  hexToRLPEncode(pTransaction.chainId.c_str())+
                                  hexToRLPEncode(pTransaction.r.c_str())+
                                  hexToRLPEncode(pTransaction.s.c_str());

  // Encode the length of the resulting string.
  return encodeLength(serializedTransaction.length()/2, 192) + serializedTransaction;
}


/*
  Encodes the string length according to the RLP rules.
  @param inputLength The amount of bytes as an integer
  @param offset An offset that is added to the length.
  @return Length in bytes as an RLP encoded string.
*/
String Signer::encodeLength(int inputLength, int offset)
{
  if (inputLength < 56)
  {
    // Perform length encoding with one part indicating length.
    return intToHex(inputLength + offset);;
  }
  else
  {
    // Perform length encoding with two parts indicating length.
    String hexLength = intToHex(inputLength);
    int tailLength = hexLength.length() / 2;
    String lengthEncoding = intToHex(offset + 55 + tailLength);
    return lengthEncoding + hexLength;
  }
}


/*
  Calculates a hex encoded string from an integer.
  @param input The integer value to be transformed.
  @return Hex encoded string of input integer.
*/
String Signer::intToHex(int input)
{
  String output = "";
  String intermediate = "";
  if(input < 16 && input > -1)
  {
    output = "0";
    output += String(input, HEX);
    return output;
  }
  else
  {
    intermediate = String(input, HEX);
    if (intermediate.length() % 2 == 1)
    {
      // Pad with leading zero if input results in uneven hex.
      output = "0" + intermediate;      
    }
    else 
    {
      output = intermediate;
    }
    return output;
  }
}


/*
  Calculates a byte value from two hex values.
  @param input The string containing hex values.
  @return A char containing the byte of the two hex values.
*/
char Signer::byteFromTwoHex(String input)
{
  unsigned long number = strtoul(input.c_str(), NULL, 16);
  return (unsigned char)number;
}


/*
  Gets a hex formatted string, calls removeHexFormatting and then RlpEncodeString.
  @param input A hex formatted string.
  @return Result of RlpEncodeString function call.
*/
String Signer::hexToRLPEncode(String input)
{
  input = removeHexFormatting(input);
  return(RlpEncodeString(input));
}


/*
  Removes the hex prefix 0x of a string.
  @param input A hex formatted string.
  @return The input string with the 0x part cut away.
*/
String Signer::removeHexFormatting(String input)
{
  if (input[0] == '0' && input[1] == 'x')
  {
    return input.substring(2, input.length());
  }
  else
  {
    return input;
  }
}


/*
  Calculates hex formatted string from a byte array.
  @param input The byte array that is to be transformed.
  @param inputSize The length of byte array.
  @return String containing hex values
*/
String Signer::bytesToHex(uint8_t input[], int inputSize)
{
  String output = "";
  static const char* lookUp = "0123456789abcdef";
  boolean even = false;
  String currentSubstr = "";
    
  for(int i = 0; i < inputSize; i++)
  {
      int firstNumber = input[i] / 16;
      int secondNumber = input[i] % 16;
      output += lookUp[firstNumber];
      output += lookUp[secondNumber];
  }
  return output;
}

