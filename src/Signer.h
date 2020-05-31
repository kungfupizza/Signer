/*
    Author: Sarthak
*/

#ifndef Signer_h

#define Signer_h

#include "Arduino.h"
#include <stdint.h>
#include "uECC.h"
#include "keccak.h"
#include "tx.h"
#include <sha256.h>



class Signer
{
    private: String bytesToHex(uint8_t[], int);
             String removeHexFormatting(String);
             String RlpEncodeString(String input);
             String hexToRLPEncode(String);
             char byteFromTwoHex(String);
             String intToHex(int);
             String encodeLength(int, int);
             String RlpEncodeTransaction(tx);
//             int RNG(uint8_t *dest, unsigned size);
    
    public: Signer();
            String generateTransaction();
            String setTransactionData(String input);
            boolean setNonce(String nonce);
            boolean setReceiveAddr(const char recvAddr[]);
            boolean setValue(String value);
            boolean setPrivKey(String privKey);
            boolean setChainId(char * chainId);
            boolean setGasLimit(char* gasLimit);
            boolean setGasPrice(char* gasPrice);
            String signText(BYTE text[]);
            String getPrivKey();
            String getPubKey();
            void generateKeys();
};

#endif

