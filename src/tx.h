

#ifndef TX_H
#define TX_H


class tx
{
  public:
    String nonce = "invalid";
    String gasPrice;
    String gasLimit;
    String to;
    String value;
    String data;
    String chainId;
    String r;
    String s;
};

#endif // TX_H
