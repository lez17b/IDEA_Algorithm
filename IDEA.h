//***********************************************************************************************************
//                                                                                                       ****
// Project Name: Secure Computing - IDEA Algorithm                                                       ****
// Created by Luciano Zavala Zelada on 11/18/21.                                                         ****
// Designed to implement the International Data Encryption Algorithm                                     ****
// Inspired using some resources online such as:                                                         ****
// - https://www.cs.cmu.edu/afs/cs.cmu.edu/project/cmcl-droh-02/mingle/src/mingled/crypto-4.2/idea.cpp   ****
// - https://www.geeksforgeeks.org/simplified-international-data-encryption-algorithm-idea/              ****
// Using also some ideas from the lectures by Dr. Gaitros.                                               ****
//                                                                                                       ****
//***********************************************************************************************************


#ifndef IDEA_ALGORITHM_ENCRYPT_IDEA_H
#define IDEA_ALGORITHM_ENCRYPT_IDEA_H
#include <cstdio>

//********************************************************
//**   International Data encryption Algorithm Class    **
//********************************************************

class IDEA {
private:
    // Variables:
    float correlation;
    int zeros, ones, bits;
    wchar_t key[9][6];

    // Function prototypes:
    static void genKeys(wchar_t keys[][6], const int *bigKey);
    static wchar_t readBlock();
    void Correlation(wchar_t buf, int block);
    void inverseKey();
    static wchar_t modulos(int a, wchar_t b);
    void code(const char *source, char *out, int *bigKey, bool decode);

public:
    void Encrypt(char *source, char *out, int *bigKey);
    void Decrypt(char *source, char *out, int *bigKey);

};

#endif //IDEA_ALGORITHM_ENCRYPT_IDEA_H
