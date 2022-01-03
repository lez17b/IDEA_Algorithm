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

#include "IDEA.h"
#include<iostream>
#include <cstdio>
#define SIZE 128

//###########################################################
//#########            Encrypt function             #########
//###########################################################

void IDEA::Encrypt(char * source, char * out, int * Key) {
    code(source, out, Key, false);
    std::cout << "\nCode: " << out << "\n";
}

//###########################################################
//#########            Decrypt function             #########
//###########################################################

void IDEA::Decrypt(char * source, char * out, int * Key) {
    code(source, out, Key, true);
    std::cout << "\nDecoded message: " << out << "\n";
}

//###########################################################
//#########        Correlation function             #########
//###########################################################


void IDEA::Correlation(wchar_t buffer, int block) {
    for (int i = 0; i < 16; i++) {
        correlation += (2 * (buffer % 2) - 1) * (2 * (block % 2) - 1);
        if ((block % 2) == 1){
            ones++;
        }
        else if ((block % 2) == 0)
        {
            zeros++;
        }

        buffer = buffer >> 1;
        block = block >> 1;
    }
}

//###########################################################
//#########        Read Block function function     #########
//# Reads the blocks of binary code to process the coding.  #
//###########################################################

wchar_t IDEA::readBlock() {
    wchar_t buffer = 0, block = 0;
    for (int i = 0; i < 2; i++) {
        fread(&buffer, sizeof(unsigned char), 1, 0);//1 байт

        // The end is reached at the very beginning
        if (feof(0) && i == 0){
            return L'\0';
        }
        if (feof(0) && i == 1){
            return block;
        }
        // the 2nd byte of the number was considered
        if (i == 1)
            buffer = buffer << 8;
        block += buffer;
    }
    if (block == 0) block = 65536;
    return block;
}

//###########################################################
//#########        InverseKey function              #########
//###########################################################

void IDEA::inverseKey() {
    wchar_t buffer[9][6];

    for (int i = 0; i < 9; i++)
    {
        buffer[i][0] = modulos(65537, key[8 - i][0]);
        if (i == 0 || i == 8) {
            buffer[i][1] = (0 - key[8 - i][1]) + 65536;
            buffer[i][2] = (0 - key[8 - i][2]) + 65536;
        }
        else {
            buffer[i][1] = (0 - key[8 - i][2]) + 65536;
            buffer[i][2] = (0 - key[8 - i][1]) + 65536;
        }
        buffer[i][3] = modulos(65537, key[8 - i][3]);
        buffer[i][4] = key[7 - i][4];
        buffer[i][5] = key[7 - i][5];
    }
    for (int i = 0; i < 9; i++)
    {
        for (int ii = 0; ii < 6; ii++) {
            key[i][ii] = buffer[i][ii];
        }
    }

}

//###########################################################
//#########          Modulos function               #########
//###########################################################

wchar_t IDEA::modulos(int a, wchar_t b) {

    int buf = a;

    int q, r, x, x1, x2, y, y1, y2;
    x2 = 1, x1 = 0, y2 = 0, y1 = 1;
    while (b > 0) {
        q = a / b;
        r = a - q * b;
        x = x2 - q * x1;
        y = y2 - q * y1;
        a = b;
        b = r;
        x2 = x1;
        x1 = x;
        y2 = y1;
        y1 = y;//
    }

    if (y2 < 0) {

        y2 = y2%buf + buf;
    }

    return y2%buf;//
}

//###########################################################
//#########          Coding  function               #########
//###########################################################

void IDEA::code(const char * source, char * out, int * bigKey, bool decode) {

    FILE *input = nullptr, *output;
    unsigned int A, B, C, D;
    correlation = 0, bits = 0;
    zeros = 0, ones = 0;

    genKeys(key, bigKey);
    if (decode) inverseKey();

    // Open read file
    fopen(reinterpret_cast<const char *>(input), "r");

    // Open write file
    fopen(reinterpret_cast<const char *>(output), "w");

    while (!feof(input)) {
        A = readBlock();
        if (feof(input)) {
            break;
        }
        //up to multiplicity
        B = readBlock();
        if (feof(input)) {
            B = C = D = 65536;
        }
        C = readBlock();
        if (feof(input)) {
            C = D = 65536;
        }
        D = readBlock();
        if (feof(input)) {
            D = 65536;
        }

        // correlation variables
        wchar_t bufA = A,
        bufB = B,
        bufC = C,
        bufD = D;

        bits += 64;
        for (int round = 0; round < 8; round++) {
            A = (A * key[round][0]) % 65537;
            B = (B + key[round][1]) % 65536;
            C = (C + key[round][2]) % 65536;
            D = (D * key[round][3]) % 65537;

            unsigned int t1, t2;
            t1 = A ^ C;
            t2 = B ^ D;

            t1 = (t1 * key[round][4]) % 65537;
            t2 = (t2 + t1) % 65536;

            t2 = (t2 * key[round][5]) % 65537;
            t1 = (t1 + t2) % 65536;

            A = A ^ t2;
            B = B ^ t1;
            C = C ^ t2;
            D = D ^ t1;

            if (round != 7) {
                wchar_t buf = B;
                B = C;
                C = buf;
            }
        }

        // final transformation
        A = (A * key[8][0]) % 65537;
        B = (B + key[8][1]) % 65536;
        C = (C + key[8][2]) % 65536;
        D = (D * key[8][3]) % 65537;

        // Computing the correlation
        Correlation(bufA, A);
        Correlation(bufB, B);
        Correlation(bufC, C);
        Correlation(bufD, D);


        fwrite(&A, sizeof(wchar_t), 1, output);
        if (decode && B == 65536)
            break;
        fwrite(&B, sizeof(wchar_t), 1, output);
        if (decode && C == 65536)
            break;
        fwrite(&C, sizeof(wchar_t), 1, output);
        if (decode && D == 65536)
            break;
        fwrite(&D, sizeof(wchar_t), 1, output);
    }

    if (!decode) {
        correlation = correlation / bits;
    }

    fclose(input);
    fclose(output);
}
//###############################################
//##### Function defined to create Keys  ########
//###############################################

void IDEA::genKeys(wchar_t keys[][6], const int * key) {
    for (int i = 0; i < 9; i++) {
        for (int ii = 0; ii < 6; ii++) {
            keys[i][ii] = 0;
        }
    }
    // Sub-key number
    int k = 0;

    // Number of shifts
    for (int j = 0; j < 7; j++) {

        // 128 bits key pass
        for (int i = 0; i < SIZE; i++) {
            keys[k / 6][k % 6] = keys[k / 6][k % 6] << 1;
            keys[k / 6][k % 6] = keys[k / 6][k % 6] + key[(i + 25 * j) % SIZE];
            if (i % 16 == 15) k++;
            if (k == 52) break;
        }
        if (k == 52) break;
    }

}
