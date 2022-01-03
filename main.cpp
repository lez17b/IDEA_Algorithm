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


#include<iostream>
#include <ctime>
#include "IDEA.h"

using namespace std;

#pragma warning(2:4235)
#define SIZE 128

//#################################
//##       Main function       ####
//#################################

int main(int argc, char* argv[]) {

    // Algorithm Object definition
    IDEA idea{};
    srand(time(nullptr));

    // key Array
    int key[SIZE];


    // Random Values for key generation
    for (int & byte : key) {
        byte = rand() % 2;
    }

    cout << "\nkey: ";
    for (int i = 0; i < SIZE; i++) {
        cout << key[i];
        if (i % 4 == 3) cout << " ";
    }

    // Coding algorithm (encrypt)
    idea.Encrypt(argv[1], argv[2], key);

    // Decoding algorithm (Decrypt)
    idea.Decrypt(argv[2], argv[3], key);


    system("PAUSE");
}

