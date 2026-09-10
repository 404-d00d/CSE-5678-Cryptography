import secrets


cipherTextOneHex = (
    "5c707f737a0b670f017c272b26365fc9"
    "c3b4cfeaec90f2ff9698f39da0bcaa"
)

cipherTextTwoHex = (
    "4f617f607c01136e0113433e393d5fd4"
    "c4c2def089f2ee9e88859794a8bcaa"
)

knownMessageOne = (
    "ATTACK AT DAWN ON THE EAST GATE"
)


# ============================================================
# Byte XOR
# ============================================================

def xorBytes(firstBytes, secondBytes):
    if len(firstBytes) != len(secondBytes):
        print("XOR refused.")
        print("Byte sequences must have the same length.")

        return None

    result = bytearray()

    for byteIndex in range(len(firstBytes)):
        xorValue = (
            firstBytes[byteIndex]
            ^ secondBytes[byteIndex]
        )

        result.append(xorValue)

    return bytes(result)


# ============================================================
# Question 3.1
# One-Time Pad Encryption
# ============================================================

def oneTimePadEncrypt(message, key):
    messageBytes = message.encode("utf-8")

    if len(messageBytes) != len(key):
        print("Encryption refused.")
        print("Key must be the same length as the message.")

        return None

    cipherText = xorBytes(
        messageBytes,
        key
    )

    return cipherText


# ============================================================
# Question 3.1
# One-Time Pad Decryption
# ============================================================

def oneTimePadDecrypt(cipherText, key):
    if len(cipherText) != len(key):
        print("Decryption refused.")
        print("Key must be the same length as the ciphertext.")

        return None

    messageBytes = xorBytes(
        cipherText,
        key
    )

    message = messageBytes.decode("utf-8")

    return message


# ============================================================
# Question 3.1 Test
# ============================================================

def testOneTimePad(message):
    messageBytes = message.encode("utf-8")

    key = secrets.token_bytes(
        len(messageBytes)
    )

    cipherText = oneTimePadEncrypt(
        message,
        key
    )

    decryptedMessage = oneTimePadDecrypt(
        cipherText,
        key
    )

    print("One-Time Pad Test")
    print("-----------------")
    print("Original message:", message)
    print("Message bytes:", messageBytes)
    print("Key:", key.hex())
    print("Ciphertext:", cipherText.hex())
    print("Decrypted message:", decryptedMessage)

    if decryptedMessage == message:
        print("Round-trip verification: successful")
    else:
        print("Round-trip verification: failed")

    print()


# ============================================================
# Question 3.2
# Recover Reused One-Time Pad Key
# ============================================================

def recoverKey(cipherText, knownMessage):
    knownMessageBytes = knownMessage.encode("utf-8")

    key = xorBytes(
        cipherText,
        knownMessageBytes
    )

    return key


# ============================================================
# Question 3.2
# Recover Second Message
# ============================================================

def recoverSecondMessage(
    cipherTextOne,
    cipherTextTwo,
    knownMessageOne
):
    key = recoverKey(
        cipherTextOne,
        knownMessageOne
    )

    recoveredMessageBytes = xorBytes(
        cipherTextTwo,
        key
    )

    recoveredMessage = (
        recoveredMessageBytes.decode("utf-8")
    )

    return (
        key,
        recoveredMessage
    )


# ============================================================
# Question 3.2 Test
# ============================================================

def testReusedOneTimePad():
    cipherTextOne = bytes.fromhex(
        cipherTextOneHex
    )

    cipherTextTwo = bytes.fromhex(
        cipherTextTwoHex
    )

    (
        recoveredKey,
        recoveredMessageTwo
    ) = recoverSecondMessage(
        cipherTextOne,
        cipherTextTwo,
        knownMessageOne
    )

    print("Reused One-Time Pad Test")
    print("------------------------")
    print("Known message one:", knownMessageOne)
    print("Ciphertext one:", cipherTextOne.hex())
    print("Ciphertext two:", cipherTextTwo.hex())
    print("Recovered key:", recoveredKey.hex())
    print(
        "Recovered message two:",
        recoveredMessageTwo
    )
    print()


# ============================================================
# Main
# ============================================================

def main():
    print("========================================")
    print("QUESTION 3.1")
    print("========================================")
    print()

    testOneTimePad("MY NAME IS DAVID TRAN")

    print("========================================")
    print("QUESTION 3.2")
    print("========================================")
    print()

    testReusedOneTimePad()


if __name__ == "__main__":
    main()