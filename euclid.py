modulus = 26

# Personal affine cipher key
# d = 41
# j = 1
# L[1] = 3
#
# a = 3
# b = 41 mod 26 = 15

affineMultiplier = 3
affineShift = 15


# ============================================================
# Question 1.1
# Extended Euclidean Algorithm
# ============================================================

def extendedGcd(firstNumber, secondNumber):
    previousRemainder = firstNumber
    currentRemainder = secondNumber

    previousFirstCoefficient = 1
    currentFirstCoefficient = 0

    previousSecondCoefficient = 0
    currentSecondCoefficient = 1

    while currentRemainder != 0:
        quotient = previousRemainder // currentRemainder

        nextRemainder = (previousRemainder - quotient * currentRemainder)
        nextFirstCoefficient = (previousFirstCoefficient - quotient * currentFirstCoefficient)
        nextSecondCoefficient = (previousSecondCoefficient - quotient * currentSecondCoefficient)

        previousRemainder = currentRemainder
        currentRemainder = nextRemainder

        previousFirstCoefficient = currentFirstCoefficient
        currentFirstCoefficient = nextFirstCoefficient

        previousSecondCoefficient = currentSecondCoefficient
        currentSecondCoefficient = nextSecondCoefficient

    gcdValue = previousRemainder
    firstBezoutCoefficient = previousFirstCoefficient
    secondBezoutCoefficient = previousSecondCoefficient

    return (gcdValue, firstBezoutCoefficient, secondBezoutCoefficient)


# ============================================================
# Question 1.2
# Modular Inverse
# ============================================================

def modularInverse(number, modulusValue):
    gcdValue, numberCoefficient, modulusCoefficient = extendedGcd(number, modulusValue)

    if gcdValue != 1:
        return None

    inverse = numberCoefficient % modulusValue

    return inverse


# ============================================================
# Affine Multiplier Validation
# ============================================================

def checkAffineMultiplier(multiplier, modulusValue):
    gcdValue, multiplierCoefficient, modulusCoefficient = extendedGcd(multiplier, modulusValue)

    isValid = gcdValue == 1

    return (isValid, gcdValue, multiplierCoefficient, modulusCoefficient)


# ============================================================
# Letter Conversion
#
# A = 0
# B = 1
# ...
# Z = 25
# ============================================================

def characterToValue(character):
    upperCharacter = character.upper()
    characterValue = (ord(upperCharacter) - ord("A"))

    return characterValue


def valueToCharacter(value):
    character = chr(value + ord("A"))

    return character


# ============================================================
# Question 2.1
# Affine Encryption
#
# E(m) = a*m + b mod 26
# ============================================================

def affineEncrypt(message, multiplier, shift):
    (isValid, gcdValue, multiplierCoefficient, modulusCoefficient) = checkAffineMultiplier(multiplier, modulus)

    if not isValid:
        print("Encryption refused.")
        print("Multiplier:", multiplier)
        print("Modulus:", modulus)
        print("gcd:", gcdValue)
        print("Multiplier coefficient:", multiplierCoefficient)
        print("Modulus coefficient:", modulusCoefficient)
        print("The multiplier does not have a modular inverse.")

        return None

    encryptedMessage = ""

    for character in message:
        if character == " ":
            encryptedMessage += " "
            continue

        upperCharacter = character.upper()

        if "A" <= upperCharacter <= "Z":
            letterValue = characterToValue(character)

            encryptedValue = (multiplier * letterValue + shift) % modulus
            encryptedCharacter = valueToCharacter(encryptedValue)

            encryptedMessage += encryptedCharacter

    return encryptedMessage


# ============================================================
# Question 2.1
# Affine Decryption
#
# D(c) = a^(-1) * (c - b) mod 26
# ============================================================

def affineDecrypt(message, multiplier, shift):
    inverseMultiplier = modularInverse(multiplier, modulus)

    if inverseMultiplier is None:
        print("Decryption refused.")
        print(multiplier, "does not have a modular inverse modulo", modulus)

        return None

    decryptedMessage = ""

    for character in message:
        if character == " ":
            decryptedMessage += " "
            continue

        upperCharacter = character.upper()

        if "A" <= upperCharacter <= "Z":
            letterValue = characterToValue(character)

            decryptedValue = (inverseMultiplier * (letterValue - shift)) % modulus
            decryptedCharacter = valueToCharacter(decryptedValue)

            decryptedMessage += decryptedCharacter

    return decryptedMessage


# ============================================================
# Question 1.1 Test
# ============================================================

def testExtendedGcd(firstNumber, secondNumber):
    gcdValue, firstCoefficient, secondCoefficient = extendedGcd(firstNumber, secondNumber)

    bezoutVerification = (firstNumber * firstCoefficient + secondNumber * secondCoefficient)

    print("Extended GCD Test")
    print("-----------------")
    print("First number:", firstNumber)
    print("Second number:", secondNumber)
    print("gcd:", gcdValue)
    print("First Bezout coefficient:", firstCoefficient)
    print("Second Bezout coefficient:", secondCoefficient)
    print("Bezout verification:", bezoutVerification)
    print()


# ============================================================
# Question 1.3 Test
# ============================================================

def testModularInverse(number, modulusValue):
    gcdValue, numberCoefficient, modulusCoefficient = extendedGcd(number, modulusValue)

    inverse = modularInverse(number, modulusValue)

    print("Modular Inverse Test")
    print("--------------------")
    print("Number:", number)
    print("Modulus:", modulusValue)
    print("gcd:", gcdValue)
    print("Number coefficient:", numberCoefficient)
    print("Modulus coefficient:", modulusCoefficient)

    if inverse is None:
        print(number, "has no modular inverse modulo", modulusValue)

    else:
        verification = (number * inverse) % modulusValue

        print("Modular inverse:", inverse)
        print("Verification:", number, "*", inverse, "mod", modulusValue, "=", verification)

    print()


# ============================================================
# Question 2.1 / 2.3 Test
# ============================================================

def testAffineCipher(message, multiplier, shift):
    (isValid, gcdValue, multiplierCoefficient, modulusCoefficient) = checkAffineMultiplier(multiplier, modulus)

    print("Affine Cipher Test")
    print("------------------")
    print("Original message:", message)
    print("a =", multiplier)
    print("b =", shift)
    print("gcd:", gcdValue)
    print("Multiplier coefficient:", multiplierCoefficient)
    print("Modulus coefficient:", modulusCoefficient)

    if not isValid:
        print("Invalid affine cipher multiplier.")
        print()
        return

    inverseMultiplier = modularInverse(multiplier, modulus)

    print("Inverse of a:", inverseMultiplier)

    encryptedMessage = affineEncrypt(message, multiplier, shift)
    decryptedMessage = affineDecrypt(encryptedMessage, multiplier, shift)

    print("Encrypted message:", encryptedMessage)
    print("Decrypted message:", decryptedMessage)

    if decryptedMessage == message.upper():
        print("Round-trip verification: successful")
    else:
        print("Round-trip verification: failed")

    print()


# ============================================================
# Question 2.2 Test
# Illegal multiplier
# ============================================================

def testInvalidAffineKey(message, multiplier, shift):
    (isValid, gcdValue, multiplierCoefficient, modulusCoefficient) = checkAffineMultiplier(multiplier, modulus)

    print("Invalid Affine Key Test")
    print("-----------------------")
    print("Message:", message)
    print("a =", multiplier)
    print("b =", shift)
    print("gcd:", gcdValue)
    print("Multiplier coefficient:", multiplierCoefficient)
    print("Modulus coefficient:", modulusCoefficient)
    print("Valid multiplier:", isValid)

    encryptedMessage = affineEncrypt(message, multiplier, shift)

    if encryptedMessage is None:
        print("No ciphertext was produced.")
    else:
        print("Encrypted message:", encryptedMessage)

    print()


# ============================================================
# Main
# ============================================================

def main():
    print("========================================")
    print("PERSONAL AFFINE CIPHER KEY")
    print("========================================")
    print()

    print("a =", affineMultiplier)
    print("b =", affineShift)
    print()

    print("========================================")
    print("QUESTION 1.1")
    print("========================================")
    print()

    testExtendedGcd(affineMultiplier, modulus)

    print("========================================")
    print("QUESTION 1.3")
    print("========================================")
    print()

    testModularInverse(affineMultiplier, modulus)
    testModularInverse(13, modulus)
    testModularInverse(8, modulus)

    print("========================================")
    print("QUESTION 2.1 AND 2.3")
    print("========================================")
    print()

    testAffineCipher("DAVID", affineMultiplier, affineShift)

    print("========================================")
    print("QUESTION 2.2")
    print("========================================")
    print()

    testInvalidAffineKey("DAVID", 13, affineShift)


if __name__ == "__main__":
    main()