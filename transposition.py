# python
# TO ENCRYPT
# remove spaces in text plus punctuation
# divide by length of key word place in equal columns and append x to the end to make the lists equal
# sort lists in list by order of key word letters in order and put into single string.

# TO DECRYPT
# create a list within a list
# brute force by dividing by 2 and 3 and test every permutation by arranging the combination of letters (assume X's are not present at all)
# use same letter scoring system as affine


import itertools
import englishDictionary


questionTwoCipherText = (
    "MENLRO THHRTX EBDIYO MIEANX EETBAN"
)

keyword = "CRYPT"


# ============================================================
# Text Cleaning
# ============================================================

def cleanText(message):
    cleanedMessage = ""

    for character in message:
        upperCharacter = character.upper()

        if "A" <= upperCharacter <= "Z":
            cleanedMessage += upperCharacter

    return cleanedMessage


# ============================================================
# Padding
# ============================================================

def padText(message, columnCount):
    paddedMessage = message

    while len(paddedMessage) % columnCount != 0:
        paddedMessage += "X"

    return paddedMessage


def removePadding(message):
    return message.rstrip("X")


# ============================================================
# Keyword Column Order
#
# Example:
#
# CRYPT
#
# Alphabetical order:
# C P R T Y
#
# Original column indexes:
# 0 3 1 4 2
# ============================================================

def getColumnOrder(keyword):
    upperKeyword = keyword.upper()

    columnOrder = list(range(len(upperKeyword)))

    columnOrder.sort(
        key=lambda columnIndex: (
            upperKeyword[columnIndex],
            columnIndex
        )
    )

    return columnOrder


# ============================================================
# Question 2.1
# Columnar Transposition Encryption
# ============================================================

def transpositionEncrypt(message, keyword):
    cleanedMessage = cleanText(message)

    columnCount = len(keyword)

    if columnCount == 0:
        print("Encryption refused.")
        print("Keyword cannot be empty.")
        return None

    paddedMessage = padText(
        cleanedMessage,
        columnCount
    )

    rowCount = len(paddedMessage) // columnCount

    grid = []

    currentPosition = 0

    for rowIndex in range(rowCount):
        row = []

        for columnIndex in range(columnCount):
            row.append(
                paddedMessage[currentPosition]
            )

            currentPosition += 1

        grid.append(row)

    columnOrder = getColumnOrder(keyword)

    cipherText = ""

    for columnIndex in columnOrder:
        for rowIndex in range(rowCount):
            cipherText += grid[rowIndex][columnIndex]

    return cipherText


# ============================================================
# Decryption Using Known Column Order
#
# This helper is also used by the brute-force search.
# ============================================================

def decryptWithColumnOrder(cipherText, columnOrder):
    cleanedCipherText = cleanText(cipherText)

    columnCount = len(columnOrder)

    if columnCount == 0:
        return None

    if len(cleanedCipherText) % columnCount != 0:
        return None

    rowCount = len(cleanedCipherText) // columnCount

    grid = []

    for rowIndex in range(rowCount):
        row = []

        for columnIndex in range(columnCount):
            row.append("")

        grid.append(row)

    currentPosition = 0

    for columnIndex in columnOrder:
        for rowIndex in range(rowCount):
            grid[rowIndex][columnIndex] = (
                cleanedCipherText[currentPosition]
            )

            currentPosition += 1

    decryptedMessage = ""

    for rowIndex in range(rowCount):
        for columnIndex in range(columnCount):
            decryptedMessage += grid[rowIndex][columnIndex]

    return decryptedMessage


# ============================================================
# Question 2.1 / 2.2
# Columnar Transposition Decryption
# ============================================================

def transpositionDecrypt(cipherText, keyword):
    columnCount = len(keyword)

    if columnCount == 0:
        print("Decryption refused.")
        print("Keyword cannot be empty.")
        return None

    columnOrder = getColumnOrder(keyword)

    decryptedMessage = decryptWithColumnOrder(
        cipherText,
        columnOrder
    )

    return decryptedMessage


# ============================================================
# English Scoring
#
# Transposition removes spaces, so whole-word splitting cannot
# be used here. Instead, search the candidate plaintext for
# common English words contained within the string.
# ============================================================

def scoreEnglish(plainText):
    cleanedPlainText = cleanText(plainText).lower()

    score = 0

    for wordLength in englishDictionary.commonWordsByLength:
        wordsOfLength = (
            englishDictionary.commonWordsByLength[
                wordLength
            ]
        )

        wordScore = englishDictionary.wordScores[
            wordLength
        ]

        for word in wordsOfLength:
            if word in cleanedPlainText:
                score += wordScore

    return score


# ============================================================
# Optional Brute-Force Transposition Search
#
# Used when no keyword is known.
#
# Only column counts that divide the ciphertext length are
# tested because every encrypted row has the same size after
# padding.
# ============================================================

def bruteForceTransposition(
    cipherText,
    minimumColumns=2,
    maximumColumns=8
):
    cleanedCipherText = cleanText(cipherText)

    results = []

    for columnCount in range(
        minimumColumns,
        maximumColumns + 1
    ):
        if len(cleanedCipherText) % columnCount != 0:
            continue

        columnIndexes = list(
            range(columnCount)
        )

        columnPermutations = itertools.permutations(
            columnIndexes
        )

        for columnOrder in columnPermutations:
            decryptedMessage = decryptWithColumnOrder(
                cleanedCipherText,
                columnOrder
            )

            score = scoreEnglish(
                decryptedMessage
            )

            results.append(
                (
                    score,
                    columnCount,
                    columnOrder,
                    decryptedMessage
                )
            )

    results.sort(reverse=True)

    return results


# ============================================================
# Decryption Selection
#
# If a keyword is supplied, use it.
#
# If keyword is None, perform the brute-force search instead.
# ============================================================

def solveTransposition(
    cipherText,
    keyword=None,
    maximumColumns=8
):
    if keyword is not None:
        decryptedMessage = transpositionDecrypt(
            cipherText,
            keyword
        )

        print("Keyword:", keyword)
        print(
            "Column order:",
            getColumnOrder(keyword)
        )
        print(
            "Plaintext with padding:",
            decryptedMessage
        )
        print(
            "Plaintext without padding:",
            removePadding(decryptedMessage)
        )
        print()

        return

    results = bruteForceTransposition(
        cipherText,
        2,
        maximumColumns
    )

    print("No keyword supplied.")
    print("Running brute-force search.")
    print("Candidates tested:", len(results))
    print()

    print("Top 10 candidate decryptions")
    print("----------------------------")

    for (
        score,
        columnCount,
        columnOrder,
        decryptedMessage
    ) in results[:10]:

        print("Score:", score)
        print("Columns:", columnCount)
        print("Column order:", columnOrder)
        print(
            "Plaintext:",
            removePadding(decryptedMessage)
        )
        print()


# ============================================================
# Question 2.1
# Round-Trip Test
# ============================================================

def testTranspositionCipher(message, keyword):
    cleanedMessage = cleanText(message)

    encryptedMessage = transpositionEncrypt(
        message,
        keyword
    )

    decryptedMessage = transpositionDecrypt(
        encryptedMessage,
        keyword
    )

    unpaddedMessage = removePadding(
        decryptedMessage
    )

    print("Transposition Cipher Test")
    print("-------------------------")
    print("Original message:", message)
    print("Cleaned message:", cleanedMessage)
    print("Keyword:", keyword)
    print(
        "Column order:",
        getColumnOrder(keyword)
    )
    print(
        "Encrypted message:",
        encryptedMessage
    )
    print(
        "Decrypted message:",
        decryptedMessage
    )
    print(
        "Without padding:",
        unpaddedMessage
    )

    if unpaddedMessage == cleanedMessage:
        print(
            "Round-trip verification: successful"
        )
    else:
        print(
            "Round-trip verification: failed"
        )

    print()


# ============================================================
# Question 2.3
# Letter Frequency Count
# ============================================================

def countLetterFrequencies(message):
    cleanedMessage = cleanText(message)

    frequencies = {}

    for characterValue in range(26):
        character = chr(
            characterValue + ord("A")
        )

        frequencies[character] = 0

    for character in cleanedMessage:
        frequencies[character] += 1

    return frequencies


# ============================================================
# Question 2.3
# Frequency Comparison
# ============================================================

def printFrequencyComparison(
    plainText,
    cipherText
):
    plainTextFrequencies = (
        countLetterFrequencies(plainText)
    )

    cipherTextFrequencies = (
        countLetterFrequencies(cipherText)
    )

    print("Letter Frequency Comparison")
    print("---------------------------")
    print("Letter  Plaintext  Ciphertext")

    for characterValue in range(26):
        character = chr(
            characterValue + ord("A")
        )

        print(
            character,
            "     ",
            plainTextFrequencies[character],
            "         ",
            cipherTextFrequencies[character]
        )

    print()


# ============================================================
# Question 2.2 Test
# ============================================================

def testQuestionTwoCipherText():
    decryptedMessage = transpositionDecrypt(
        questionTwoCipherText,
        keyword
    )

    unpaddedMessage = removePadding(
        decryptedMessage
    )

    print("Question 2.2 Decryption")
    print("-----------------------")
    print("Ciphertext:", questionTwoCipherText)
    print("Keyword:", keyword)
    print(
        "Column order:",
        getColumnOrder(keyword)
    )
    print(
        "Plaintext with padding:",
        decryptedMessage
    )
    print(
        "Plaintext without padding:",
        unpaddedMessage
    )
    print()

    return decryptedMessage


# ============================================================
# Main
# ============================================================

def main():
    print("========================================")
    print("QUESTION 2.1")
    print("========================================")
    print()

    testTranspositionCipher(
        "MY NAME IS DAVID TRAN",
        keyword
    )

    print("========================================")
    print("QUESTION 2.2")
    print("========================================")
    print()

    decryptedMessage = (
        testQuestionTwoCipherText()
    )

    print("========================================")
    print("QUESTION 2.3")
    print("========================================")
    print()

    printFrequencyComparison(
        decryptedMessage,
        questionTwoCipherText
    )

    # ========================================================
    # OPTIONAL BRUTE-FORCE TEST
    #
    # Uncomment this to search without supplying the keyword.
    # ========================================================

    # print("========================================")
    # print("OPTIONAL BRUTE-FORCE SEARCH")
    # print("========================================")
    # print()
    #
    # solveTransposition(
    #     questionTwoCipherText,
    #     keyword=None,
    #     maximumColumns=8
    # )


if __name__ == "__main__":
    main()