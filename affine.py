import euclid
import englishDictionary


questionOneCipherText = (
    "HFY ETXK WYCLYH HFGH IGHHYLW QW HFY MYK "
    "YDYLKHFQTU YXWY HFY GHHGCMYL GXLYGNK MTEOW"
)

bonusCipherText = (
    "VONBEK SCYV LODOF HCIJM XADOK"
)


# ============================================================
# Question 1.2
# English Scoring
# ============================================================

def scoreEnglish(plainText):
    words = plainText.lower().split()
    score = 0

    for word in words:
        wordLength = len(word)

        if wordLength not in englishDictionary.commonWordsByLength:
            continue

        wordsOfLength = englishDictionary.commonWordsByLength[
            wordLength
        ]

        if word in wordsOfLength:
            score += englishDictionary.wordScores[wordLength]

    return score


# ============================================================
# Question 1.2
# Exhaustive Affine Cipher Search
# ============================================================

def breakAffine(cipherText):
    results = []

    for multiplier in range(euclid.modulus):
        (
            isValid,
            gcdValue,
            multiplierCoefficient,
            modulusCoefficient
        ) = euclid.checkAffineMultiplier(
            multiplier,
            euclid.modulus
        )

        if not isValid:
            continue

        for shift in range(euclid.modulus):
            decryptedMessage = euclid.affineDecrypt(
                cipherText,
                multiplier,
                shift
            )

            score = scoreEnglish(decryptedMessage)

            results.append(
                (
                    score,
                    multiplier,
                    shift,
                    decryptedMessage
                )
            )

    results.sort(reverse=True)

    return results


# ============================================================
# Question 1.2 Test
# ============================================================

def testAffineBreaker(cipherText):
    results = breakAffine(cipherText)

    print("Affine Cipher Exhaustive Search")
    print("-------------------------------")
    print("Valid keys tested:", len(results))
    print()

    print("Top 5 candidate decryptions")
    print("---------------------------")

    for score, multiplier, shift, decryptedMessage in results[:5]:
        print("Score:", score)
        print("a =", multiplier)
        print("b =", shift)
        print("Plaintext:", decryptedMessage)
        print()

# ============================================================
# Exhaustive Affine Cipher Results
# ============================================================

def printAllAffineCandidates(cipherText):
    results = breakAffine(cipherText)

    print("Complete Affine Cipher Exhaustive Search")
    print("----------------------------------------")
    print("Valid keys tested:", len(results))
    print()

    candidateNumber = 1

    for score, multiplier, shift, decryptedMessage in results:
        print("Candidate:", candidateNumber)
        print("Score:", score)
        print("a =", multiplier)
        print("b =", shift)
        print("Plaintext:", decryptedMessage)
        print()

        candidateNumber += 1


# ============================================================
# Main
# ============================================================

def main():
    print("========================================")
    print("QUESTION 1.2")
    print("========================================")
    print()

    testAffineBreaker(questionOneCipherText)

    print("========================================")
    print("QUESTION BONUS")
    print("========================================")
    print()

    printAllAffineCandidates(bonusCipherText)


if __name__ == "__main__":
    main()