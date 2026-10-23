# Reed-Solomon codes on a toy example

The last three words of a paper backup are a checksum called `rs1024`,
borrowed from SLIP-0039. It is a Reed-Solomon code. This chapter explains
what that means, first on a tiny example with numbers mod 7, then on the
real 22-word backup. It is background reading: nothing here is needed to
use the tool. [FORMAT.md](../FORMAT.md) specifies the checksum exactly.

## The idea in one sentence

A polynomial of degree less than k is determined by any k of its values.
Publish more than k values, and the extra ones are redundancy: any k of
them rebuild the polynomial and therefore all the others. Reed-Solomon
codes are this idea with the values taken in a finite field, so that the
arithmetic is exact and every symbol has the same size.

## A toy code with numbers mod 7

Work in GF(7), the integers mod 7. The message is two symbols, 3 and 5.
Read them as the values of a line at x = 0 and x = 1. The unique line
through (0, 3) and (1, 5) is y = 3 + 2x. Evaluate that line at three more
points to get the check symbols:

| x | 0 | 1 | 2 | 3 | 4 |
| --- | --- | --- | --- | --- | --- |
| y = 3 + 2x mod 7 | **3** | **5** | 0 | 2 | 4 |

The codeword is `3 5 0 2 4`. The first two symbols are the message
verbatim and the last three are check symbols. A backup has the same
shape: 19 data words followed by 3 check words.

A sequence of five symbols is *valid* when its five points (0, y0) to
(4, y4) lie on one line. There are 49 lines, so 49 of the 16,807 possible
sequences are valid.

### Why any three errors are detected

Two different lines share at most one point. So any other valid codeword
agrees with ours in at most 1 of the 5 positions and differs in at least 4.
For example, the line 3 + 3x gives `3 6 2 5 1`, which differs from
`3 5 0 2 4` in four positions. The code has *minimum distance* 4.

Consequence: changing 1, 2 or 3 symbols of a valid codeword can never land
on another valid codeword. Every error affecting up to three symbols is
detected with certainty. A hash-based checksum only detects such an error
with high probability; this is a guarantee.

### Locating one error

Suppose you receive `3 5 0 6 4`. The line through the first two points,
3 + 2x, predicts 2 at x = 3, but you received 6, so the sequence is
invalid. Which symbol is wrong? Perhaps position 3. But perhaps position 0
is wrong and the true line is the one through the other four points. One
pair of points cannot tell you.

**The vote.** Draw the line through every pair of received points and
count how many of the five points each line contains:

| Pair used | Line | Values at x = 0..4 | Received points on it |
| --- | --- | --- | --- |
| (0, 3), (1, 5) | 3 + 2x | 3 5 0 2 4 | positions 0, 1, 2, 4: **four** |
| (0, 3), (3, 6) | 3 + x | 3 4 5 6 0 | positions 0, 3: two |
| (1, 5), (3, 6) | 1 + 4x | 1 5 2 6 3 | positions 1, 3: two |

Every other pair gives either 3 + 2x again or a line with only two points.
Exactly one line holds four of the five points. The point not on it,
position 3, is the error, and the line's value there, 2, is the correction.

Why four points on a line settle it: if only one symbol was changed, the
four untouched points still lie on the original line. Any other line
contains at most one of those four, plus possibly the altered point, so at
most two. Four points on one line can only happen for the true line.

**The brute-force version.** Instead of drawing lines, try all 30 single
changes, 5 positions times 6 alternative values, and test each result for
validity. Exactly one succeeds: position 3 set to 2. Here is why exactly
one. A successful trial produces some codeword C'. It differs from the
received sequence in one place, and the received sequence differs from the
true codeword C in one place, so C and C' differ in at most two places.
Two different codewords always differ in at least four. So C' is C.

### Two errors: a tie

Take the true codeword `3 5 0 2 4` and the other line `3 6 2 5 1`. They
share only the point at x = 0. Change positions 1 and 2 of the true
codeword to the other line's values. You receive `3 6 2 2 4`.

Now the vote ties. The line 3 + 2x holds positions 0, 3 and 4. The line
3 + 3x holds positions 0, 1 and 2. The received data is equally consistent
with "line A with errors at 1 and 2" and "line B with errors at 3 and 4".
No decoder can break that tie, so two errors cannot be corrected reliably.

They are still detected. The received sequence is not valid, and the
brute-force search finds nothing, because the sequence is at distance 2
from both lines and no single change reaches either. A decoder can
truthfully report "at least two symbols are wrong" without guessing which.

### Three errors: a convincing impostor

Change positions 1, 2 and 3 of the true codeword to the other line's
values. You receive `3 6 2 5 4`.

It differs from the truth `3 5 0 2 4` in three places. It differs from
`3 6 2 5 1` in only one place, position 4. The vote finds four points on
the line 3 + 3x, and the brute-force search finds exactly one valid single
change, position 4 set to 1. Both methods confidently "correct" to
`3 6 2 5 1`, whose message is 3, 6 instead of 3, 5.

Nothing in the received data distinguishes "three errors from line A"
from "one error from line B". A decoder that corrects picks the
explanation with fewer errors, and here that is the wrong one. Note that
the sequence is still invalid as received, so a decoder that only checks
validity and never corrects rejects it. With three check symbols you get
either "detect up to 3 errors" or "correct 1 while reliably detecting 2",
not both at once.

### The rule behind all three cases

With e wrong symbols, the received sequence is at distance e from the truth
and, by the triangle inequality, at distance at least 4 − e from every
other codeword:

| Errors | Distance to truth | Distance to any other codeword | What a decoder sees |
| --- | ---: | ---: | --- |
| 1 | 1 | ≥ 3 | one unique single-symbol fix, and it is correct |
| 2 | 2 | ≥ 2 | invalid, no single-symbol fix, possible tie |
| 3 | 3 | ≥ 1 | invalid, but a single-symbol fix may exist and be wrong |
| 4 | 4 | ≥ 0 | may be another valid codeword, undetectable |

## From seven numbers to 1024 words

Replace GF(7) by GF(1024), the field with 2^10 elements. Its elements are
10-bit values. Addition is XOR, and multiplication is polynomial
multiplication over GF(2) reduced modulo a fixed irreducible polynomial of
degree 10. Every word index in the wordlist is one field element, so a
word is one symbol and a completely garbled word is one symbol error.

A backup is 19 data words and 3 check words. The same argument as above
applies: two different polynomials of degree below 19 agree in at most 18
of the 22 positions, so the minimum distance is again 4, and so are the
consequences in the table. The field has 1024 elements, which allows
sequences of up to 1023 symbols. Twenty-two is nowhere near that limit.

`rs1024` is organized a little differently from the line code, as the next
section shows, but the guarantee and the reason for it are the same.

## How rs1024 actually computes the check words

The line code describes codewords by evaluation. The equivalent and more
convenient description is by division: a sequence is a codeword when, read
as the coefficients of a polynomial, it is divisible by a fixed *generator*
polynomial g(x). This is exactly how a CRC works, except that a CRC uses
bits as symbols, and here the symbols are whole words.

### The same trick in GF(7)

Pick α = 3. Its powers mod 7 are 3, 2, 6, 4, 5, 1, so it generates every
nonzero element. Let the generator have the roots α, α² and α³:

```text
g(x) = (x − 3)(x − 2)(x − 6) = x³ + 3x² + x + 6   (mod 7)
```

A sequence `c4 c3 c2 c1 c0` is a codeword when c(x) = c4·x⁴ + ... + c0 is
divisible by g(x), which is the same as c(3) = c(2) = c(6) = 0. Encoding is
systematic: put the data in c4 and c3, divide c4·x⁴ + c3·x³ by g(x), and
set c2, c1, c0 to the negated remainder so that the whole thing divides
evenly. For the data 3, 5 this gives the codeword `3 5 5 0 4`. It is a
different set of 49 codewords from the line code, but it also has minimum
distance 4.

The reason is again "a nonzero polynomial has few roots", in a different
costume. If two codewords differed in only three places, their difference
would be a polynomial with at most three nonzero terms that vanishes at the
three distinct points α, α², α³. Such a polynomial must be zero, so the
codewords were equal.

Division also *locates* a single error without any voting. Suppose the
received polynomial is r(x) = c(x) + e·x^j, one error of size e at the
symbol of degree j. Evaluating at the three roots gives the *syndromes*:

```text
S1 = r(α)  = e·α^j
S2 = r(α²) = e·α^(2j)
S3 = r(α³) = e·α^(3j)
```

S2 / S1 = α^j reveals j, then e = S1 / α^j, and S3 must equal e·α^(3j) or
there is more than one error. Example: change c1 of `3 5 5 0 4` from 0 to
4, receiving `3 5 5 4 4`. The syndromes are S1 = 5, S2 = 1, S3 = 3.
S2 / S1 = 1 · 5⁻¹ = 3 = α¹, so j = 1: the symbol c1 is wrong. Then
e = 5 / 3 = 5 · 5 = 4, and S3 = 4 · α³ = 4 · 6 = 24 ≡ 3 matches.

### The ten constants

The `rs1024` code in FORMAT.md is long division by g(x) performed one word
at a time. Its 30-bit state `chk` is the remainder so far, three symbols of
10 bits. Each step shifts the state left by one symbol (multiplication by
x), XORs in the incoming word, and reduces: the symbol `b` that overflowed
past degree 2 is removed by subtracting b·g(x). Since the b·x³ part cancels,
that means XORing b·(g(x) − x³) into the three remaining symbols.

Multiplication by b is linear over GF(2), so b·(g − x³) is the XOR of
2^i·(g − x³) over the set bits i of b. `GEN[i]` is exactly 2^i·(g − x³)
packed into 30 bits. Ten constants cover every possible b. As a small check,
`GEN[0]` splits into the symbols 14, 56 and 64, the low coefficients of the
generator, and `GEN[1]` to `GEN[3]` are plain left shifts of `GEN[0]`.
From `GEN[4]` on, a coefficient would overflow 10 bits and the field's
reduction polynomial bends the pattern. The loop never names the field's
polynomial or α explicitly; both are baked into the constants.

Two further details. The customization string, `gpkb` here and `shamir` in
SLIP-39, is a fixed prefix of symbols fed into the division before the
data. Two different prefixes give disjoint sets of valid sequences, which
is why a SLIP-39 share fails the GPKB checksum and vice versa. And the
state starts at 1 rather than 0, with a final XOR of 1, so that a leading
`academic` (index 0) changes the result; starting from 0, any number of
leading zero symbols would leave the remainder unchanged.

## The real thing: the project's test vector

`tests/vectors.txt` contains a complete backup:

```text
activity permit founder academic again category ruin aircraft branch husky
adjust ancestor crunch royal elevator average echo beard liquid home spill beard
```

As word indices these are

```text
5 661 366 0 16 128 772 20 96 450 9 40 176 771 270 60 257 68 531 | 440 851 68
```

The first symbol, `0000000101` in binary, carries the version byte `01` in
its top eight bits. Running the FORMAT.md code on the first 19 indices with
customization `gpkb` returns 440, 851, 68, the words `home spill beard`.

Plant one error: replace the seventh word `ruin` with `ruler`. The checksum
fails. Trying all 1023 alternatives at each of the 22 positions, 22,506
candidates, finds exactly one valid sequence: position 7 restored to `ruin`.
That is what `paper-pgp decode` reports as "word 7 is probably wrong". It
names the position and never the word, and it never applies the change,
for the reason the three-error example gave: a sequence with three wrong
words can be one substitution away from a different valid backup. The
fingerprint comparison after recovery remains the final check.

This short program reproduces the numbers above:

```python
GEN = [0xe0e040, 0x1c1c080, 0x3838100, 0x7070200, 0xe0e0009,
       0x1c0c2412, 0x38086c24, 0x3090fc48, 0x21b1f890, 0x3f3f120]

def polymod(values):
    chk = 1
    for v in values:
        b = chk >> 20
        chk = (chk & 0xfffff) << 10 ^ v
        for i in range(10):
            chk ^= GEN[i] if (b >> i) & 1 else 0
    return chk

CS = [ord(c) for c in "gpkb"]
data = [5, 661, 366, 0, 16, 128, 772, 20, 96, 450, 9, 40, 176, 771, 270, 60, 257, 68, 531]
pm = polymod(CS + data + [0, 0, 0]) ^ 1
check = [(pm >> 10 * (2 - i)) & 1023 for i in range(3)]
assert check == [440, 851, 68]
words = data + check
assert polymod(CS + words) == 1

bad = words[:]
bad[6] = 773                                   # "ruler" instead of "ruin"
assert polymod(CS + bad) != 1
hits = [(q + 1, u) for q in range(22) for u in range(1024)
        if u != bad[q] and polymod(CS + bad[:q] + [u] + bad[q + 1:]) == 1]
assert hits == [(7, 772)]
```

## Why three check words

Three check words give distance 4, so every error touching up to three
words is caught with certainty, and random garbage passes with probability
2^-30. The previous design used a truncated SHA-256 of 40 bits: one word
longer, a 2^-40 pass rate for garbage, but only probabilistic detection and
no way to locate anything. For handwriting, the typical failure is one or
two misread words, which is exactly the regime the Reed-Solomon code
handles best.

More check words would buy more. Four give distance 5, which detects four
errors or corrects two, with a 2^-40 pass rate for garbage. That needs a
generator with four roots and a new set of constants, since the SLIP-39
constants are built for three. Reusing the published, widely tested
`rs1024` was judged worth more than the extra margin.

## Further reading

- [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md),
  which defines `rs1024` and the wordlist.
- [BIP-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki),
  whose bech32 checksum introduced this style of polymod loop, over GF(32).
- [Reed-Solomon codes for coders](https://en.wikiversity.org/wiki/Reed%E2%80%93Solomon_codes_for_coders),
  a hands-on introduction to the field arithmetic and the decoding algorithms.
- [Reed–Solomon error correction](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction)
  on Wikipedia, for the general theory and the history.
