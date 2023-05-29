import random
import math

class Cryptography:
    @staticmethod
    def generate_key(bit_length):
        p = Cryptography.blum_prime(bit_length // 2)
        q = Cryptography.blum_prime(bit_length // 2)
        N = p * q
        return N, p, q

    @staticmethod
    def encrypt(m, N):
        return pow(m, 2, N)

    @staticmethod
    def decrypt(c, p, q):
        N = p * q
        p1 = pow(c, (p + 1) // 4, p)
        p2 = p - p1
        q1 = pow(c, (q + 1) // 4, q)
        q2 = q - q1

        ext = Cryptography.gcd(p, q)
        y_p = ext[1]
        y_q = ext[2]

        d1 = (y_p * p * q1 + y_q * q * p1) % N
        d2 = (y_p * p * q2 + y_q * q * p1) % N
        d3 = (y_p * p * q1 + y_q * q * p2) % N
        d4 = (y_p * p * q2 + y_q * q * p2) % N

        return d1, d2, d3, d4

    @staticmethod
    def gcd(a, b):
        s, old_s = 0, 1
        t, old_t = 1, 0
        r, old_r = b, a

        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
            old_t, t = t, old_t - quotient * t

        return old_r, old_s, old_t

    @staticmethod
    def blum_prime(bit_length):
        while True:
            p = random.getrandbits(bit_length)
            if p % 4 == 3 and Cryptography.is_prime(p):
                return p

    @staticmethod
    def is_prime(n, k=5):
        if n <= 1:
            return False
        if n <= 3:
            return True

        d = n - 1
        while d % 2 == 0:
            d //= 2

        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, d, n)

            if x == 1 or x == n - 1:
                continue

            while d != n - 1:
                x = (x * x) % n
                d *= 2

                if x == 1:
                    return False
                if x == n - 1:
                    break

            if x != n - 1:
                return False

        return True


def main():
    key = Cryptography.generate_key(512)
    n, p, q = key[0], key[1], key[2]
    final_message = None
    i = 1
    s = "my encrypted message"

    print("Message sent by sender:", s)

    m = int.from_bytes(s.encode("utf-8"), "big")
    c = Cryptography.encrypt(m, n)

    print("Encrypted Message:", c)

    m2 = Cryptography.decrypt(c, p, q)
    for b in m2:
        dec = b.to_bytes(math.ceil(b.bit_length() / 8), "big").decode("utf-8", errors="ignore")
        if dec == s:
            final_message = dec
        i += 1

    print("Message received by Receiver:", final_message)


if __name__ == "__main__":
    main()
