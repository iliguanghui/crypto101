def extended_gcd(a, b):
    old_r, r = a, b
    old_x, x = 1, 0
    old_y, y = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r= r, old_r - q * r
        old_x, x= x, old_x - q * x
        old_y, y= y, old_y - q * y
    return old_r, old_x, old_y # gcd, x, y


if __name__ == '__main__':
    a, b = 240, 46
    gcd, x, y = extended_gcd(a, b)
    print(f"{gcd} = {x} * {a} + {y} * {b}")