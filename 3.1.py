import math

p = 1009
q = 3643
phi = (p-1)*(q-1)

def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

min_count = None
best_es = []

for e in range(2, phi):
    if gcd(e, phi) != 1:
        continue
    count = gcd(e-1, p-1) * gcd(e-1, q-1)
    if (min_count is None) or (count < min_count):
        min_count = count
        best_es = [e]
    elif count == min_count:
        best_es.append(e)

print("最小未加密信息数量:", min_count)
print("满足条件的 e 数量:", len(best_es))
print("这些 e 的和:", sum(best_es))
