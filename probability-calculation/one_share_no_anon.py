import numpy as np
import math
import matplotlib.pyplot as plt

def GetCombination (n, r):
    if n < 0 or r < 0:
        return -1
    if r > n:
        return -1
    return math.comb(n, r)

def GetSign(power):
    val = 1
    for _ in range(power):
        val *= (-1)
    return val

r = 10
t = 5
s = 10

results = []
results2 = []
count = 0

for t in range(2, s):
    results.append([])
    results2.append([])
    for p in range(1, r*s):
        denominator = math.comb(r*s, p)
        numerator = 0
        for i in range(r):
            sign = GetSign(i)
            term1 = GetCombination(r, i)
            term2 = GetCombination(p - r * t - i*(s-t+1)+r-1, r-1)
            if term1 > 0 and term2 > 0:
                # print(sign, term1, term2)
                numerator += sign * term1 * term2
        results[count].append(float(numerator)/float(denominator))
        results2[count].append(numerator)
    count = count + 1

x = [i for i in range(1, r*s)]
results3 = []
for i in range(count):
    sum2 = sum(results2[i])
    results3.append([x / sum2 for x in results2[i]])
for i in range(count):
    plt.plot(x, results3[i])

legend = [i for i in range(2, s)]
# Set labels and title
plt.xlabel('No. of trustees contacted', fontsize=15)
plt.ylabel('Probability of secret recovery', fontsize=15)
plt.xticks(fontsize=12)
plt.yticks(fontsize=12)
# add legend
plt.grid(True)
plt.legend(legend)
plt.savefig('plot-prob-1.pdf', format='pdf', dpi=300, bbox_inches='tight')