
import hashlib
import itertools

target = "67ae1a64661ac8b4494666f58c4822408dd0a3e4"
chars = ['(', 'Q', '=', 'w', 'i', 'n', '*', '5']  # 从图片读出的候选键
# 假设密码长度为 8 且每个按键只按一次 -> permutations
for perm in itertools.permutations(chars, 8):
    s = ''.join(perm)
    if hashlib.sha1(s.encode()).hexdigest() == target:
        print("FOUND:", s)
        break
