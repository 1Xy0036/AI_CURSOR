def greet(name):
  """
  这个函数会生成一句个性化的问候语并返回它。
  """
  if name:
    return f"你好, {name}！欢迎来到编程的世界。"
  else:
    return "你好！请输入一个名字。"

# 获取用户输入的名字并调用函数
user_name = input("请输入你的名字: ")
message = greet(user_name)

# 1. 将问候语打印到屏幕
print(message)

# 2. 将同一句问候语写入到本地文件
file_name = "greetings_log.txt"
with open(file_name, "w", encoding="utf-8") as f:
  f.write(message)

print(f"问候语已成功写入到文件: {file_name}")