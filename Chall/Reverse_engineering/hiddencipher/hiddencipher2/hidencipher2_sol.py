data = [1680, 1575, 1485, 1665, 1005, 1260, 1050, 1845, 1635, 780, 1740, 1560, 1425, 1470, 765, 1560, 735, 1650, 1500, 1425, 1485, 735, 1680, 1560, 765, 1710, 1425, 780, 1455, 765, 1470, 750, 1485, 1485, 1530, 1875] # Replace your nums list here
text = ""
for num in data:
  char = num // 15 # Divide 15 to get the ascii number
  text += chr(char)
print(f"Flag is : {text}") # Flag