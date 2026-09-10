# 1. Sum of a list of numbers
def sum_list(numbers):
    """Returns the sum of all numbers in a list."""
    total = 0
    for num in numbers:
        total += num
    return total

# Example:
# numbers = [1, 2, 3, 4]
# print(sum_list(numbers))  # Output: 10

# 2. Find the largest number in a list
def find_max(numbers):
    """Returns the largest number in a list."""
    max_num = numbers[0]
    for num in numbers:
        if num > max_num:
            max_num = num
    return max_num

# Example:
# numbers = [5, 2, 9, 1]
# print(find_max(numbers))  # Output: 9

# 3. Reverse a string
def reverse_string(text):
    """Returns the reverse of a given string."""
    return text[::-1]

# Example:
# text = "hello"
# print(reverse_string(text))  # Output: "olleh"

# 4. Count occurrences of an item in a list
def count_occurrences(items, target):
    """Returns how many times 'target' appears in 'items'."""
    count = 0
    for item in items:
        if item == target:
            count += 1
    return count

# Example:
# fruits = ["apple", "banana", "apple", "orange"]
# print(count_occurrences(fruits, "apple"))  # Output: 2

# 5. Filter even numbers from a list
def filter_evens(numbers):
    """Returns a new list with only the even numbers."""
    evens = []
    for num in numbers:
        if num % 2 == 0:
            evens.append(num)
    return evens

# Example:
# numbers = [1, 2, 3, 4, 5, 6]
# print(filter_evens(numbers))  # Output: [2, 4, 6]