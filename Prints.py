import time
class Prints:

    @staticmethod
    def menu():
        time.sleep(0.1)
        print("\nMENU:")
        # print("'m' for message | 'f' for file | 'sml' for simulate message lost | '!quit' for quit")
        print("'m' for message | 'f' for file | '!q / !quit' for quit")
        choice = input("Choose an option: ").strip()
        return choice

    @staticmethod
    def info_menu():
        print("MENU:")
        # print("'m' for message | 'f' for file | 'sml' for simulate message lost | '!quit' for quit")
        print("'m' for message | 'f' for file | '!q / !quit' for quit")