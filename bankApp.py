# Define the file names for bank data and transaction log
bank_data_file = "Bank Data.txt"
transaction_log_file = "Transaction Log.txt"


# Function to read the current balance from the bank data file
def read_balance():
    try:
        with open(bank_data_file, "r") as file:
            return float(file.read())
    except FileNotFoundError:
        # If the file doesn't exist, initialize the balance to 0
        return 0.0


# Function to update the bank data file with a new balance
def update_balance(new_balance):
    with open(bank_data_file, "w") as file:
        file.write(str(new_balance))


# Function to log transactions in the transaction log file
def log_transaction(transaction_type, amount, balance):
    with open(transaction_log_file, "a") as file:
        file.write(f"{transaction_type}: {amount} - New Balance: {balance}\n")


# Main function to interact with the user
def main():
    print("Welcome to the Banking Application!")

    while True:
        print("Would you like to make a transaction? (Yes or No)")
        choice = input().strip().lower()

        if choice != "yes":
            break

        current_balance = read_balance()
        print(f"Current Balance: ${current_balance:.2f}")

        print("Would you like to make a deposit or withdrawal? (Deposit or Withdraw)")
        transaction_type = input().strip().lower()

        if transaction_type not in ["deposit", "withdraw"]:
            print("You provided an invalid input")
            continue

        try:
            amount = float(input(f"How much would you like to {transaction_type}? $"))
            if transaction_type == "deposit":
                current_balance += amount
            else:
                if amount > current_balance:
                    print("Insufficient funds.")
                    continue
                current_balance -= amount
        except ValueError:
            print("You provided an invalid input")
            continue

        update_balance(current_balance)
        log_transaction(transaction_type, amount, current_balance)

        print(f"Transaction completed. New Balance: ${current_balance:.2f}")


# if __name__ == "__main":
main()
