from CTkMessagebox import CTkMessagebox
from time import gmtime, strftime
import customtkinter as ctk
from PIL import Image
import random
import hashlib
import json

USER_DATA_FILE = 'user_data.txt'


def load_user_data():
    try:
        with open(USER_DATA_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}


def save_user_data(user_data):
    with open(USER_DATA_FILE, 'w') as file:
        json.dump(user_data, file, indent=2)


def validate_inputs(input1, input2, input3):
    # Validate the first input (must be text)
    if not isinstance(input1, str):
        return False

    # Validate the second input (must be non-zero int or float, 50 and above)
    if not (isinstance(input2, (int, float)) and input2 != 0 and input2 >= 50):
        return False

    # Validate the third input (must be text)
    if not isinstance(input3, str):
        return False

    # All validations passed
    return True


def register_user(master, username, account, amount, gen_password, security_question, security_answer):

    user_data = load_user_data()

    if validate_inputs(username, amount, security_answer):
        CTkMessagebox(title="Error", message="Invalid Input\nPlease try again.", icon="warning")
        # master.destroy()
        return

    # Hash the password before storing
    hashed_password = hashlib.sha256(gen_password.encode()).hexdigest()

    # Store user data
    user_data[username] = {
        'account': account,
        'amount': amount,
        'password': hashed_password,
        'security_question': security_question,
        'security_answer': hashlib.sha256(security_answer.encode()).hexdigest()
    }

    # Save updated user data to the file
    save_user_data(user_data)

    CTkMessagebox(title="Acc Details", message="Your Account Number is: " + str(account), icon="check")
    master.destroy()
    Main_Menu()


#
def signup(master):
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    master.destroy()

    signup_wind = ctk.CTkToplevel()
    signup_wind.geometry("570x600")
    signup_wind.title("Create Account")

    # Title/Heading
    l_title = ctk.CTkLabel(master=signup_wind, text="CodeX   Banking   System", font=('Times New Roman Bold', 20))
    l_title.pack(pady=20)

    # Image frame
    icon = ctk.CTkImage(dark_image=Image.open("Images/Sign.jpg"), size=(200, 200))
    disply_icon = ctk.CTkLabel(signup_wind, image=icon, text='').pack(padx=20, pady=20)

    # Details Frame
    frame = ctk.CTkFrame(master=signup_wind)
    frame.pack(pady=10, padx=40, fill='both', expand=True)

    # Enter Name
    l1 = ctk.CTkLabel(frame, text="Enter Name:")
    l1.grid(row=0, column=0, pady=12, padx=10)
    e1 = ctk.CTkEntry(frame)
    e1.grid(row=0, column=1, pady=12, padx=10)

    # Enter the opening amount
    l3 = ctk.CTkLabel(frame, text="Enter opening amount:")
    l3.grid(row=1, column=0, pady=12, padx=10)
    e2 = ctk.CTkEntry(frame)
    e2.grid(row=1, column=1, pady=12, padx=10)

    # Display and Generate PIN
    generated_pin_label = ctk.CTkLabel(frame, text="Generated Password:")
    generated_pin_label.grid(row=2, column=0, pady=12, padx=10)

    e3 = ctk.CTkEntry(frame, show="*")
    e3.grid(row=2, column=1, pady=12, padx=10)

    # Enter the security question
    l5 = ctk.CTkLabel(frame, text="Security question*\nWhat is your pet\'s name?:")
    l5.grid(row=3, column=0, pady=12, padx=10)
    e4 = ctk.CTkEntry(frame)
    e4.grid(row=3, column=1, pady=12, padx=10)

    # Generating random account number
    account = random.randint(65 * 10 ** (9), 65 * 10 ** (10) - 1)

    def generate_pin():

        # Initializing our character values
        lowerCase = "abcdefghijklmnopqrstuvwxyz"
        upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        numbers = "0123456789"
        symbols = "!@#$%^&*.[]"

        # The string variable is created by concatenating all these character sets
        string = lowerCase + upperCase + numbers + symbols

        # The length variable specifies the desired length of the password.
        length = 16

        # Randomly shuffle the characters in the string
        shuffled_string = ''.join(random.sample(string, len(string)))

        # Randomly select length number of characters from the shuffled string
        password = ''.join(random.sample(shuffled_string, length))

        # random_pin = str(random.randint(1000, 9999))
        e3.delete(0, 'end')  # Clear any existing PIN in the entry field
        e3.insert(0, password)  # Insert the generated PIN into the entry field

    # Show and Hide Pin
    def show_and_hide():
        if e3.cget('show') == '*':
            e3.configure(show='')

        else:
            e3.configure(show='*')

    # Back Button
    b1 = ctk.CTkButton(frame, text="Back", command=lambda: home_return(signup_wind))
    b1.grid(row=4, column=0, pady=12, padx=10, sticky="w")

    pin_checkbox = ctk.CTkCheckBox(frame, text="Show Password", fg_color='red', font=('verdana', 11),
                                   command=show_and_hide)
    pin_checkbox.grid(row=2, column=2, pady=12, padx=10)

    # Generate PIN Button
    generate_pin_button = ctk.CTkButton(frame, text="Generate Password", command=generate_pin)
    generate_pin_button.grid(row=4, column=1, pady=12, padx=10)

    # Sign up Button
    b = ctk.CTkButton(frame, text="Submit",
                      command=lambda: register_user(signup_wind, e1.get().strip(), account, e2.get().strip(),
                                                    e3.get().strip(), 'What is your pet\'s name?:', e4.get().strip()))
    b.grid(row=4, column=2, pady=12, padx=10)

    # Back Button
    b1 = ctk.CTkButton(signup_wind, text="Back", command=signup_wind.destroy)
    b1.grid(row=5, column=2, pady=12, padx=10)

    #
    # register_user(e1.get().strip(), e2.get().strip(), e3.get().strip(), 'What is your pet\'s name?:', e4.get().strip())
    signup_wind.bind("<Return>", lambda x:  register_user(signup_wind, e1.get().strip(), account, e2.get().strip(),
                                                    e3.get().strip(), 'What is your pet\'s name?:', e4.get().strip()))
    # master.destry()
    return


def recover_password(master, username, new_password, security_answer):

    user_data = load_user_data()

    if username in user_data:
        # Verify the security answer
        hashed_answer = hashlib.sha256(security_answer.encode()).hexdigest()
        if hashed_answer == user_data[username]['security_answer']:
            # Update the password
            user_data[username]['password'] = hashlib.sha256(new_password.encode()).hexdigest()
            CTkMessagebox(title="Success", message="Password recovery successful!.", icon="check")

            master.destroy()
            log_in(master)
            # Save updated user data to the file
            save_user_data(user_data)
        else:
            CTkMessagebox(title="Error", message="Incorrect security answer.", icon="warning")
    else:
        CTkMessagebox(title="Error", message="User not found.\n", icon="warning")
        return


# Add this function for handling forgotten passwords
def forgot_password(master):
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    master.destroy()

    forgotPassword_wind = ctk.CTkToplevel()
    forgotPassword_wind.geometry("340x200")
    forgotPassword_wind.title("Reset Password")

    l1 = ctk.CTkLabel(forgotPassword_wind, text="Enter username: ")
    e1 = ctk.CTkEntry(forgotPassword_wind)
    l1.grid(row=0, column=0, padx=10, pady=10, sticky="e")
    e1.grid(row=0, column=1, padx=10, pady=10, sticky="e")

    l2 = ctk.CTkLabel(forgotPassword_wind, text="Enter New Password: ")
    e2 = ctk.CTkEntry(forgotPassword_wind)
    l2.grid(row=1, column=0, padx=1, pady=10, sticky="e")
    e2.grid(row=1, column=1, padx=10, pady=10, sticky="e")

    l3 = ctk.CTkLabel(forgotPassword_wind, text="Security question*\nWhat is your pet\'s name?:")
    e3 = ctk.CTkEntry(forgotPassword_wind)
    l3.grid(row=2, column=0, padx=10, pady=10, sticky="e")
    e3.grid(row=2, column=1, padx=10, pady=10, sticky="e")

    reset_button = ctk.CTkButton(forgotPassword_wind, text="Reset", command=lambda:recover_password(forgotPassword_wind, e1.get().strip(), e2.get().strip(), e3.get().strip()))
    reset_button.grid(row=3, column=1, padx=10, pady=10, sticky="e")
    forgotPassword_wind.bind("<Return>", lambda x: recover_password(forgotPassword_wind, e1.get().strip(), e2.get().strip(), e3.get().strip()))


def check_log_in(master, username, password):
    user_data = load_user_data()
    if username in user_data:

        print(f"Welcome, {username}! You have successfully logged in.")
        if username in user_data:
            # Verify the password
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            if hashed_password == user_data[username]['password']:
                CTkMessagebox(title="Success", message=f"Welcome, {username}! You have successfully logged in.",
                              icon="check")
                master.destroy()
                logged_in_menu(username)
            else:
                CTkMessagebox(title="Error", message="Incorrect password", icon="warning")
                return False
        else:
            print("User not found.")
            return False
        # You can perform additional actions for a successful login here
    else:
        CTkMessagebox(title="Error", message=f"Error: User '{username}' not found. Please check your username.", icon="warning")
        print(f"Error: User '{username}' not found. Please check your username.")
        return
        # You can customize the error message or take additional actions for unsuccessful login attempts
        # master.destroy()
        #logged_in_menu(account_num)


#
def log_in(master):
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    master.destroy()

    login_wind = ctk.CTkToplevel()
    login_wind.geometry("560x500")
    login_wind.title("Log in")

    # Title/Heading
    l_title = ctk.CTkLabel(master=login_wind, text="CodeX Banking System", font=('Times New Roman Bold', 20))
    l_title.pack(pady=20)

    # Image frame
    icon = ctk.CTkImage(dark_image=Image.open("Images/login.png"), size=(250, 200))
    disply_icon = ctk.CTkLabel(login_wind, image=icon, text='').pack(padx=20, pady=20)

    # Details Frame
    frame = ctk.CTkFrame(master=login_wind)
    frame.pack(pady=10, padx=40, fill='both', expand=True)

    # Enter username
    l2 = ctk.CTkLabel(frame, text="Enter username")
    l2.grid(row=0, column=0, padx=10, sticky="e")
    e2 = ctk.CTkEntry(frame)
    e2.grid(row=0, column=1, pady=12, padx=10)

    # Enter Account Pin
    l3 = ctk.CTkLabel(frame, text="Enter your Password:")
    l3.grid(row=1, column=0, padx=10, sticky="e")
    e3 = ctk.CTkEntry(frame, show="*")
    e3.grid(row=1, column=1, pady=12, padx=10)

    # Show and Hide Pin
    def show_and_hide():
        if e3.cget('show') == '*':
            e3.configure(show='')
        else:
            e3.configure(show='*')

    pin_checkbox = ctk.CTkCheckBox(frame, text="Show Password", fg_color='red', font=('verdana', 11),
                                   command=show_and_hide)
    pin_checkbox.grid(row=1, column=2, pady=12, padx=10, sticky="w")

    # Login Button
    b = ctk.CTkButton(frame, text="Submit",
                      command=lambda: check_log_in(login_wind, e2.get().strip(), e3.get().strip()))
    b.grid(row=2, column=2, pady=12, padx=10, sticky="e")

    # Forgot Password Button
    forgot_button = ctk.CTkButton(frame, text="Forgot Password", command=lambda: forgot_password(login_wind))
    forgot_button.grid(row=2, column=1, pady=12, padx=10)

    # Back Button
    b1 = ctk.CTkButton(frame, text="Back", command=lambda: home_return(login_wind))
    b1.grid(row=2, column=0, pady=12, padx=10, sticky="w")
    login_wind.bind("<Return>", lambda x: check_log_in(login_wind, e2.get().strip(), e3.get().strip()))


def logged_in_menu(username):
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    root_wind = ctk.CTkToplevel()
    root_wind.geometry("320x540")
    root_wind.title("CodeX  Banking  System")

    # Title/Heading
    l_title = ctk.CTkLabel(master=root_wind, text="CodeX  Banking System",
                           font=('Times New Roman Bold', 20))
    l_title.grid(row=0, column=0, columnspan=2, pady=20)

    # Image frame
    icon = ctk.CTkImage(dark_image=Image.open("Images/Welcome.png"), size=(240, 200))
    disply_icon = ctk.CTkLabel(root_wind, image=icon, text='').grid(row=1, column=0, columnspan=2, pady=20)

    label = ctk.CTkLabel(master=root_wind, text=f"Welcome Back " + username)
    label.grid(row=2, column=0, columnspan=2)

    # Deposit Button
    b2 = ctk.CTkButton(master=root_wind, text="Deposit",
                       command=lambda: deposit_amt(username))
    b2.grid(row=3, column=0, pady=12, padx=10, sticky='nsew')

    # View Balance Button
    b4 = ctk.CTkButton(master=root_wind, text="View Balance",
                       command=lambda: disp_bal(username))
    b4.grid(row=3, column=1, pady=12, padx=10, sticky='nsew')

    # Withdraw Button
    b3 = ctk.CTkButton(master=root_wind, text="Withdraw",
                       command=lambda: withdraw_amt(username))
    b3.grid(row=4, column=0, pady=12, padx=10, sticky='nsew')

    # View Transaction History Button
    b5 = ctk.CTkButton(master=root_wind, text="Transaction History",
                       command=lambda: disp_tr_hist(username))
    b5.grid(row=4, column=1, columnspan=2, pady=12, padx=10, sticky='nsew')

    # Log Out Button
    b6 = ctk.CTkButton(master=root_wind, text="Logout",
                       command=lambda: logout(root_wind))
    b6.grid(row=5, column=0, pady=12, padx=10, sticky='nsew')


# Make deposit window
def deposit_amt(username):
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    deposit_wind = ctk.CTkToplevel()
    deposit_wind.geometry("500x500")
    deposit_wind.title("Deposits")

    # Image frame
    icon = ctk.CTkImage(dark_image=Image.open("Images/dposit_money.png"), size=(200, 200))
    disply_icon = ctk.CTkLabel(deposit_wind, image=icon, text='').pack(padx=20, pady=20)

    l1 = ctk.CTkLabel(deposit_wind, text="Enter Amount to be deposited: ")
    e1 = ctk.CTkEntry(deposit_wind)
    l1.pack(pady=12, padx=10)
    e1.pack(pady=12, padx=10)

    # Deposit Button
    b = ctk.CTkButton(deposit_wind, text="Deposit", command=lambda: crdt_write(deposit_wind, e1.get(), username))
    b.pack(pady=12, padx=10)
    deposit_wind.bind("<Return>", lambda x: crdt_write(deposit_wind, e1.get(), username))

    # Cancel Button
    b1 = ctk.CTkButton(deposit_wind, text="Cancel", command=deposit_wind.destroy)
    b1.pack(pady=12, padx=10)


# Update Users Credit/Deposits
def crdt_write(master, amount, username):
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    user_data = load_user_data()

    try:
        # Try converting the input to a float
        amount = float(amount)

        # Check if the number is positive
        if amount > 0:
            initial_amount = float(user_data[username]['amount'])
            new_balance = initial_amount + float(amount)
            user_data[username]['amount'] = new_balance

            # Save updated user data to the file
            save_user_data(user_data)

            account = user_data[username]['account']

            frec = open(str(account) + "-rec.txt", 'a+')
            frec.write(
                str(strftime("[%Y-%m-%d][%H:%M:%S]", gmtime())) + "     +" + str(initial_amount) + "          " + str(
                    new_balance) + "\n")
            frec.close()
            CTkMessagebox(message="Deposit Successful!", icon="check")
            master.destroy()
            return
        else:
            CTkMessagebox(title="Error", message="Enter positive amount", icon="cancel")
            master.destroy()
            return
    except ValueError:
        CTkMessagebox(title="Error", message="Invalid Input!", icon="cancel")
        return


# Update Users Debits/Withdrawal
def debit_write(master, amount, username):
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    user_data = load_user_data()


    try:
        # Try converting the input to a float
        amount = float(amount)

        balance = float(user_data[username]['amount'])

        # Check if the number is positive
        if amount > 0:
            if amount > balance:
                CTkMessagebox(title="Error", message="Insufficient Funds!", icon="cancel")
            else:
                new_balance = balance - amount
                user_data[username]['amount'] = new_balance

                # Save updated user data to the file
                save_user_data(user_data)

                account = user_data[username]['account']

                frec = open(str(account) + "-rec.txt", 'a+')
                frec.write(str(strftime("[%Y-%m-%d][%H:%M:%S]", gmtime())) + "     -" + str(balance) + "          " +
                           str(new_balance) + "\n")
                frec.close()
                CTkMessagebox(message="Withdrawal Successful!", icon="check")
                master.destroy()
                return
        else:
            CTkMessagebox(title="Error", message="Enter positive amount", icon="cancel")
            master.destroy()
            return
    except ValueError:
        CTkMessagebox(title="Error", message="Invalid Input!", icon="cancel")
        return


# Make Deposit window
def withdraw_amt(username):
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    withdraw_wind = ctk.CTkToplevel()
    withdraw_wind.geometry("500x500")
    withdraw_wind.title("Withdrawals")

    # Image frame
    icon = ctk.CTkImage(dark_image=Image.open("Images/withdraw_money.png"), size=(200, 200))
    disply_icon = ctk.CTkLabel(withdraw_wind, image=icon, text='').pack(padx=20, pady=20)

    l1 = ctk.CTkLabel(withdraw_wind, text="Enter Amount to be withdrawn: ")
    e1 = ctk.CTkEntry(withdraw_wind)
    l1.pack(pady=12, padx=10)
    e1.pack(pady=12, padx=10)

    # Withdraw Button
    b = ctk.CTkButton(withdraw_wind, text="Withdraw", command=lambda: debit_write(withdraw_wind, e1.get(), username))
    b.pack(pady=12, padx=10)
    withdraw_wind.bind("<Return>", lambda x: debit_write(withdraw_wind, e1.get(), username))

    # Cancel Button
    b1 = ctk.CTkButton(withdraw_wind, text="Cancel", command=withdraw_wind.destroy)
    b1.pack(pady=12, padx=10)


# Display transaction history
def disp_tr_hist(username):
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    transaction_wind = ctk.CTkToplevel()
    transaction_wind.geometry("500x680")
    transaction_wind.title("Transaction History")

    user_data = load_user_data()

    # Title/Heading
    l_title = ctk.CTkLabel(master=transaction_wind, text="CodeX Banking System", font=('Times New Roman Bold', 20))
    l_title.pack(pady=20)

    # Image frame
    icon = ctk.CTkImage(dark_image=Image.open("Images/transaction-history.png"), size=(200, 200))
    disply_icon = ctk.CTkLabel(transaction_wind, image=icon, text='').pack(padx=20, pady=20)

    l1 = ctk.CTkLabel(transaction_wind, text="Your Transaction History:",  padx=100, pady=20, width=1000)
    l1.pack(side="top")

    scrollable_frame = ctk.CTkScrollableFrame(master=transaction_wind, width=200, height=200)
    scrollable_frame.pack(side="top", pady=20, padx=40, fill='both', expand=True)

    account = str(user_data[username]['account'])

    frec = open(account + "-rec.txt", 'r')
    for line in frec:
        l = ctk.CTkLabel(scrollable_frame, text=line, padx=100, pady=20, width=1000)
        l.pack(side="top")

    b = ctk.CTkButton(transaction_wind, text="Quit", command=transaction_wind.destroy)
    b.pack(pady=12, padx=10)
    frec.close()


def disp_bal(username):
    user_data = load_user_data()
    CTkMessagebox(title="Balance", message="Current Balance: R" + str(user_data[username]['amount']))


# Log out the user
def logout(master):
    CTkMessagebox(title="Log Out", message="You Have Been Successfully Logged Out!!", icon="check")
    master.destroy()
    Main_Menu()


def home_return(master):
    master.destroy()
    Main_Menu()


# Welcome/Main Window
def Main_Menu():
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")

    rootwn = ctk.CTkToplevel()
    rootwn.geometry("500x500")
    rootwn.title("CodeX Banking System")

    # Title
    l_title = ctk.CTkLabel(master=rootwn, text="CodeX   Banking   System", font=('Times New Roman Bold', 20))
    l_title.pack(pady=20)

    # Image frame
    icon = ctk.CTkImage(dark_image=Image.open("Images/X.png"), size=(200, 200))
    disply_icon = ctk.CTkLabel(rootwn, image=icon, text='').pack(padx=20, pady=20)

    # Sign up button
    b1 = ctk.CTkButton(rootwn, text="Sign Up", command=lambda: signup(rootwn))
    b1.pack(pady=12, padx=10)

    # Login Button
    b2 = ctk.CTkButton(rootwn, text="Login", command=lambda: log_in(rootwn))
    b2.pack(pady=12, padx=10)

    # Quite Button
    b6 = ctk.CTkButton(rootwn, text="Exit", command=rootwn.destroy)
    b6.pack(pady=12, padx=10)

    rootwn.mainloop()


Main_Menu()




    # If all validations pass, proceed with user registration logic
    # ...

# Example usage:
try:
    register_user("john_doe", 123456789, 100.00, "secure_password", "Favorite color?", "Blue")
except ValueError as e:
    print(f"Error: {e}")