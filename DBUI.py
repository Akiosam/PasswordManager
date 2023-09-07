import sqlite3
from tkinter import *

def create_table():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Create the users table if it doesn't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    # Check if any user exists in the database
    cursor.execute('SELECT COUNT(*) FROM users')
    count = cursor.fetchone()[0]

    if count > 0:
        # Disable the register button if a user already exists
        register_button.config(state=DISABLED)

    conn.commit()
    conn.close()

def register():
    username = username_entry.get()
    password = password_entry.get()

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Check if any user exists in the database
    cursor.execute('SELECT COUNT(*) FROM users')
    count = cursor.fetchone()[0]

    if count > 0:
        status_label.config(text="Registration not allowed. An account already exists.")
    else:
        # Insert the new user into the users table
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        status_label.config(text="Registration successful.")

    conn.commit()
    conn.close()

def search_user(username):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Search for the user in the database
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()

    conn.close()

    return result

def login():
    username = username_entry.get()
    password = password_entry.get()

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    # Check if the username and password match a user in the database
    cursor.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
    if cursor.fetchone() is not None:
        status_label.config(text="Login successful.")
        open_password_manager()
    else:
        status_label.config(text="Invalid username or password.")

    conn.close()



def open_password_manager():
    import sqlite3
    import tkinter as tk
    from tkinter import ttk
    import hashlib

    # Password database functions

    # Function to create a password database table
    def create_pass_db():
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()

        c.execute('''
                CREATE TABLE IF NOT EXISTS passwords 
                (id INTEGER PRIMARY KEY, 
                 website TEXT, 
                 username TEXT, 
                 password TEXT)
                ''')

        conn.commit()
        conn.close()

    # Function to add a password with encryption
    def add_password(website, username, password):
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()

        # Hash the password using SHA-256 before storing it
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        c.execute("INSERT INTO passwords VALUES (NULL, ?, ?, ?)",
                  (website, username, hashed_password))

        conn.commit()
        conn.close()

    # Function to retrieve passwords with decryption
    def get_passwords():
        conn = sqlite3.connect('passwords.db')
        c = conn.cursor()

        c.execute("SELECT * FROM passwords")
        rows = c.fetchall()

        conn.close()

        # Decrypt the passwords and return them
        passwords = []
        for row in rows:
            id, website, username, hashed_password = row
            # Decrypt the hashed password (not recommended for production use)
            decrypted_password = hashlib.sha256(hashed_password.encode()).hexdigest()
            passwords.append((id, website, username, decrypted_password))

        return passwords

    # Tkinter UI

    root = tk.Tk()
    root.title('Password Manager')
    root.config(padx=10, pady=10, bg='white')

    style = ttk.Style()
    style.configure('TLabel', font=('Arial', 12))
    style.configure('TButton', font=('Arial', 12))

    content = ttk.Frame(root, padding=(10, 10))
    content.grid()

    # Labels and entry widgets for website, username, and password

    website_lbl = ttk.Label(content, text="Website:")
    website_lbl.grid(row=0, column=0, padx=5, pady=5)

    website_entry = ttk.Entry(content)
    website_entry.grid(row=0, column=1, padx=5, pady=5)

    username_lbl = ttk.Label(content, text="Username:")
    username_lbl.grid(row=1, column=0, padx=5, pady=5)

    username_entry = ttk.Entry(content)
    username_entry.grid(row=1, column=1, padx=5, pady=5)

    password_lbl = ttk.Label(content, text="Password:")
    password_lbl.grid(row=2, column=0, padx=5, pady=5)

    password_entry = ttk.Entry(content)
    password_entry.grid(row=2, column=1, padx=5, pady=5)

    password_list = ttk.Treeview(content)
    password_list['columns'] = ('website', 'username', 'password')

    password_list.column('#0', width=0, stretch=tk.NO)
    password_list.column('website', anchor=tk.W, width=120)
    password_list.column('username', anchor=tk.W, width=120)
    password_list.column('password', anchor=tk.W, width=120)

    password_list.heading('website', text='Website', anchor=tk.W)
    password_list.heading('username', text='Username', anchor=tk.W)
    password_list.heading('password', text='Password', anchor=tk.W)

    password_list.grid(row=4, column=0, columnspan=4, padx=10, pady=10)

    # Scrollbars
    y_scrollbar = ttk.Scrollbar(content, orient=tk.VERTICAL, command=password_list.yview)
    x_scrollbar = ttk.Scrollbar(content, orient=tk.HORIZONTAL, command=password_list.xview)

    password_list.configure(yscroll=y_scrollbar.set, xscroll=x_scrollbar.set)
    y_scrollbar.grid(row=4, column=4, sticky='ns')
    x_scrollbar.grid(row=5, column=0, columnspan=4, sticky='ew')

    # Entry widget for search query
    search_entry = ttk.Entry(content)
    search_entry.grid(row=6, column=0, columnspan=4, padx=10, pady=10)

    def filter_passwords(event):
        search_query = search_entry.get().strip().lower()
        filtered_rows = [row for row in get_passwords() if search_query in row[1].lower() or search_query in row[2].lower()]

        password_list.delete(*password_list.get_children())

        for row in filtered_rows:
            # Ensure the column identifiers align with the values
            password_list.insert('', tk.END, values=(row[1], row[2], row[3]))

    # Bind the filter_passwords function to the <KeyRelease> event of the search entry
    search_entry.bind('<KeyRelease>', filter_passwords)

    # Button function to add a password

    def add_password_button():
        website = website_entry.get()
        username = username_entry.get()
        password = password_entry.get()

        # Validate user input
        if not website or not username or not password:
            raise ValueError("Website, username, and password are required fields.")

        add_password(website, username, password)

        populate_passwords()

    add_pass_btn = ttk.Button(content, text="Add Password", command=add_password_button)
    add_pass_btn.grid(row=3, column=0, padx=5, pady=5)

    # Define the remove_database function
    def remove_database():
        try:
            # Connect to the database
            conn = sqlite3.connect('passwords.db')
            c = conn.cursor()

            # Delete the entire database
            c.execute("DROP TABLE IF EXISTS passwords")

            # Commit the changes to the database
            conn.commit()

            # Close the database connection
            conn.close()

            # Clear the password_list (the visual list)
            password_list.delete(*password_list.get_children())

        except sqlite3.Error as e:
            print("SQLite Error:", e)

    # Bind the remove_database function to the Remove Database button
    remove_db_btn = ttk.Button(content, text="Remove Database", command=remove_database)
    remove_db_btn.grid(row=3, column=2, padx=5, pady=5)

    # Function to populate the password list

    def populate_passwords():
        password_list.delete(*password_list.get_children())
        rows = get_passwords()

        for row in rows:
            password_list.insert('', tk.END, values=(row[1], row[2], row[3]))

    # Startup

    create_pass_db()
    populate_passwords()
    root.mainloop()

# Check if an account exists before creating the Tkinter window
create_table()

# Create the Tkinter application window
window = Tk()
window.title("User Authentication")
window.geometry("300x200")

# Create the username label and entry field
username_label = Label(window, text="Username:")
username_label.pack()
username_entry = Entry(window)
username_entry.pack()

# Create the password label and entry field
password_label = Label(window, text="Password:")
password_label.pack()
password_entry = Entry(window, show="*")
password_entry.pack()

# Create the login button
login_button = Button(window, text="Login", command=login)
login_button.pack()

# Create the register button
register_button = Button(window, text="Register", command=register)
register_button.pack()

# Create the status label
status_label = Label(window, text="")
status_label.pack()

# Start the Tkinter event loop
window.mainloop()