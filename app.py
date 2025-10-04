from flask import Flask, render_template, request, redirect, url_for, session, flash, session, jsonify, send_from_directory
import sqlite3
import os
import re
from flask import current_app
import traceback
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import pytz


app = Flask(__name__)
app.secret_key = 'bf27ec4e5ca1d0f29432362bf41a2ba5'

# Path for file uploads (movies posters and trailers)
UPLOAD_FOLDER = 'static/photos/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Allowed extensions for uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    uid = session.get('userid')
    connection = sqlite3.connect('Trojan.db')
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    # Query to fetch most selected categories based on bookings
    cursor.execute("""
        SELECT c.categoryid, c.categoryname, COUNT(b.bookingid) as total_bookings, c.poster, c.categorystatus
        FROM categories c
        LEFT JOIN bookings b ON c.categoryid = b.categoryid
        GROUP BY c.categoryid
        ORDER BY total_bookings DESC
        LIMIT 3
    """)
    popular_categories = cursor.fetchall()
    connection.close()
    return render_template("home.html", uid=uid, popular_categories=popular_categories)

@app.route('/guidetouse')
def guidetouse():
    uid = session.get('userid')
    return render_template('guidetouse.html',uid=uid)

@app.route('/faq')
def faq():
    uid = session.get('userid')
    return render_template('faq.html', uid=uid)

#Route aboutus
@app.route('/about')
def about():
    # Connect to the database and fetch trainer data
    connection = sqlite3.connect('Trojan.db')
    cursor = connection.cursor()
    cursor.execute("SELECT trainername, occupation, photo, trainerid FROM trainers")
    trainers = cursor.fetchall()
    connection.close()
    uid = session.get('userid')
        
    # Pass the trainer data to the template
    return render_template('about.html', trainers=trainers, uid=uid)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Gets the directory of the current script
DATABASE_PATH = os.path.join(BASE_DIR, 'Trojan.db') 

#Route for searching wiht category name, package
@app.route('/search', methods=['GET'])
def search_items():
    uid = session.get('userid')
    search_term = request.args.get('query', '')
    print(f"Search term: {search_term}")  # Debugging to confirm the search term is being captured
    
    # Connect to the SQLite database
    try:
        conn = sqlite3.connect(DATABASE_PATH)        
        print("Connected to the database successfully.")
    except sqlite3.Error as e:
        print(f"Database connection failed: {e}")
        return jsonify({"error": "Database connection failed"}), 500
    
    # Create a cursor object using the connection
    cur = conn.cursor()
    try:
        # Modified SQL query to search by categoryname and packagename only
        query = """
            SELECT c.categoryname, p.packagename, p.description, p.price, p.photo
            FROM categories c
            LEFT JOIN packages p ON c.categoryid = p.categoryid
            WHERE c.categoryname LIKE ? OR p.packagename LIKE ?
        """
        cur.execute(query, ('%' + search_term + '%', '%' + search_term + '%'))        
        # Fetch all the results matching the search query
        rows = cur.fetchall()

        # Close the cursor and connection
        cur.close()
        conn.close()

        if rows:
            # If matching records are found, return the search results
            return render_template('search_results.html', search_term=search_term, rows=rows,uid=uid)
        else:
            flash("No results found matching your search.", "danger")
            return redirect(url_for('home'))

    except sqlite3.Error as e:
        print(f"SQL error: {e}")
        return jsonify({"error": "Query execution failed"}), 500    
    
@app.route('/package/<int:package_id>', methods=['GET'])
def package_detail(package_id):
    connection = sqlite3.connect('Trojan.db')
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM packages WHERE packagesid = ?", (package_id,))
    package = cursor.fetchone()
    connection.close()
    if package:
        return render_template('package_detail.html', package=package)
    else:
        return "Package not found", 404
    
@app.route('/category/<int:category_id>')
def category_detail(category_id):
    uid = session.get('userid')
    connection = sqlite3.connect("Trojan.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM categories WHERE categoryid = ?", (category_id,))
    category_row = cursor.fetchone()  # Fetches the specific category by ID
    connection.close()
    
    if category_row:
        # Convert Row object to dictionary for better handling
        category = dict(category_row)
        # Set default values for potentially None fields
        category['poster'] = category.get('poster') or ''  # Default to empty string if None
        category['video'] = category.get('video') or ''    # Default to empty string if None
        category['details'] = category.get('details') or 'No additional details provided.'        
        return render_template('category_detail.html', category=category, uid=uid)
    else:
        return "Category not found", 404

@app.route("/viewcontactform")
def viewcontactform():
    # Ensure the admin is logged in
    adminid = session.get('adminid')
    if not adminid:
        flash("You need to log in to access this page.", "danger")
        return redirect(url_for('login'))

    # Get the current page from the query parameters; default to page 1
    current_page = request.args.get('page', 1, type=int)
    contact_forms_per_page = 5  # Number of contact form submissions to display per page

    # Calculate the offset and limit for pagination
    offset = (current_page - 1) * contact_forms_per_page

    # Connect to the database
    connection = sqlite3.connect("Trojan.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    try:
        # Fetch total number of contact form submissions for pagination
        cursor.execute("SELECT COUNT(*) FROM contact_form")
        total_contact_forms = cursor.fetchone()[0]
        total_pages = (total_contact_forms + contact_forms_per_page - 1) // contact_forms_per_page  # Ceiling division

        # Fetch contact forms for the current page
        cursor.execute(
            "SELECT * FROM contact_form LIMIT ? OFFSET ?",
            (contact_forms_per_page, offset)
        )
        contact_forms = cursor.fetchall()

        # Calculate the pagination range (page numbers to display)
        start_page = max(1, current_page - 1)  
        end_page = min(total_pages, current_page + 1)  
        page_range = list(range(start_page, end_page + 1))

    except sqlite3.Error as e:
        # Handle database errors
        flash(f"An error occurred while retrieving contact forms: {e}", "danger")
        contact_forms = []
        total_pages = 1
        page_range = []
    finally:
        # Ensure the connection is closed
        connection.close()

    # Render the template with contact form data and pagination details
    return render_template(
        "managecontactform.html",
        contact_forms=contact_forms,
        current_page=current_page,
        total_pages=total_pages,
        page_range=page_range,
        adminid=adminid
    )

#Contact page that appear in user side in footer
@app.route('/contact')
def contact():
    uid = session.get('userid')
    return render_template('contact.html',uid=uid)

#Delete contact from that user upload by admin from admindashboard
@app.route('/delete_contactform/<int:contactid>', methods=['POST'])
def delete_contactform(contactid):
    connection = sqlite3.connect('Trojan.db')
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()    
    # Deleting the category from the categories table
    cursor.execute("DELETE FROM contact_form WHERE contactid=?", (contactid,))    
    connection.commit()
    connection.close()
    flash("Message delete successfully", "success")  
    # Redirect to the category management page (adjust the URL as needed)
    return redirect(url_for('viewcontactform'))

#User send contact form to admin throug contact us
@app.route("/submitcontactform", methods=["GET", "POST"])
def submitcontactform():
    uid = session.get('userid')
    # Ensure user is logged in
    if "userid" not in session or "useremail" not in session:
        flash("Please log in to contact us.", "warning")
        return redirect(url_for("login"))  # Redirect to login page if not logged in   
    
    # Fetch logged-in user's details from the session
    username = session.get("username")
    useremail = session.get("useremail")
    
    if request.method == "POST":
        reason = request.form.get("reason")
        subject = request.form.get("subject")
        description = request.form.get("description")
        
        # Validate form fields
        if not useremail:
            flash("User email is required.", "danger")
            return redirect(url_for("submitcontactform"))

        # Insert the form data into the database
        connection = sqlite3.connect("Trojan.db")
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO contact_form (userid, username, useremail, reason, subject, description)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (session["userid"], username, useremail, reason, subject, description))
        connection.commit()
        connection.close()

        # Flash a success message and redirect
        flash("Your contact form has been submitted successfully. Admin will reply within 24 Hours", "success")
        return redirect(url_for("submitcontactform"))
        
    # Render the contact form with pre-filled user data
    return render_template("contactform.html", username=username, useremail=useremail, uid=uid)        
        
#Route to Reply user's content from by admin
@app.route("/replycontactform/<int:contactid>", methods=["GET", "POST"])
def reply_contactform(contactid):
    # Ensure admin is logged in
    if "adminid" not in session:
        flash("Please log in as an admin to reply.", "danger")
        return redirect(url_for("admin_login"))

    if request.method == "POST":
        reply_message = request.form.get("reply_message")

        # Validate the reply message
        if not reply_message:
            flash("Reply message cannot be empty.", "warning")
            return redirect(url_for("reply_contactform", contactid=contactid))
        
        # Get the current time in Myanmar timezone
        myanmar_tz = pytz.timezone("Asia/Yangon")
        replay_date = datetime.now(myanmar_tz).strftime("%Y-%m-%d %H:%M:%S")

        # Save the reply to the database
        connection = sqlite3.connect("Trojan.db")
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO contact_replies (contactid, adminid, reply_message, reply_date)
            VALUES (?, ?, ?, ?)
        """, (contactid, session["adminid"], reply_message, replay_date))
        connection.commit()
        connection.close()
        
        flash("Reply sent successfully.", "success")
        return redirect(url_for("viewcontactform"))

    return render_template("reply_contactform.html", contactid=contactid)

#Login Page for user
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'attempt_count' not in session:
        session['attempt_count'] = 0

    if request.method == 'POST':
        email_or_name = request.form['email_or_name']
        password = request.form['password']

        conn = sqlite3.connect('Trojan.db')
        c = conn.cursor()
        
        c.execute("SELECT * FROM users WHERE useremail = ?", (email_or_name,))
        user = c.fetchone()
        conn.close()

        if user and user[3] == password:
            session['userid'] = user[0]
            session['username'] = user[1]
            session['useremail'] = user[2]
            session['attempt_count'] = 0  # Reset attempt counter            
            return redirect(url_for('home'))
        else:
            session['attempt_count'] += 1
            flash('Invalid credentials, please try again.', 'error')

            if session['attempt_count'] == 2:
                flash('Forgot your password? Click here to reset it.', 'info')                
    return render_template('login.html')

#password, email and username voilation in register
def validate_password(password):
    """Validates password strength."""
    if (len(password) < 8 or
        not re.search(r'[A-Z]', password) or
        not re.search(r'[a-z]', password) or
        not re.search(r'[0-9]', password) or
        not re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):
        return False
    return True

def is_email_used(email):
    """Checks if the email has been used before."""
    conn = sqlite3.connect('Trojan.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE useremail = ?", (email,))
    result = c.fetchone()
    conn.close()
    return result is not None

def is_username_used(username):
    """Checks if the username has been used before."""
    conn = sqlite3.connect('Trojan.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    return result is not None

# Route for new user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get the form data
        username = request.form['username']
        email = request.form['useremail']
        password = request.form['userpassword']
        confirm_password = request.form['cpassword']

        # Validate email format
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('Invalid email format.', 'error')
            return redirect(url_for('register'))

        # Check if passwords match
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('register'))

        # Validate password strength
        if not validate_password(password):
            flash('Password must be at least 8 characters long, include uppercase, lowercase, a number, and a special character.', 'error')
            return redirect(url_for('register'))

        # Check if email has been used before
        if is_email_used(email):
            flash('This email has already been used. Please choose a different one.', 'error')
            return redirect(url_for('register'))

        # Check if username has been used before
        if is_username_used(username):
            flash('This username is already taken. Please choose a different one.', 'error')
            return redirect(url_for('register'))

        # Get the current time in Myanmar Time
        myanmar_tz = pytz.timezone('Asia/Yangon')
        registration_date = datetime.now(myanmar_tz).strftime('%Y-%m-%d %H:%M:%S')

        # Connect to the SQLite database
        conn = sqlite3.connect('Trojan.db')
        c = conn.cursor()
        try:
            # Insert user into the database with registration_date
            c.execute("INSERT INTO users (username, useremail, userpassword, registration_date) VALUES (?, ?, ?, ?)", 
                      (username, email, password, registration_date))
            conn.commit()
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Registration failed. Please try again.', 'error')
        finally:
            conn.close()
    # Render the registration page
    return render_template('register.html')

#Route for user profile
@app.route('/user/profile', methods=['GET', 'POST'])
def user_profile():
    # Ensure the user is logged in
    uid = session.get('userid')
    if 'userid' not in session:
        flash("Please log in to view your profile.", 'error')
        return redirect(url_for('login'))
    
    userid = session['userid']
    conn = sqlite3.connect('Trojan.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    try:
        # Fetch user info
        c.execute("SELECT username, useremail, userprofile_photo FROM users WHERE userid = ?", (userid,))
        user = c.fetchone()
        
        # Fetch user bookings with invoice paths
        c.execute("SELECT bookingid, total_price, invoice_path FROM bookings WHERE userid = ?", (userid,))
        bookings = c.fetchall()

        # Fetch replies to the user's contact forms
        c.execute("""
            SELECT cf.subject, cr.reply_message, cr.reply_date
            FROM contact_form cf
            JOIN contact_replies cr ON cf.contactid = cr.contactid
            WHERE cf.userid = ?
        """, (userid,))
        replies = c.fetchall()

        # Handling profile photo upload
        if request.method == 'POST':
            # Check for uploaded file
            if 'userprofile_photo' not in request.files:
                flash("No file part", 'error')
                return redirect(request.url)
            file = request.files['userprofile_photo']            
            if file and allowed_file(file.filename):
                # Secure the filename and save the file
                filename = secure_filename(file.filename)
                upload_folder = current_app.config['UPLOAD_FOLDER']
                file_path = os.path.join(upload_folder, filename)
                file.save(file_path)

                # Update the user's profile photo in the database
                c.execute("UPDATE users SET userprofile_photo = ? WHERE userid = ?", (filename, userid))
                conn.commit()
                flash("Profile photo updated successfully.", 'success')
                return redirect(url_for('user_profile'))
            else:
                flash("Invalid file format. Please upload an image.", 'error')
    finally:
        conn.close()
    return render_template('user_profile.html', user=user, bookings=bookings, replies=replies, uid=uid)

#Route for user updating password
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'userid' not in session:
        return redirect(url_for('login'))    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        userid = session['userid']        
        conn = sqlite3.connect('Trojan.db')
        c = conn.cursor()

        # Query to check if the current password matches
        c.execute("SELECT * FROM users WHERE userid=? AND userpassword=?", (userid, current_password))
        user = c.fetchone()        
        if user:
            # Update the password if correct
            c.execute("UPDATE users SET userpassword=? WHERE userid=?", (new_password, userid))
            conn.commit()
            conn.close()
            return redirect(url_for('user_profile'))
        else:
            flash("Current password is incorrect!", 'error')            
    return render_template('change_password.html')

@app.route('/userdeletebookings/<int:bookingid>', methods=['POST'])
def userdeletebookings(bookingid):
    connection = sqlite3.connect('Trojan.db')
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    # Get the booking details, including the booking date
    cursor.execute("SELECT booking_date FROM bookings WHERE bookingid=?", (bookingid,))
    booking = cursor.fetchone()    
    if booking:
        try:
            # Parse the booking date from the database
            booking_date = datetime.strptime(booking['booking_date'], '%Y-%m-%d %H:%M:%S.%f')
            # Calculate the time difference between now and the booking date
            time_difference = datetime.now() - booking_date
            # Check if the booking is older than one hour
            if time_difference > timedelta(hours=3):
                flash("You cannot delete a booking that was made more than three hour ago.")
                connection.close()
                return redirect(url_for('user_profile'))
            # If the booking is less than one hour old, proceed to delete
            cursor.execute("DELETE FROM bookings WHERE bookingid=?", (bookingid,))
            connection.commit()
            flash("Booking deleted successfully.")
        except ValueError as e:
            flash(f"Error parsing booking date: {str(e)}")
    else:
        flash("Booking not found.")
    connection.close()
    return redirect(url_for('user_profile'))

#Route for user password recovery
@app.route('/user/recover_password', methods=['GET', 'POST'])
def user_password_recovery():
    if request.method == 'POST':
        useremail = request.form['useremail']
        security_key = request.form['security_key']        
        conn = sqlite3.connect('Trojan.db')
        c = conn.cursor()        
        # Check if the email exists in the users database
        c.execute("SELECT * FROM users WHERE useremail=?", (useremail,))
        user = c.fetchone()
        if user:
            # Debugging: Print to check security_key comparison
            print("User security key in DB:", user[5])  # Correct index for security_key
            print("Entered security key:", security_key)
            
            # Check if the entered security key matches the one in the database
            if user[5] == security_key:  # user[5] is now the correct index for security_key
                # Get the new password from the form and update the user's password
                new_password = request.form['new_password']
                c.execute("UPDATE users SET userpassword=? WHERE useremail=?", (new_password, useremail))
                conn.commit()
                conn.close()
                
                flash("Password reset successful! You can now log in with your new password.")
                return redirect(url_for('login'))  # Redirect to login after password recovery
            else:                
                flash("Invalid security key! Please try again.")
        else:           
            flash("Email not found! Please check and try again.")    
    return render_template('user_password_recovery.html')

#Route for user to set security key for password security
@app.route('/user/set_security_key', methods=['GET', 'POST'])
def set_security_key():
    if request.method == 'POST':
        try:
            # Ensure the required form fields are present
            useremail = request.form['useremail']
            current_password = request.form['current_password']
            new_security_key = request.form['new_security_key']
        except KeyError as e:
            flash(f"Missing form field: {e}")
            return render_template('set_security_key.html')
        
        conn = sqlite3.connect('Trojan.db')
        c = conn.cursor()

        # Check if the email exists in the users database
        c.execute("SELECT * FROM users WHERE useremail=?", (useremail,))
        user = c.fetchone()

        if user:
            # Verify current password
            if user[3] == current_password:  # Assuming user[3] is the userpassword column
                # Update the security key
                c.execute("UPDATE users SET security_key=? WHERE useremail=?", (new_security_key, useremail))
                conn.commit()
                conn.close()
                
                flash("Security key updated successfully!")
                return redirect(url_for('login'))  # Redirect to login or any other page after updating
                
            else:
                conn.close()
                flash("Incorrect password. Please try again.")
        else:
            conn.close()
            flash("Email not found. Please try again.")
    
    return render_template('set_security_key.html')

#Admin Login 
@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if 'attempt_count' not in session:
        session['attempt_count'] = 0

    if request.method == 'POST':
        email_or_name = request.form['email_or_name']
        password = request.form['password']

        # Connect to the SQLite database
        conn = sqlite3.connect('Trojan.db')
        c = conn.cursor()

        # Try to find the admin in the 'admins' table by email
        c.execute("SELECT * FROM admins WHERE adminemail = ?", (email_or_name,))
        admin = c.fetchone()
        conn.close()

        # If an admin is found and the password matches
        if admin and admin[3] == password:  
            session['adminid'] = admin[0]  
            session['adminname'] = admin[1]  
            session['adminemail'] = admin[2]  
            session['attempt_count'] = 0             
            return redirect(url_for('admindashboard'))
        
        # If no match, increment the attempt counter
        session['attempt_count'] += 1
        flash('Invalid credentials, please try again.', 'error')

        # If 2 failed attempts, show a password reset message
        if session['attempt_count'] == 2:
            flash('Forgot your password? Click here to reset it.', 'info')
    return render_template('admin_login.html')

#Admin Profile
@app.route('/admin/profile', methods=['GET', 'POST'])
def admin_profile():
    if 'adminid' not in session:
        return redirect(url_for('admin_login'))
    adminid = session.get('adminid')
    
    # Connect to the database
    conn = sqlite3.connect('Trojan.db')
    c = conn.cursor()
    
    # Fetch the admin details
    c.execute("SELECT adminname, adminemail, adminprofile_photo FROM admins WHERE adminid = ?", (adminid,))
    admin = c.fetchone()
    
    if request.method == 'POST':
        # Handle profile photo upload
        if 'adminprofile_photo' in request.files:
            file = request.files['adminprofile_photo']
            if file.filename != '':
                # Secure the file name and save it to the upload folder
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                # Update the profile photo path in the database
                c.execute("UPDATE admins SET adminprofile_photo = ? WHERE adminid = ?", (filename, adminid))
                conn.commit()                
                return redirect(url_for('admin_profile'))    
    # Close the connection
    conn.close()    
    return render_template('admin_profile.html', admin=admin,adminid=adminid)

#Admin update password
@app.route('/admin_change_password', methods=['GET', 'POST'])
def admin_change_password():
    if 'adminid' not in session:
        return redirect(url_for('login'))    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        adminid = session['adminid']        
        conn = sqlite3.connect('Trojan.db')
        c = conn.cursor()

        # Query to check if the current password matches
        c.execute("SELECT * FROM admins WHERE adminid=? AND adminpassword=?", (adminid, current_password))
        user = c.fetchone()        
        if user:
            # Update the password if correct
            c.execute("UPDATE admins SET adminpassword=? WHERE adminid=?", (new_password, adminid))
            conn.commit()
            conn.close()
            return redirect(url_for('admin_profile'))
        else:
            flash ("Current password is incorrect!", 'error')    
    return render_template('admin_change_password.html')

#Admin password recovery with security key and adminemail
@app.route('/admin/recover_password', methods=['GET', 'POST'])
def admin_password_recovery():
    if request.method == 'POST':
        adminemail = request.form['adminemail']
        security_key = request.form['security_key']
        
        conn = sqlite3.connect('Trojan.db')
        c = conn.cursor()

        # Check if the email exists in the admins database
        c.execute("SELECT * FROM admins WHERE adminemail=?", (adminemail,))
        admin = c.fetchone()

        if admin:
            # Debugging: Print to check security_key comparison
            print("Admin security key in DB:", admin[5])  # Correct index for security_key
            print("Entered security key:", security_key)
            
            # Check if the entered security key matches the one in the database
            if admin[5] == security_key:  # admin[5] is the correct index for security_key
                # Get the new password from the form and update the admin's password
                new_password = request.form['new_password']
                c.execute("UPDATE admins SET adminpassword=? WHERE adminemail=?", (new_password, adminemail))
                conn.commit()
                conn.close()
                
                flash("Password reset successful! You can now log in with your new password.")
                return redirect(url_for('admin_login'))  # Redirect to login after password recovery
            else:
                conn.close()
                flash("Invalid security key! Please try again.")
        else:
            conn.close()
            flash("Email not found! Please check and try again.")
    
    return render_template('admin_password_recovery.html')
   
#Route to set security key for password revocery in admin    
@app.route('/admin/set_security_key', methods=['GET', 'POST'])
def set_admin_security_key():
    if request.method == 'POST':
        adminemail = request.form['adminemail']
        current_password = request.form['current_password']
        new_security_key = request.form['new_security_key']
        
        conn = sqlite3.connect('Trojan.db')
        c = conn.cursor()

        # Check if the email exists in the admins database
        c.execute("SELECT * FROM admins WHERE adminemail=?", (adminemail,))
        admin = c.fetchone()

        if admin:
            # Verify current password
            if admin[3] == current_password:  # Assuming admin[3] is the adminpassword column
                # Update the security key
                c.execute("UPDATE admins SET security_key=? WHERE adminemail=?", (new_security_key, adminemail))
                conn.commit()
                conn.close()
                
                flash("Security key updated successfully!")
                return redirect(url_for('admin_login'))  # Redirect to login or any other page after updating
                
            else:
                conn.close()
                flash("Incorrect password. Please try again.")
        else:
            conn.close()
            flash("Email not found. Please try again.")
    
    return render_template('set_admin_security_key.html')   

@app.route("/admin/dashboard")
def admindashboard():
    if 'adminid' in session:
        adminname = session.get('adminname')
        adminid = session.get('adminid')

        connection = sqlite3.connect('Trojan.db')
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()

        try:
            # Total counts for dashboard cards
            total_users = cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            total_categories = cursor.execute("SELECT COUNT(*) FROM categories").fetchone()[0]
            total_bookings = cursor.execute("SELECT COUNT(*) FROM bookings").fetchone()[0]

            # Pagination setup
            page = request.args.get('page', 1, type=int)  # Current page from query string
            per_page = 5  # Rows per page
            offset = (page - 1) * per_page  # Calculate offset

            # Ensure offset doesn't exceed total records
            if offset >= total_bookings and page != 1:
                flash("Invalid page number.", "warning")
                return redirect(url_for('admindashboard', page=1))

            # Fetch bookings with LIMIT and OFFSET
            bookings = cursor.execute("""
                SELECT 
                    users.username AS username, 
                    categories.categoryname AS categoryname, 
                    bookings.packagename AS packagename, 
                    bookings.booking_date AS booking_date, 
                    bookings.status AS status 
                FROM bookings
                JOIN users ON bookings.userid = users.userid
                JOIN categories ON bookings.categoryid = categories.categoryid
                LIMIT ? OFFSET ?
            """, (per_page, offset)).fetchall()

            # Calculate total pages for pagination
            total_pages = (total_bookings + per_page - 1) // per_page

            # Calculate pagination range
            start_page = max(1, page - 1)
            end_page = min(total_pages, page + 1)
            page_range = list(range(start_page, end_page + 1))

        except Exception as e:
            print("Error:", e)  # Debug information
            bookings, total_pages, page, page_range = [], 0, 1, []

        finally:
            connection.close()

        return render_template(
            "admindashboard.html",
            adminname=adminname,
            adminid=adminid,
            total_users=total_users,
            total_categories=total_categories,
            total_bookings=total_bookings,
            bookings=bookings,
            current_page=page,
            total_pages=total_pages,
            page_range=page_range
        )   
    return redirect(url_for('admin_login'))

@app.route("/viewusers")
def viewusers():
    adminid = session.get('adminid')
    page = request.args.get('page', 1, type=int)  # Default page is 1
    rows_per_page = 5  # Number of rows to display per page
    offset = (page - 1) * rows_per_page  # Calculate the offset

    connection = sqlite3.connect("Trojan.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    
    # Fetch total number of users for pagination calculation
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]
    
    # Fetch limited rows for the current page, including registration_date and security_key
    cursor.execute(
        """
        SELECT userid, username, useremail, userpassword, 
               security_key, registration_date, userprofile_photo 
        FROM users 
        LIMIT ? OFFSET ?
        """, 
        (rows_per_page, offset)
    )
    users = cursor.fetchall()
    connection.close()
    
    total_pages = (total_users + rows_per_page - 1) // rows_per_page  # Calculate total pages

    # Calculate pagination range
    start_page = max(1, page - 1)
    end_page = min(total_pages, page + 1)
    page_range = list(range(start_page, end_page + 1))

    return render_template(
        "manageusers.html", 
        users=users, 
        adminid=adminid, 
        current_page=page, 
        total_pages=total_pages,
        page_range=page_range
    )

#Delete User route in admin side
@app.route("/deleteuser/<int:userid>", methods=['GET', 'POST'])
def deleteuser(userid):
    connection = sqlite3.connect("Trojan.db")
    connection.row_factory = sqlite3.Row  # Ensure rows are returned as dict-like objects
    cursor = connection.cursor()
    if request.method == 'POST':
        # If the form is submitted, delete the user
        cursor.execute("DELETE FROM users WHERE userid = ?", (userid,))
        connection.commit()
        connection.close()
        flash('User deleted successfully!', 'danger')
        return redirect(url_for('viewusers'))
    else:
        # Fetch the user details for confirmation
        cursor.execute("SELECT * FROM users WHERE userid = ?", (userid,))
        user = cursor.fetchone()
        connection.close()
         
        if user:
            # Pass the user to the template to display confirmation
            return render_template('deleteuser.html', user=user)
        else:
            # If the user is not found, display an error
            flash('User not found.', 'error')   
            return redirect(url_for('viewusers'))
        
#Updating usr route in adminside  
@app.route("/edituser/<int:userid>", methods=['GET', 'POST'])
def edituser(userid):
    connection = sqlite3.connect("Trojan.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    if request.method == 'POST':
        username = request.form['username']
        useremail = request.form['useremail']
        userpassword = request.form['userpassword']

        cursor.execute("UPDATE users SET username = ?, useremail = ?, userpassword = ? WHERE userid = ?", 
                       (username, useremail, userpassword, userid))
        connection.commit()
        connection.close()
        flash('User updated successfully!', 'success')
        return redirect(url_for('viewusers'))
    else:
        cursor.execute("SELECT * FROM users WHERE userid = ?", (userid,))
        user = cursor.fetchone()
        connection.close()
        if user:
            return render_template('edituser.html', user=user)
        else:
            flash('User not found.', 'error')
            return redirect(url_for('viewusers'))

#Adding new user in admin route        
@app.route("/adduser", methods=['GET', 'POST'])
def adduser():
    if request.method == 'POST':
        username = request.form.get('username')
        useremail = request.form.get('useremail')
        userpassword = request.form.get('userpassword')
        myanmar_tz = pytz.timezone('Asia/Yangon')
        registration_date = datetime.now(myanmar_tz).strftime('%Y-%m-%d %H:%M:%S')

        # Check if all fields are filled
        if not username or not useremail or not userpassword:
            flash("All fields are required.", "error")
            return redirect(url_for('adduser'))

         # Add the new user to the database
        connection = sqlite3.connect("Trojan.db")
        cursor = connection.cursor()
        try:
            cursor.execute("INSERT INTO users (username, useremail, userpassword,registration_date) VALUES (?, ?, ?,?)", 
                           (username, useremail, userpassword,registration_date))
            connection.commit()
            flash("User added successfully!", "success")
            return redirect(url_for('viewusers'))
        except sqlite3.Error as e:
            flash("Error adding user: " + str(e), "error")
            return redirect(url_for('adduser'))
        finally:
            connection.close()
                        
    # If GET request, just render the form
    return render_template('adduser.html')

#categories that show in user side in navagation bar
@app.route("/categories")
def categories():
    uid = session.get('userid')  
    connection = sqlite3.connect("Trojan.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM categories")
    categories = cursor.fetchall()  # Fetches all rows from the Movie table    
    connection.close()
    return render_template("viewcategories.html", categories=categories,uid=uid)

@app.route("/viewcategories")
def viewcategories():
    adminid = session.get('adminid')
    
    # Define the number of categories per page
    per_page = 1 # Set the fixed number of categories per page
    
    # Get the current page number from the URL, default is 1
    current_page = request.args.get('page', 1, type=int)
    
    # Calculate the offset for the SQL query
    offset = (current_page - 1) * per_page
    
    # Connect to the database
    connection = sqlite3.connect("Trojan.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    
    try:
        # Query to get the total number of categories
        cursor.execute("SELECT COUNT(*) FROM categories")
        total_categories = cursor.fetchone()[0]
        
        # Calculate total pages
        total_pages = (total_categories + per_page - 1) // per_page  # Ceiling division
        
        # Query to fetch categories for the current page
        cursor.execute("SELECT * FROM categories LIMIT ? OFFSET ?", (per_page, offset))
        categories = cursor.fetchall()
        
        # Calculate the pagination range (e.g., showing 3 pages: prev, current, next)
        start_page = max(1, current_page - 1)
        end_page = min(total_pages, current_page + 1)
        page_range = list(range(start_page, end_page + 1))
        
    except sqlite3.Error as e:
        flash(f"An error occurred while retrieving categories: {e}", "danger")
        categories = []
        total_pages = 1
        page_range = []
    finally:
        # Ensure the connection is closed
        connection.close()
    
    # Render the template with categories data and pagination details
    return render_template(
        "managecategories.html",
        categories=categories,
        adminid=adminid,
        current_page=current_page,
        total_pages=total_pages,
        page_range=page_range
    )

#add new category
@app.route('/addcategory', methods=['GET', 'POST'])
def addcategory():
    if request.method == 'POST':
        categoryname = request.form['categoryname']
        categorystatus = request.form['categorystatus']
        
        # Handle file uploads
        poster = request.files['poster']
        video = request.files['video']
        
        # Save files if they exist
        poster_filename = poster.filename if poster else ''
        video_filename = video.filename if video else ''
        
        if poster_filename:
            poster.save('static/photos/' + poster_filename)
        if video_filename:
            video.save('static/photos/' + video_filename)

        # Insert category data into the database
        connection = sqlite3.connect('Trojan.db')
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO categories (categoryname, categorystatus, poster, video)
            VALUES (?, ?, ?, ?)
        """, (categoryname, categorystatus, poster_filename, video_filename))
        
        connection.commit()
        connection.close()
        
        flash('Category added successfully!', 'success')
        return redirect(url_for('viewcategories'))    
    return render_template('addcategories.html')

@app.route('/editcategory/<int:categoryid>', methods=['GET', 'POST'])
def editcategory(categoryid):
    connection = sqlite3.connect('Trojan.db')
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    if request.method == 'POST':
        categoryname = request.form['categoryname']
        categorystatus = request.form['categorystatus']
        
        # Handle file uploads
        poster = request.files['poster']
        video = request.files['video']

        # Fetch current poster and video filenames
        cursor.execute("""
            SELECT poster, video FROM categories WHERE categoryid = ?
        """, (categoryid,))
        current_files = cursor.fetchone()
        current_poster = current_files['poster'] if current_files else ''
        current_video = current_files['video'] if current_files else ''

        # If no new file is uploaded, keep the existing filename
        poster_filename = poster.filename if poster and poster.filename else current_poster
        video_filename = video.filename if video and video.filename else current_video
        
        # Save new files if uploaded
        if poster and poster.filename:
            poster.save('static/photos/' + poster_filename)
        if video and video.filename:
            video.save('static/photos/' + video_filename)

        # Update the categories table with the new values
        cursor.execute("""
            UPDATE categories 
            SET categoryname=?, categorystatus=?, poster=?, video=? 
            WHERE categoryid=?
        """, (categoryname, categorystatus, poster_filename, video_filename, categoryid))
        connection.commit()
        connection.close()

        # Flash a success message
        flash('Category updated successfully!', 'success')
        return redirect(url_for('viewcategories'))

    # Fetch the category details
    cursor.execute("""
        SELECT categoryid, categoryname, categorystatus, poster, video
        FROM categories
        WHERE categoryid = ?
    """, (categoryid,))

    categorydetail = cursor.fetchone()
    connection.close()

    if categorydetail:
        # Convert sqlite3.Row to a regular dictionary
        category_dict = dict(categorydetail)
        return render_template('editcategories.html', category=category_dict)
    else:
        flash('Category not found!', 'danger')
        return "Category not found", 404

#Delete category
@app.route('/delete_category/<int:categoryid>', methods=['POST'])
def delete_category(categoryid):
    connection = sqlite3.connect('Trojan.db')
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()    

    # Delete the category
    cursor.execute("DELETE FROM categories WHERE categoryid=?", (categoryid,))
    connection.commit()
    connection.close()

    # Flash success message
    flash("Category deleted successfully!", "success")

    # Redirect to the category management page
    return redirect(url_for('viewcategories'))

#View package that show packages in navagation bar
@app.route("/packages")
def packages():
    uid = session.get('userid')
    connection = sqlite3.connect("Trojan.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM packages")
    rows = cursor.fetchall()
    connection.close()

    # Convert each row to a dictionary
    packages = [dict(row) for row in rows]

    return render_template("viewpackages.html", packages=packages, uid=uid)

#view package for manage packages in admin side
@app.route("/viewpackages")
def viewpackages():
    adminid = session.get('adminid')
    page = request.args.get('page', 1, type=int)
    per_page = 5
    offset = (page - 1) * per_page

    connection = sqlite3.connect("Trojan.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    # Fetch packages
    cursor.execute("SELECT * FROM packages LIMIT ? OFFSET ?", (per_page, offset))
    packages = cursor.fetchall()

    # Total packages for pagination
    cursor.execute("SELECT COUNT(*) FROM packages")
    total_packages = cursor.fetchone()[0]
    total_pages = (total_packages // per_page) + (1 if total_packages % per_page > 0 else 0)

    # Calculate pagination range
    start_page = max(1, page - 1)
    end_page = min(total_pages, page + 1)
    page_range = list(range(start_page, end_page + 1))

    connection.close()

    return render_template(
        "managepackages.html",
        packages=packages,
        adminid=adminid,
        current_page=page,
        total_pages=total_pages,
        page_range=page_range
    )

@app.route('/addpackage', methods=['GET', 'POST'])
def addpackage():
    if request.method == 'POST':
        # Get form data
        categoryid = request.form['categoryid']
        packagename = request.form['packagename']
        description = request.form['description']
        price = request.form['price']
        group_size = request.form['group_size']  # New field for Group Size
        
        # Handle file upload for the package photo
        photo = request.files['photo']
        photo_filename = photo.filename if photo else ''
        
        # Save the photo if it exists
        if photo_filename:
            photo.save('static/photos/' + photo_filename)

        # Insert package data into the database
        connection = sqlite3.connect('Trojan.db')
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO packages (categoryid, packagename, description, price, photo, group_size)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (categoryid, packagename, description, price, photo_filename, group_size))
        
        connection.commit()
        connection.close()
        
        # Redirect to view the packages after the insert
        flash('New package added successfully!', 'success')
        return redirect(url_for('viewpackages'))    
    return render_template('addpackages.html')

@app.route('/editpackages/<int:packagesid>', methods=['GET', 'POST'])
def editpackages(packagesid):
    # Establish database connection
    connection = sqlite3.connect('Trojan.db')
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    if request.method == 'POST':
        # Get form data
        packagename = request.form['packagename']
        categoryid = request.form['categoryid']
        description = request.form['description']
        price = request.form['price']
        group_size = request.form['group_size']
        poster = request.files['photo']

        # Handle the uploaded photo
        poster_filename = poster.filename if poster and poster.filename else None
        if poster_filename:
            poster.save(f'static/photos/{poster_filename}')
            # Update with the new photo
            cursor.execute("""
                UPDATE packages
                SET packagename = ?, categoryid = ?, photo = ?, description = ?, price = ?, group_size = ?
                WHERE packagesid = ?
            """, (packagename, categoryid, poster_filename, description, price, group_size, packagesid))
        else:
            # Keep the existing photo
            cursor.execute("""
                UPDATE packages
                SET packagename = ?, categoryid = ?, description = ?, price = ?, group_size = ?
                WHERE packagesid = ?
            """, (packagename, categoryid, description, price, group_size, packagesid))

        # Commit the transaction and close the connection
        connection.commit()
        connection.close()
        flash('Packages updated successfully!', 'success')
        return redirect(url_for('viewpackages'))

    # Fetch the package details
    cursor.execute("""
        SELECT packagesid, packagename, description, photo, categoryid, price, group_size
        FROM packages
        WHERE packagesid = ?
    """, (packagesid,))
    packagesdetail = cursor.fetchone()

    # Close the connection
    connection.close()

    if packagesdetail:
        # Convert sqlite3.Row to a regular dictionary
        package_dict = dict(packagesdetail)
        return render_template('editpackages.html', package=package_dict)
    else:
        return "Package not found", 404

@app.route('/delete_package/<int:packagesid>', methods=['POST'], endpoint='delete_package')
def delete_packagesid(packagesid):
    connection = sqlite3.connect('Trojan.db')
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()    
    # Deleting the category from the packages table
    cursor.execute("DELETE FROM packages WHERE packagesid=?", (packagesid,))    
    connection.commit()
    connection.close()    
    flash("Package deleted successfully!", "success")
    # Redirect to the package management page    
    return redirect(url_for('viewpackages'))

@app.route("/package_types")
def package_types():
    connection = sqlite3.connect("Trojan.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM package_types")
    package_types = cursor.fetchall()  # Fetches all rows from the packages table
    connection.close()
    return render_template("viewpackage_types.html", package_types=package_types)

@app.route("/viewpackage_types")
def viewpackage_types():
    adminid = session.get('adminid')
    page = request.args.get('page', 1, type=int)  # Get the page number from the URL (default to 1)
    per_page = 10  # Number of package types per page
    offset = (page - 1) * per_page  # Calculate the offset for the query

    connection = sqlite3.connect("Trojan.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    # Fetch the package types for the current page
    cursor.execute("SELECT * FROM package_types LIMIT ? OFFSET ?", (per_page, offset))
    package_types = cursor.fetchall()

    # Get the total number of package types for pagination
    cursor.execute("SELECT COUNT(*) FROM package_types")
    total_package_types = cursor.fetchone()[0]
    total_pages = (total_package_types // per_page) + (1 if total_package_types % per_page > 0 else 0)

    # Calculate the pagination range (e.g., current page ± 1)
    start_page = max(1, page - 1)
    end_page = min(total_pages, page + 1)
    page_range = list(range(start_page, end_page + 1))

    connection.close()
    
    return render_template(
        "managepackage_types.html", 
        package_types=package_types, 
        adminid=adminid, 
        current_page=page, 
        total_pages=total_pages, 
        page_range=page_range
    )

@app.route('/addpackage_type', methods=['GET', 'POST'])
def addpackage_type():
    if request.method == 'POST':
        # Get form data
        packagetypeid = request.form['packagetypeid']
        packagetypename = request.form['packagetypename']
        categoryid = request.form['categoryid']
        price = request.form['price']
        
        # Insert package type data into the database
        connection = sqlite3.connect('Trojan.db')
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO package_types (packagetypeid, packagetypename, price, categoryid)
            VALUES (?, ?, ?, ?)
        """, (packagetypeid, packagetypename, price, categoryid))
        
        connection.commit()
        connection.close()
        
        # Redirect to view the package types after the insert
        flash('New packages type added successfully!', 'success')
        return redirect(url_for('viewpackage_types'))    
    return render_template('addpackage_types.html')

@app.route('/editpackage_types/<int:packagetypeid>', methods=['GET', 'POST'])
def editpackage_types(packagetypeid):
    connection = sqlite3.connect('Trojan.db')
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    if request.method == 'POST':
        # Get form data
        packagetypename = request.form['packagetypename']
        categoryid = request.form['categoryid']
        packagesid = request.form['packagesid']
        price = request.form['price']
        
        # Update the package_types table with the new values
        cursor.execute("""
            UPDATE package_types 
            SET packagetypename=?, categoryid=?, packagesid=?, price=?
            WHERE packagetypeid=?
        """, (packagetypename, categoryid, packagesid, price, packagetypeid))
        connection.commit()
        connection.close()
        flash('Package Type updated successfully!', 'success')
        return redirect(url_for('viewpackage_types'))
    
    # Fetch the package details
    cursor.execute("""
        SELECT packagetypeid, packagetypename, categoryid, packagesid, price
        FROM package_types
        WHERE packagetypeid = ?
    """, (packagetypeid,))
    packagetypedetail = cursor.fetchone()
    connection.close()

    if packagetypedetail:
        # Convert sqlite3.Row to a regular dictionary
        package_dict = dict(packagetypedetail)
        return render_template('editpackage_types.html', packagetype=package_dict)
    else:
        print(f"No package found with ID {packagetypeid}")  # Debugging
        return "Package not found", 404

@app.route('/delete_package_types/<int:packagetypeid>', methods=['POST'], endpoint='delete_package_types')
def delete_package_types(packagetypeid):
    connection = sqlite3.connect('Trojan.db')
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    # Deleting the package type from the package_types table
    cursor.execute("DELETE FROM package_types WHERE packagetypeid = ?", (packagetypeid,))
    connection.commit()
    connection.close()
    flash("Package Type deleted successfully!", "success")
    # Redirect to the package types management page
    return redirect(url_for('viewpackage_types'))

@app.route('/generate-report', methods=['GET', 'POST'])
def generate_report():
    adminid = session.get('adminid')
    bookings_report = []
    users_report = []
    payments_report = []

    # Get pagination parameters from the URL
    page_bookings = request.args.get('page_bookings', 1, type=int)
    page_users = request.args.get('page_users', 1, type=int)
    page_payments = request.args.get('page_payments', 1, type=int)

    per_page = 5  # Number of items per page
    offset_bookings = (page_bookings - 1) * per_page
    offset_users = (page_users - 1) * per_page
    offset_payments = (page_payments - 1) * per_page

    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')

    # Initialize no reports shown flag
    show_reports = False

    connection = sqlite3.connect('Trojan.db')
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    if request.method == 'POST':
        start_date = request.form['start_date']
        end_date = request.form['end_date']
    
    if start_date and end_date:
        # Convert dates to datetime objects and handle the end date inclusivity
        start_datetime = datetime.strptime(start_date, "%Y-%m-%d")
        end_datetime = datetime.strptime(end_date, "%Y-%m-%d")
        end_datetime = end_datetime.replace(hour=23, minute=59, second=59)

        # Query for bookings
        bookings_query = """
            SELECT * FROM bookings 
            WHERE booking_date BETWEEN ? AND ? 
            LIMIT ? OFFSET ?;
        """
        cursor.execute(bookings_query, (start_datetime, end_datetime, per_page, offset_bookings))
        bookings_report = cursor.fetchall()

        # Query for users
        users_query = """
            SELECT * FROM users 
            WHERE registration_date BETWEEN ? AND ?
            LIMIT ? OFFSET ?;
        """
        cursor.execute(users_query, (start_datetime, end_datetime, per_page, offset_users))
        users_report = cursor.fetchall()

        # Query for payments
        payments_query = """
            SELECT * FROM payments 
            WHERE payment_date BETWEEN ? AND ? 
            LIMIT ? OFFSET ?;
        """
        cursor.execute(payments_query, (start_datetime, end_datetime, per_page, offset_payments))
        payments_report = cursor.fetchall()

        # Set flag to show reports if data exists
        if bookings_report or users_report or payments_report:
            show_reports = True

    connection.close()

    # Calculate total pages for each table
    connection = sqlite3.connect('Trojan.db')
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    total_pages_bookings = 0
    total_pages_users = 0
    total_pages_payments = 0

    if bookings_report:
        cursor.execute("SELECT COUNT(*) FROM bookings WHERE booking_date BETWEEN ? AND ?;", (start_datetime, end_datetime))
        total_bookings = cursor.fetchone()[0]
        total_pages_bookings = (total_bookings // per_page) + (1 if total_bookings % per_page else 0)

    if users_report:
        cursor.execute("SELECT COUNT(*) FROM users WHERE registration_date BETWEEN ? AND ?;", (start_datetime, end_datetime))
        total_users = cursor.fetchone()[0]
        total_pages_users = (total_users // per_page) + (1 if total_users % per_page else 0)

    if payments_report:
        cursor.execute("SELECT COUNT(*) FROM payments WHERE payment_date BETWEEN ? AND ?;", (start_datetime, end_datetime))
        total_payments = cursor.fetchone()[0]
        total_pages_payments = (total_payments // per_page) + (1 if total_payments % per_page else 0)

    connection.close()

    return render_template(
        'generate_report.html',
        bookings=bookings_report,
        users=users_report,
        payments=payments_report,
        adminid=adminid,
        page_bookings=page_bookings,
        page_users=page_users,
        page_payments=page_payments,
        total_pages_bookings=total_pages_bookings,
        total_pages_users=total_pages_users,
        total_pages_payments=total_pages_payments,
        show_reports=show_reports,
        start_date=start_date,
        end_date=end_date
    )

    
@app.route('/booking', methods=['GET', 'POST'])
def booking():
    if 'userid' not in session:
        flash("You need to be logged in to make a booking", "error")
        return redirect(url_for('login'))
    return redirect(url_for('selectcategories'))

@app.route("/selectcategories")
def selectcategories():
    uid = session.get('userid')
    connection = sqlite3.connect("Trojan.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM categories")
    categories = cursor.fetchall()
    connection.close()
    # Debug print for categories
    print(f"selectcategories - User ID: {uid}, Categories: {categories}")
    
    return render_template("selectcategories.html", categories=categories, uid=uid)

@app.route("/select_trainer/<int:category_id>/<int:packages_id>", methods=["GET", "POST"])
def select_trainer(category_id, packages_id):
    print(f"select_trainer - Category ID: {category_id}, Package ID: {packages_id}")  # Debugging print
    uid = session.get('userid')
    connection = sqlite3.connect("Trojan.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    # Fetch the package details
    cursor.execute("SELECT * FROM packages WHERE packagesid = ?", (packages_id,))
    package = cursor.fetchone()

    # Redirect if the package does not require a trainer
    if package['packagename'] == "Without Trainer: Self-Slim Plan":
        return redirect(url_for('selectpackage_types', category_id=category_id, packages_id=packages_id))

    # Fetch trainers that belong to the selected category
    cursor.execute("SELECT * FROM trainers WHERE categoryid = ?", (category_id,))
    trainers = cursor.fetchall()

    connection.close()

    # Debug print for filtered trainers
    print(f"select_trainer - Filtered Trainers for Category ID {category_id}: {trainers}")

    if request.method == 'POST':
        selected_trainer_id = request.form.get('trainer_id')
        if selected_trainer_id:
            return redirect(url_for('selectpackage_types', category_id=category_id, packages_id=packages_id, trainer_id=selected_trainer_id))
        else:
            flash("Please select a trainer.", "error")    
    return render_template("selecttrainer.html", trainers=trainers, category_id=category_id, packages_id=packages_id, uid=uid)

@app.route("/selectpackages/<int:category_id>", methods=["GET", "POST"])
def selectpackages(category_id):
    print(f"selectpackages - Category ID: {category_id}")  # Debugging print
    uid = session.get('userid')
    connection = sqlite3.connect("Trojan.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    
    cursor.execute("SELECT * FROM categories WHERE categoryid = ?", (category_id,))
    category = cursor.fetchone()

    cursor.execute("SELECT * FROM packages WHERE categoryid = ?", (category_id,))
    packages = cursor.fetchall()

    connection.close()

    # Debug print for category and packages
    print(f"selectpackages - Category: {category}, Packages: {packages}")

    if request.method == 'POST':
        selected_package_id = request.form.get('package_id')
        if selected_package_id:
            selected_package = next((pkg for pkg in packages if pkg['packagesid'] == int(selected_package_id)), None)
            if selected_package:
                trainer_required = selected_package['packagename'] in ["One-on-One: Shed & Shred Program", "Small Group: Lean Team Sessions"]
                if trainer_required:
                    return redirect(url_for('select_trainer', category_id=category_id, packages_id=selected_package_id))
                return redirect(url_for('selectpackage_types', category_id=category_id, packages_id=selected_package_id))
        else:
            flash("Please select a package.", "error")
            
    return render_template("selectpackages.html", category=category, packages=packages, uid=uid)


@app.route("/selectpackage_types/<int:category_id>/<int:packages_id>", methods=["GET", "POST"])
@app.route("/selectpackage_types/<int:category_id>/<int:packages_id>/<int:trainer_id>", methods=["GET", "POST"])
def selectpackage_types(category_id, packages_id, trainer_id=None):
    print(f"selectpackage_types - Category ID: {category_id}, Package ID: {packages_id}, Trainer ID: {trainer_id}")  # Debugging print
    uid = session.get('userid')
    connection = sqlite3.connect("Trojan.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    cursor.execute("SELECT * FROM packages WHERE packagesid = ?", (packages_id,))
    package = cursor.fetchone()

    cursor.execute("SELECT * FROM categories WHERE categoryid = ?", (category_id,))
    category = cursor.fetchone()

    cursor.execute("SELECT * FROM package_types WHERE packagesid = ?", (packages_id,))
    package_types = cursor.fetchall()

    trainers = None
    if package['packagename'] in ["One-on-One: Shed & Shred Program", "Small Group: Lean Team Sessions"]:
        cursor.execute("SELECT * FROM trainers")
        trainers = cursor.fetchall()

    connection.close()

    # Debug print for package, category, package_types, and trainers
    print(f"selectpackage_types - Package: {package}, Category: {category}, Package Types: {package_types}, Trainers: {trainers}")

    if request.method == 'POST':
        selected_packagetype_id = request.form.get('packagetype_id')
        selected_trainer_id = request.form.get('trainer_id') or trainer_id  # Preserve trainer_id if passed in the URL

        if not selected_packagetype_id:
            flash("Please select a package type.", "error")
        elif trainers and not selected_trainer_id:
            flash("Please select a trainer.", "error")
        else:
            if package['packagename'] == "Without Trainer: Self-Slim Plan":
                # For "Without Trainer: Self-Slim Plan", redirect directly to confirm booking without selecting time slot
                return redirect(url_for(
                    'confirm_booking',
                    category_id=category_id,
                    packages_id=packages_id,
                    packagetype_id=selected_packagetype_id
                ))
            else:
                return redirect(url_for(
                    'select_time',
                    category_id=category_id,
                    packages_id=packages_id,
                    packagetype_id=selected_packagetype_id,
                    trainer_id=selected_trainer_id,
                    uid=uid
                ))
                
    return render_template("selectpackagetypes.html", category=category, package=package, package_types=package_types, trainers=trainers, trainer_id=trainer_id, uid=uid)


@app.route("/select_time/<int:category_id>/<int:packages_id>/<int:packagetype_id>", methods=["GET", "POST"])
@app.route("/select_time/<int:category_id>/<int:packages_id>/<int:packagetype_id>/<int:trainer_id>", methods=["GET", "POST"])
def select_time(category_id, packages_id, packagetype_id, trainer_id=None):
    print(f"select_time - Category ID: {category_id}, Package ID: {packages_id}, Package Type ID: {packagetype_id}, Trainer ID: {trainer_id}")  # Debugging print

    connection = sqlite3.connect("Trojan.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    # Fetch group size from the package
    cursor.execute("SELECT group_size FROM packages WHERE packagesid = ?", (packages_id,))
    group_size = cursor.fetchone()['group_size']

    # Dynamically update max_bookings for all relevant time slots for the trainer
    cursor.execute("""
        UPDATE time_slots
        SET max_bookings = ?
        WHERE trainerid = ? AND timeid IN (
            SELECT timeid FROM time_slots WHERE trainerid = ?)
    """, (group_size, trainer_id, trainer_id))
    connection.commit()

    # Fetch available time slots (not fully booked)
    if trainer_id:
        cursor.execute("""
            SELECT * FROM time_slots
            WHERE trainerid = ? AND bookings_count < max_bookings
        """, (trainer_id,))
    else:
        cursor.execute("""
            SELECT * FROM time_slots
            WHERE bookings_count < max_bookings
        """)
    time_slots = cursor.fetchall()

    # Fetch fully booked time slots for display (optional)
    if trainer_id:
        cursor.execute("""
            SELECT * FROM time_slots
            WHERE trainerid = ? AND bookings_count >= max_bookings
        """, (trainer_id,))
        full_time_slots = cursor.fetchall()
    else:
        cursor.execute("""
            SELECT * FROM time_slots
            WHERE bookings_count >= max_bookings
        """)
        full_time_slots = cursor.fetchall()

    connection.close()

    print(f"select_time - Available Time Slots: {time_slots}, Full Time Slots: {full_time_slots}")

    if request.method == 'POST':
        selected_time_id = request.form.get('time_id')
        if selected_time_id:
            return redirect(url_for(
                'confirm_booking',
                category_id=category_id,
                packages_id=packages_id,
                packagetype_id=packagetype_id,
                time_id=selected_time_id,
                trainer_id=trainer_id
            ))
        flash("Please select a time slot.", "error")
        
    return render_template(
        "select_time.html",
        time_slots=time_slots,
        full_time_slots=full_time_slots,
        category_id=category_id,
        packages_id=packages_id,
        packagetype_id=packagetype_id,
        trainer_id=trainer_id
    )

@app.route("/confirm_booking/<int:category_id>/<int:packages_id>/<int:packagetype_id>", methods=["GET", "POST"])
@app.route("/confirm_booking/<int:category_id>/<int:packages_id>/<int:packagetype_id>/<int:time_id>", methods=["GET", "POST"])
@app.route("/confirm_booking/<int:category_id>/<int:packages_id>/<int:packagetype_id>/<int:time_id>/<int:trainer_id>", methods=["GET", "POST"])
def confirm_booking(category_id, packages_id, packagetype_id, time_id=None, trainer_id=None):
    print(f"confirm_booking - Category ID: {category_id}, Package ID: {packages_id}, Package Type ID: {packagetype_id}, Time ID: {time_id}, Trainer ID: {trainer_id}")  # Debugging print
    if 'userid' not in session:
        flash("You need to be logged in to confirm the booking", "error")
        return redirect(url_for('login'))

    userid = session.get('userid')
    connection = sqlite3.connect("Trojan.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    # Fetch necessary details
    cursor.execute("SELECT * FROM categories WHERE categoryid = ?", (category_id,))
    category = cursor.fetchone()

    cursor.execute("SELECT * FROM packages WHERE packagesid = ?", (packages_id,))
    package = cursor.fetchone()

    cursor.execute("SELECT * FROM package_types WHERE packagetypeid = ?", (packagetype_id,))
    package_type = cursor.fetchone()

    time_slot = None
    if time_id:
        cursor.execute("SELECT * FROM time_slots WHERE timeid = ?", (time_id,))
        time_slot = cursor.fetchone()

    trainer = None
    if trainer_id:
        cursor.execute("SELECT * FROM trainers WHERE trainerid = ?", (trainer_id,))
        trainer = cursor.fetchone()

    cursor.execute("SELECT username FROM users WHERE userid = ?", (userid,))
    user = cursor.fetchone()

    if not (category and package and package_type):
        flash("Invalid booking details. Please try again.", "error")
        return redirect(url_for("home"))

    # Set default values for "Without Trainer: Self-Slim Plan" package
    if package['packagename'] == "Without Trainer: Self-Slim Plan":
        trainer_name = "Without Trainer"
        time_name = "Free Time"
        time_description = "Free Time"
    else:
        trainer_name = trainer['trainername'] if trainer else "None"
        time_name = time_slot['name'] if time_slot else "None"
        time_description = time_slot['description'] if time_slot else "None"

    # Check if the time slot has reached its max bookings (only if time slot is applicable)
    if time_slot and time_slot['bookings_count'] >= time_slot['max_bookings']:
        flash("This time slot is fully booked. Please choose another time.", "error")
        return redirect(url_for("select_time", category_id=category_id, packages_id=packages_id, packagetype_id=packagetype_id, trainer_id=trainer_id))
    total_price = package['price'] + package_type['price']

    if request.method == 'POST':
        payment_method = request.form.get("payment_method")
        payment_amount = total_price
        payment_status = 'pending'
        myanmar_tz = pytz.timezone("Asia/Yangon")
        now = datetime.now(myanmar_tz)  # Capture current time
        booking_date = now.strftime("%Y-%m-%d %H:%M:%S") + f".{now.microsecond:06d}"
        # Insert booking
        cursor.execute(""" 
            INSERT INTO bookings (userid, categoryid, categoryname, packagesid, packagename, packagetypeid, packagetypename,booking_date ,timeid, name, description, trainerid, trainername, payment_method, payment_amount, total_price, status, username) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,?)
        """, (
            userid, category_id, category['categoryname'], packages_id, package['packagename'],
            packagetype_id, package_type['packagetypename'], booking_date,time_id if time_id else None, time_name, time_description, trainer_id,
            trainer_name, payment_method, payment_amount, total_price, "pending", user['username']
        ))
        booking_id = cursor.lastrowid

        # Insert payment details
        cursor.execute("""
            INSERT INTO payments (bookingid, userid, payment_method, payment_amount, payment_status)
            VALUES (?, ?, ?, ?, ?)
        """, (booking_id, userid, payment_method, payment_amount, payment_status))

        # Increment the booked_count for the selected time slot (if applicable)
        if time_id:
            cursor.execute("""
                UPDATE time_slots 
                SET bookings_count = bookings_count + 1 
                WHERE timeid = ?
            """, (time_id,))

        connection.commit()
        connection.close()

        # Redirect to payment processing
        return redirect(url_for("process_payment", booking_id=booking_id))
    connection.close()
    return render_template(
        "confirm_booking.html",
        category=category,
        package=package,
        package_type=package_type,
        time_slot=None if package['packagename'] == "Without Trainer: Self-Slim Plan" else time_slot,
        trainer=None if package['packagename'] == "Without Trainer: Self-Slim Plan" else trainer,
        total_price=total_price,
        username=user['username']
    )

@app.route("/process_payment/<int:booking_id>", methods=["GET", "POST"])
def process_payment(booking_id):
    with sqlite3.connect("Trojan.db") as connection:
        connection.row_factory = sqlite3.Row
        cursor = connection.cursor()

        # Retrieve the payment method from the bookings table
        cursor.execute("SELECT payment_method FROM bookings WHERE bookingid = ?", (booking_id,))
        booking = cursor.fetchone()

        if not booking:
            flash("Booking not found.", "error")
            return redirect(url_for("home"))

        payment_method = booking['payment_method']  # Ensure it's fetched from the database

        # Get current time in Myanmar timezone
        myanmar_tz = pytz.timezone("Asia/Yangon")
        now = datetime.now(myanmar_tz)  # Capture current time
        payment_date = now.strftime("%Y-%m-%d %H:%M:%S") + f".{now.microsecond:06d}"

        # Update the payment status and details in the payments table
        cursor.execute("""
            UPDATE payments
            SET payment_status = 'completed', payment_date = ?
            WHERE bookingid = ?
        """, (payment_date, booking_id))

        # Update the booking status in the bookings table
        cursor.execute("""
            UPDATE bookings
            SET status = 'confirmed', payment_status = 'completed', payment_date = ?
            WHERE bookingid = ?
        """, (payment_date, booking_id))

        connection.commit()

    flash("Payment successful and booking confirmed!", "success")
    return redirect(url_for("invoice", booking_id=booking_id))

@app.route("/invoice/<int:booking_id>", methods=["GET"])
def invoice(booking_id):
    connection = sqlite3.connect("Trojan.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    # Fetch booking and payment details, including payment_method
    cursor.execute("""
        SELECT b.*, c.categoryname, p.packagename, pt.packagetypename, u.username, 
        pmt.payment_amount, b.payment_status, b.payment_method, b.payment_date, 
        ts.name AS time_slot_name, ts.description AS time_slot_description
        FROM bookings b
        JOIN categories c ON b.categoryid = c.categoryid
        JOIN packages p ON b.packagesid = p.packagesid
        JOIN package_types pt ON b.packagetypeid = pt.packagetypeid
        JOIN users u ON b.userid = u.userid
        LEFT JOIN payments pmt ON b.bookingid = pmt.bookingid
        LEFT JOIN time_slots ts ON b.timeid = ts.timeid
        WHERE b.bookingid = ?
    """, (booking_id,))
    bookings = cursor.fetchone()
    connection.close()

    if bookings:
        return render_template("invoice.html", bookings=bookings)
    else:
        flash('Booking not found.', 'error')
        return redirect(url_for('home'))    

@app.route("/viewbookings")
def viewbookings():
    adminid = session.get('adminid')

    # Get the page number from the URL query, default to 1 if not specified
    page = request.args.get('page', 1, type=int)
    per_page = 5  # Number of records per page
    offset = (page - 1) * per_page  # Calculate the offset for the query

    # Connect to the database
    connection = sqlite3.connect("Trojan.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    # Fetch the bookings for the current page
    cursor.execute("SELECT * FROM bookings LIMIT ? OFFSET ?", (per_page, offset))
    bookings = cursor.fetchall()

    # Get the total number of bookings to calculate total pages
    cursor.execute("SELECT COUNT(*) FROM bookings")
    total_bookings = cursor.fetchone()[0]
    total_pages = (total_bookings // per_page) + (1 if total_bookings % per_page > 0 else 0)

    # Calculate the pagination range (page numbers to display)
    start_page = max(1, page - 1)  
    end_page = min(total_pages, page + 1)  
    page_range = list(range(start_page, end_page + 1))  # List of page numbers

    # Close the database connection
    connection.close()
    
    return render_template(
        "managebookings.html", 
        bookings=bookings, 
        adminid=adminid, 
        current_page=page, 
        total_pages=total_pages, 
        page_range=page_range  # Pass the page range to the template
    )

@app.route('/delete_bookings/<int:bookingid>', methods=['POST'])
def delete_bookings(bookingid):
    connection = sqlite3.connect('Trojan.db')
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()    
    
    cursor.execute("DELETE FROM bookings WHERE bookingid=?", (bookingid,))    
    connection.commit()
    connection.close()
    flash('Booking deleted successfully!', 'danger')        
    return redirect(url_for('viewbookings'))
       
@app.route('/trainer_profile/<int:trainer_id>/', methods=['GET'])
def trainer_profile(trainer_id):
    # Connect to the database and fetch trainer data by ID
    connection = sqlite3.connect('Trojan.db')
    cursor = connection.cursor()
    cursor.execute("SELECT trainername, age, weight, height, occupation, photo, description FROM trainers WHERE trainerid = ?", (trainer_id,))
    trainer = cursor.fetchone()
    connection.close()
    
    # Check if trainer data was found
    if trainer:
        # Pass the trainer data to the template
        return render_template('trainer_profile.html', trainer=trainer)
    else:
        # If no trainer is found, return a "Not Found" error
        return "Trainer not found", 404

@app.route("/viewtrainers")
def viewtrainers():
    # Ensure the admin is logged in
    adminid = session.get('adminid')
    if not adminid:
        flash("You need to log in to access this page.", "danger")
        return redirect(url_for('login'))

    # Get the current page from the query parameters; default to page 1
    current_page = request.args.get('page', 1, type=int)
    trainers_per_page = 1  # Number of trainers to display per page

    # Calculate the offset and limit for pagination
    offset = (current_page - 1) * trainers_per_page

    # Connect to the database
    connection = sqlite3.connect("Trojan.db")
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()

    try:
        # Fetch total number of trainers for pagination
        cursor.execute("SELECT COUNT(*) FROM trainers")
        total_trainers = cursor.fetchone()[0]
        total_pages = (total_trainers + trainers_per_page - 1) // trainers_per_page  # Ceiling division

        # Fetch trainers for the current page
        cursor.execute(
            "SELECT * FROM trainers LIMIT ? OFFSET ?",
            (trainers_per_page, offset)
        )
        trainers = cursor.fetchall()

        # Calculate the pagination range
        start_page = max(1, current_page - 1)
        end_page = min(total_pages, current_page + 1)
        page_range = list(range(start_page, end_page + 1))
    except sqlite3.Error as e:
        # Handle database errors
        flash(f"An error occurred while retrieving trainers: {e}", "danger")
        trainers = []
        total_pages = 1
        page_range = []
    finally:
        # Ensure the connection is closed
        connection.close()

    # Render the template with trainers data and pagination details
    return render_template(
        "managetrainers.html",
        trainers=trainers,
        current_page=current_page,
        total_pages=total_pages,
        page_range=page_range,
        adminid=adminid
    )



@app.route('/addtrainers', methods=['GET', 'POST'])
def addtrainers():
    if request.method == 'POST':
        # Get form data
        trainername = request.form['trainername']
        age = request.form['age']
        weight = request.form['weight']
        height = request.form['height']
        occupation = request.form['occupation']
        description = request.form['description']        
        
        # Handle file upload for the trainer photo
        photo = request.files['photo']
        photo_filename = photo.filename if photo else ''  # Set filename or empty if no photo is provided
        
        # Save the photo if it exists
        if photo_filename:
            photo.save('static/photos/' + photo_filename)

        # Insert trainer data into the database (no trainerid because it's auto-incremented)
        connection = sqlite3.connect('Trojan.db')
        cursor = connection.cursor()
        cursor.execute("""
            INSERT INTO trainers (trainername, age, weight, height, occupation, description, photo)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (trainername, age, weight, height, occupation, description, photo_filename))
        
        connection.commit()
        connection.close()
        flash("New trainer add successfully", "success")
        
        # Redirect to view trainers after the insert
        return redirect(url_for('viewtrainers'))    
    
    return render_template('addtrainers.html')

@app.route('/deletetrainers/<int:trainerid>', methods=['POST'], endpoint='deletetrainers')
def deletetrainers(trainerid):
    connection = sqlite3.connect('Trojan.db')
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    # Deleting the package type from the package_types table
    cursor.execute("DELETE FROM trainers WHERE trainerid = ?", (trainerid,))
    connection.commit()
    connection.close()
    # Redirect to the package types management page
    flash("Trainer Profile delete successfully", "success")
    return redirect(url_for('viewtrainers'))

@app.route('/edittrainers/<int:trainerid>', methods=['GET', 'POST'])
def edittrainers(trainerid):
    connection = sqlite3.connect('Trojan.db')
    connection.row_factory = sqlite3.Row
    cursor = connection.cursor()
    # Fetch the current trainer data
    cursor.execute("SELECT * FROM trainers WHERE trainerid=?", (trainerid,))
    trainer = cursor.fetchone()
    if request.method == 'POST':
        # Get form data
        trainername = request.form['trainername']
        age = request.form['age']
        weight = request.form['weight']
        height = request.form['height']
        occupation = request.form['occupation']
        description = request.form['description']
        poster = request.files['photo']  # 'photo' form field

        # Handle the uploaded photo
        photo_filename = poster.filename if poster else trainer['photo']  # changed from 'photo' to 'poster'
        if poster and photo_filename:  # same change here, use 'poster'
            poster.save('static/photos/' + photo_filename)

        # Update the trainers table with the new values
        cursor.execute("""
            UPDATE trainers
            SET trainername=?, age=?, weight=?, height=?, occupation=?, description=?, photo=?
            WHERE trainerid=?
        """, (trainername, age, weight, height, occupation, description, photo_filename, trainerid))

        connection.commit()
        connection.close()
        flash("Trainer profile updated successfully", "success")
        return redirect(url_for('viewtrainers'))

    # If GET request, pre-fill the form with current trainer data
    return render_template('edittrainers.html', trainer=trainer)

@app.route('/logout')
def logout():
    session.clear()  # Clears the session    
    return redirect(url_for('home'))

@app.route('/adminlogout')
def admin_logout():
    session.clear()  # Clears the session
    flash("You have been logged out.", "success")
    return redirect(url_for('admindashboard'))

if __name__ == '__main__':
    app.run(debug=True)

