import json
from flask import Flask, flash, request, session, render_template, redirect, url_for, render_template_string
#from msgraph_core import GraphClientFactory, AzureIdentityAuthenticationProvider
from msgraph_core import AzureIdentityAuthenticationProvider
import requests
import mysql.connector
import secrets
import requests
from flask import redirect, session
from adal import AuthenticationContext

#from msgraph import AuthorizationCodeProvider, GraphApiClient

CLIENT_ID = 'baf988fb-4544-4dcf-a47d-4e21a533c2db'
CLIENT_SECRET = 'gh88Q~Z5S9YPafojtomr6qOo-osGsufKmil5ia90'
TENANT_ID = 'e34fd78b-f48d-4235-9787-fef76723be14'
REDIRECT_URI = 'http://localhost:5000/handle'
SCOPES = ['User.Read']
authority_url = f'https://login.microsoftonline.com/{TENANT_ID}'

secret_key = secrets.token_urlsafe(24)

app = Flask(__name__)
app.secret_key = secret_key

# MySQL Database Connection
connection = mysql.connector.connect(
    host='162.241.244.25',
    user='uahqojmy_TaSharma',
    password='Ects0131!!!',
    database='uahqojmy_student_TaSharma'
)

@app.route('/create_request')
def create_request():
    user_id = session.get('user_id')
    connection.reconnect()
    cursor = connection.cursor(dictionary=True)
    cursor.execute('SELECT Id, display_name FROM Lab')
    labs = cursor.fetchall()
    lab_query = '''
            SELECT l.display_name
            FROM Lab l
            JOIN User_Lab ul ON l.Id = ul.lab_id
            WHERE ul.user_id = %s
        '''
    cursor.execute(lab_query, (user_id,))
    lab_display_name = cursor.fetchone()
    cursor.execute('SELECT Id, Display FROM Request_Type')
    request_types = cursor.fetchall()

    return render_template('create_request.html', labs=labs, request_types=request_types, lab_display_name=lab_display_name)


@app.route('/submit_request', methods=['POST'])
def submit_request():
    connection.reconnect()
    user_id = session.get('user_id')
    cursor = connection.cursor(dictionary=True)
    lab_query = '''
            SELECT l.Id
            FROM Lab l
            JOIN User_Lab ul ON l.Id = ul.lab_id
            WHERE ul.user_id = %s
        '''
    cursor.execute(lab_query, (user_id,))
    lab_ids = cursor.fetchall()
    matching_lab_id = lab_ids[0]["Id"]

    # for lab_id in lab_ids:
    #     if lab_id['Id'] == user_id:
    #         matching_lab_id = lab_id['Id']
    #         break  # Found the matching lab_id, no need to continue the loop
    connection.commit()
    
    # lab_id = request.form['lab_id']
    requested_date = request.form['requested_date']
    description = request.form['description']
    unit_price = request.form['unit_price']
    quantity = request.form['quantity']
    oac_recommended_date = request.form['oac_recommended_date']
    request_type_id = request.form['request_type_id']  
    additional_notes = request.form['additional_notes']

    #  # Check if the "Save as Draft" button is clicked
    # if 'save_as_draft' in request.form:
    #     state_id = 1  # Set State_Id to 1 (draft)
    # else:
    #     state_id = 3  # Set State_Id to 3 (submitted)

    # Establish a cursor to execute SQL queries
    connection.reconnect()
    cursor = connection.cursor()

    insert_query = '''
    INSERT INTO Request (Lab_Id, Requested_Date, Description, Unit_Price, Quantity,
                        OAC_Recommended_Date, Request_Type_Id, Additional_Notes, User_Id, State_Id)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    '''
    # Execute the query with the provided form data and User_Id
    cursor.execute(insert_query, (
        matching_lab_id, requested_date, description, unit_price, quantity,
        oac_recommended_date, request_type_id, additional_notes, user_id, 3
    ))

    # Commit the changes to the database
    connection.commit()
    return redirect(url_for('teacher_dashboard'))



def fetch_admin_id_by_role(role_display):
    connection.reconnect()
    cursor = connection.cursor()
    query = 'SELECT User_Id FROM User_Role WHERE Role_Id = (SELECT Id FROM Role WHERE Display = %s)'
    cursor.execute(query, (role_display,))
    admin_id = cursor.fetchone()
    if admin_id:
        return admin_id[0]
    else:
        return None


@app.route('/')
def home():
    return redirect("https://login.microsoftonline.com/e34fd78b-f48d-4235-9787-fef76723be14/oauth2/v2.0/authorize?client_id=baf988fb-4544-4dcf-a47d-4e21a533c2db&response_type=code&redirect_uri=http://localhost:5000/handle&response_mode=query&scope=User.Read")
    #out = sp.run(["php", "login.php"], stdout=sp.PIPE)
    #return out.stdout

# Function to fetch a teacher's current and past requaests
def get_teacher_requests(user_id):
    connection.reconnect()
    cursor = connection.cursor(dictionary=True)
    #query = "select * from users where userid = " + somevar + " " #this is bad because
    #what people do is fill out the form with a field like "; drop database users;" 
    # Fetch requests based on user_id (assuming user_id corresponds to the teacher)
    query = '''
    SELECT r.*, rt.Display AS Request_Type, s.Display AS State
    FROM Request r
    JOIN Request_Type rt ON r.Request_Type_Id = rt.Id
    JOIN State s ON r.State_Id = s.Id
    WHERE r.User_Id = %s
    ORDER BY r.Requested_Date DESC
    '''
    cursor.execute(query, (user_id,))
    requests = cursor.fetchall()

    return requests


def fetch_response_comments(request_id):
    connection.reconnect()
    cursor = connection.cursor(dictionary=True)
    query = '''
        SELECT Notes
        FROM Response
        WHERE Request_Id = %s
    '''
    cursor.execute(query, (request_id,))
    comments = cursor.fetchall()
    return [comment['Notes'] for comment in comments]


@app.route('/handle')
def handle():
    session['authcode'] = request.args.get('code')
    return redirect("/getuser")
    #    $_SESSION['authcode'] = $_GET["code"];
    #header("location:./GetUser.php");


@app.route('/getuser')
def getuser():
    if 'authcode' not in session:
        return redirect('/login')

    authcode = session['authcode']
    scopes = ['https://graph.microsoft.com/User.Read']
    authority_uri = f'https://login.microsoftonline.com/{TENANT_ID}'
    auth_context = AuthenticationContext(authority_uri)
    
    token_response = auth_context.acquire_token_with_authorization_code(
        authcode,
        REDIRECT_URI,                                                                
        None,
        CLIENT_ID,
        CLIENT_SECRET
    )
    
    if 'accessToken' in token_response:
        access_token = token_response['accessToken']
        headers = {
            'Authorization': 'Bearer ' + access_token,
            'Content-Type': 'application/json'
        }

        try:
            # Get user information from Microsoft Graph API
            response = requests.get('https://graph.microsoft.com/v1.0/me', headers=headers)

            if response.status_code == 200:
                me = response.json()

                # Check if the user exists in the local database
                cursor = connection.cursor(dictionary=True)
                cursor.execute("SELECT id FROM User WHERE email = %s", (me.get('mail'),))
                existing_user = cursor.fetchone()

                if existing_user:
                    # If user exists, redirect to teacher_dashboard.html with user_id in session
                    session['user_id'] = existing_user['id']
                    return redirect('/teacher_dashboard.html')
                else:
                    # If user doesn't exist, create a new entry in the User table
                    cursor.execute("INSERT INTO User (id, email, display_name, givenName, surname) VALUES (%s, %s, %s, %s, %s)",
                                (None, me.get('mail'), me.get('displayName'), me.get('givenName'), me.get('surname')))
                    connection.commit()

                    cursor.execute("SELECT MAX(Id) FROM User")
                    max_id_tuple = cursor.fetchone()
                    if max_id_tuple:
                        new_user_id = max_id_tuple['MAX(Id)']
                    else:
                        new_user_id = None  # Handle the case where there are no records in the table

                    #connection.commit()  # Commit after fetching the maximum id

                    # Increment user ID for the next user (assuming auto-increment is not enabled)
                    #new_user_id += 1

                    cursor.execute("INSERT INTO User_Role (User_Id, Role_Id) VALUES (%s, %s)",
                                (new_user_id, 1))
                    connection.commit()

                    cursor.execute("INSERT INTO User_Lab (User_Id, Lab_id) VALUES (%s, %s)",
                                (new_user_id, 1))
                    connection.commit()

                    # Set user_id in session and redirect to teacher_dashboard.html
                    session['user_id'] = new_user_id
                    return redirect('/teacher_dashboard.html')
            else:
                return f"Failed to retrieve user data from Microsoft Graph API. Status code: {response.status_code}"
        except Exception as e:
            return f"An error occurred while processing user data: {str(e)}"
    else:
        return "Failed to acquire access token"

    
@app.route('/request_role_change')
def request_role_change():
    user_id = session.get('user_id')

    # Check if user_id exists in the session
    if user_id is None:
        return redirect(url_for('home'))
    
    connection.reconnect()
    cursor = connection.cursor(dictionary=True)


    query_check = '''
        SELECT * FROM Request_Role
    '''
    cursor.execute(query_check)
    check_requests = cursor.fetchall()
    for request in check_requests:
        if (request['User_Id'] == user_id) and (request['State_Id'] == 3):
            return render_template_string("""
                <script>
                    alert("You Have Already Submitted A Request To Be An Admin");
                    window.location.href = "{{ url_for('teacher_dashboard') }}";
                </script>
                """)

    query = """
        INSERT INTO Request_Role (Current_Role_Id, New_Role_Id, State_Id, User_Id)
        VALUES (1, 2, 3, %s);
    """
    cursor.execute(query, (user_id,))

    connection.commit()
    cursor.close()

    return render_template_string("""
    <script>
        alert("Request to be an admin submitted successfully!");
        window.location.href = "{{ url_for('teacher_dashboard') }}";
    </script>
    """)




@app.route('/teacher_dashboard.html')
def teacher_dashboard():
    user_id = session.get('user_id')

    # Check if user_id exists in the session
    if user_id is None:
        return redirect(url_for('home'))  # Redirect to the login page

    connection.reconnect()
    cursor = connection.cursor(dictionary=True)
    cursor.execute('SELECT * FROM User WHERE id = %s', (user_id,))
    user = cursor.fetchone()

    if user:
        # Fetching display_name from User table
        display_name = user['display_name']

        # Fetching role Display from Role table using User_Role table
        cursor.execute('''
            SELECT Role.Long_Description, Role.Display
            FROM Role
            JOIN User_Role ON Role.Id = User_Role.Role_Id
            WHERE User_Role.User_Id = %s
        ''', (user_id,))
        role_data = cursor.fetchone()
        role_long_description = role_data['Long_Description']
        role_display = role_data['Display'] if 'Display' in role_data else None

        # Fetching the user's requests directly from the Request table using User_Id
        query = '''
            SELECT r.*, rt.Display AS Request_Type, s.Display AS State, r.Additional_Notes
            FROM Request r
            JOIN Request_Type rt ON r.Request_Type_Id = rt.Id
            JOIN State s ON r.State_Id = s.Id
            WHERE r.User_Id = %s
            ORDER BY r.Requested_Date DESC
        '''
        cursor.execute(query, (user_id,))
        user_requests = cursor.fetchall()

        # Update the State field to include the display name
        for request in user_requests:
            state_id = request['State_Id']
            state_display = fetch_state_display(state_id)
            request['State_Display'] = state_display

            # Fetch comments from the Response table
            request['Comments'] = fetch_response_comments(request['Id'])

        # Filter requests to display only the ones matching the current user's ID
        user_requests = [req for req in user_requests if req['User_Id'] == user_id]

        print("User Requests:", user_requests)

        user_details = {
            'email': user['email'],
            'name': display_name,  # Using display_name from User table as 'name'
            'role': role_long_description,   # Fetching role Long_Description from Role table
            'role2': role_display,
            'user_requests': user_requests,  # Adding user's requests to the dictionary
            'user_id': user_id  # Pass user_id to the template
        }

        # # Fetch messages for the user
        # messages_query = '''
        #     SELECT m.*, u.display_name AS sender_name
        #     FROM Message m
        #     JOIN User u ON m.Sender_Id = u.Id
        #     WHERE m.Recipient_Id = %s AND m.Is_Read = 0
        # '''
        # cursor.execute(messages_query, (user_id,))
        # unread_messages = cursor.fetchall()

        # # Update messages as read
        # update_messages_query = '''
        #     UPDATE Message SET Is_Read = 1 WHERE Recipient_Id = %s
        # '''
        # cursor.execute(update_messages_query, (user_id,))
        connection.commit()

        # # Remove unread messages
        # unread_messages = []  # Empty list to remove unread messages

        return render_template('teacher_dashboard.html', user=user_details) #, unread_messages=unread_messages)
    else:
        return redirect(url_for('home'))
    

def fetch_state_display(state_id):
    connection.reconnect()
    cursor = connection.cursor()
    query = 'SELECT Display FROM State WHERE Id = %s'
    cursor.execute(query, (state_id,))
    state_display = cursor.fetchone()
    if state_display:
        return state_display[0]
    else:
        return None



def fetch_user_role_description(user_id):
    # Assuming you have a function to fetch the user's role description from the database
    # Establish a database connection and execute a query to fetch the user's role description
    connection.reconnect()
    cursor = connection.cursor(dictionary=True)
    query = '''
        SELECT Role.Long_Description
        FROM Role
        JOIN User_Role ON Role.Id = User_Role.Role_Id
        WHERE User_Role.User_Id = %s
    '''
    cursor.execute(query, (user_id,))
    role_description = cursor.fetchone()
    if role_description:
        return role_description['Long_Description']  # Assuming the role description is in the 'Display' column
    else:
        return None  # Return None or a default value if the role description isn't found
    

@app.route('/review_lab_change/<int:Current_Lab_Id>/<int:New_Lab_Id>/<int:User_Id>', methods=['POST'])
def review_lab_change(Current_Lab_Id, New_Lab_Id, User_Id):

    connection.reconnect()
    cursor = connection.cursor()
    query = '''
        SELECT ls.Current_Lab_Id, ls.New_Lab_Id, ls.State_Id, ls.User_Id, s.Display, u.display_name userDisplayName, l.display_name labDisplayName, l2.display_name lab2DisplayName
        FROM Lab_State ls
        JOIN State s ON ls.State_Id = s.Id
        JOIN User u ON ls.User_Id = u.Id
        JOIN Lab l ON ls.Current_Lab_Id = l.Id
        JOIN Lab l2 ON ls.New_Lab_Id = l2.Id
        WHERE ls.Current_Lab_Id = %s
        AND ls.New_Lab_Id = %s
        AND ls.User_Id = %s
    '''
    cursor.execute(query, (Current_Lab_Id, New_Lab_Id, User_Id,))
    labstate = cursor.fetchone()

    if labstate:
        if request.method == 'POST':
            action = request.form['action']  # Get the action (accept or deny) from the form
            
            # Modify the state ID based on the action
            if action == 'accept':
                new_state_id = 4  # Set the new state ID to 4 for accepted requests

                user_display_name = labstate[5]  # Index 5 corresponds to 'userDisplayName'
                current_lab_id = labstate[0]      # Index 0 corresponds to 'Current_Lab_Id'
                new_lab_id = labstate[1]          # Index 1 corresponds to 'New_Lab_Id'

                # Update the user's lab ID in the User_Lab table to the new lab ID
                update_query = '''
                    UPDATE User_Lab
                    SET Lab_Id = %s
                    WHERE User_Id = (SELECT Id FROM User WHERE display_name = %s)
                    AND Lab_Id = %s
                '''
                cursor.execute(update_query, (new_lab_id, user_display_name, current_lab_id))
                connection.commit()
                    
            elif action == 'deny':
                new_state_id = 6 
            else:
                return redirect(url_for('lab_requests'))
            
            # Update the state ID in the database
            update_query2 = "UPDATE Lab_State SET State_Id = %s WHERE User_Id = %s AND Current_Lab_Id = %s AND New_Lab_Id = %s"
            cursor.execute(update_query2, (new_state_id, labstate[3], labstate[0], labstate[1]))
            connection.commit()
            
            # Close the cursor and connection
            cursor.close()
            connection.close()

            # Redirect to the lab_requests route after processing the request
            return redirect(url_for('lab_requests'))
    return "Something went wrong"




@app.route('/lab_requests')
def lab_requests():
    connection.reconnect()
    cursor = connection.cursor(dictionary=True)
    
    # Fetch lab change requests along with state names
    query = '''
        SELECT ls.Current_Lab_Id, ls.New_Lab_Id, ls.State_Id, ls.User_Id, s.Display, u.display_name userDisplayName, l.display_name labDisplayName, l2.display_name lab2DisplayName
        FROM Lab_State ls
        JOIN State s ON ls.State_Id = s.Id
        JOIN User u ON ls.User_Id = u.Id
        JOIN Lab l ON ls.Current_Lab_Id = l.Id
        JOIN Lab l2 ON ls.New_Lab_Id = l2.Id
    '''
    cursor.execute(query)
    lab_requests = cursor.fetchall()
    
    print(lab_requests)

    # Close the cursor and connection
    cursor.close()
    connection.close()
    
    # Pass lab change requests to the lab_requests.html template
    return render_template('lab_requests.html', lab_requests=lab_requests)


@app.route('/review_role_change_requests')
def review_role_change_requests():
    connection.reconnect()
    cursor = connection.cursor(dictionary=True)

    query = """
    SELECT * FROM Request_Role r
    INNER JOIN User u ON r.User_Id = u.Id
    INNER JOIN State s ON r.State_Id = s.Id
    WHERE r.State_Id = 3
    """

    cursor.execute(query)
    requests = cursor.fetchall()

    return render_template('review_role_change_requests.html', requests=requests)

@app.route('/admin_dashboard')
def admin_dashboard():
    user_id = session.get('user_id')
    if user_id is None:
        return redirect(url_for('home'))  # Redirect to login page

    connection.reconnect()
    cursor = connection.cursor(dictionary=True)
    cursor.execute('SELECT * FROM User WHERE Id = %s', (user_id,))
    user = cursor.fetchone()

    if user:
        # Fetching display_name from User table
        display_name = user['display_name']

        # Fetching role using the updated function
        admin_role = fetch_user_role(user_id)
        if admin_role != 'admin':
            return "You don't have permission to access this page."

        query = '''
            SELECT r.*, u.display_name AS name, rt.Display AS Request_Type, s.Display AS State, r.Lab_Id, r.Additional_Notes
            FROM Request r
            JOIN User u ON r.User_Id = u.Id
            JOIN Request_Type rt ON r.Request_Type_Id = rt.Id
            JOIN State s ON r.State_Id = s.Id
            WHERE r.State_Id = 3 
            ORDER BY r.Requested_Date DESC
        '''
        cursor.execute(query)
        requests = cursor.fetchall()

        # Fetch all entries from the Lab table and store them in a dictionary
        lab_lookup = {0: ''}
        cursor.execute('SELECT Id, display_name FROM Lab')
        labs_data = cursor.fetchall()
        for lab in labs_data:
            lab_lookup[lab['Id']] = lab['display_name']

        user_details = {
            'email': user['email'],
            'name': display_name,
            'role': 'Admin',
        }

        cursor.execute('SELECT display_name FROM Lab')
        labs_data = cursor.fetchall()
        labs = [lab['display_name'] for lab in labs_data]
        
        for request in requests:
            lab_id = request['Lab_Id']
            request['lab_display_name'] = lab_lookup.get(lab_id)
            if not request['lab_display_name']:
                lab_display_name = 0
                lab_display_name = lab_lookup.get(1)
                request['lab_display_name'] = lab_display_name

        

        return render_template('admin_dashboard.html', user=user_details, requests=requests, labs=labs, lab_lookup=lab_lookup)
    else:
        return redirect(url_for('home'))  # Redirect to login if user details not found




@app.route('/process_request/<int:request_id>', methods=['POST'])
def process_request(request_id):
    user_id = session.get('user_id')
    if user_id is None:
        return redirect(url_for('home'))

    # Check if the user has the admin role
    admin_role = fetch_user_role(user_id)
    if admin_role != 'admin':
        return "You don't have permission to process requests."

    # Get the admin's decision and comments
    action = request.form.get('action')
    comments = request.form.get('comments')

    connection.reconnect()
    cursor = connection.cursor()

    # Determine the state_id and response_type_id based on the admin's action
    if action == 'approve':
        state_id = 4  # Approve with comments
        response_type_id = 4  
    elif action == 'deny':
        state_id = 6  # Deny with reason
        response_type_id = 5  
    elif action == 'return':
        state_id = 7  # Return to teacher and ask for more details
        response_type_id = 6
        
    # Save the admin's comments in the Response table
    response_query = '''
        INSERT INTO Response (User_Id, Request_Id, Response_Type_Id, Date, Notes)
        VALUES (%s, %s, %s, NOW(), %s)
    '''
    cursor.execute(response_query, (user_id, request_id, response_type_id, comments))
    connection.commit()

    # Set State_Id to 6 when admin denies the request
    connection.reconnect()
    cursor = connection.cursor()
    update_query = '''
        UPDATE Request
        SET State_Id = %s
        WHERE Id = %s
    '''
    cursor.execute(update_query, (state_id, request_id))
    connection.commit()

    cursor.close()

    return redirect(url_for('admin_dashboard'))



def fetch_user_role(user_id):
    connection.reconnect()
    cursor = connection.cursor()
    query = 'SELECT Role.Display FROM Role JOIN User_Role ON Role.Id = User_Role.Role_Id WHERE User_Role.User_Id = %s'
    cursor.execute(query, (user_id,))
    role = cursor.fetchone()
    if role:
        return role[0]
    else:
        return None

@app.route('/logout')
def logout():
    session.clear()  # Clear the session data
    return redirect(url_for('teacher_dashboard'))

@app.route('/completed_requests_table')
def completed_requests_table():
    user_id = session.get('user_id')

    # Check if the user has the admin role
    admin_role = fetch_user_role(user_id)

    if admin_role != 'admin':
        return "You don't have permission to access this page."

    connection.reconnect()
    cursor = connection.cursor(dictionary=True)

    # Fetch user details
    cursor.execute('SELECT * FROM User WHERE Id = %s', (user_id,))
    user = cursor.fetchone()

    if user:
        # Fetching display_name from User table
        display_name = user['display_name']

        # Fetching the list of completed requests (State_Id = 4) with Unit_Price and Quantity
        query = '''
            SELECT r.*, u.display_name AS name, rt.Display AS Request_Type, s.Display AS State,
                   r.Unit_Price, r.Quantity  -- Include Unit_Price and Quantity
            FROM Request r
            JOIN User u ON r.User_Id = u.Id
            JOIN Request_Type rt ON r.Request_Type_Id = rt.Id
            JOIN State s ON r.State_Id = s.Id
            WHERE r.State_Id = 4
            ORDER BY r.Requested_Date DESC
        '''
        cursor.execute(query)
        completed_requests = cursor.fetchall()

        user_details = {
            'email': user['email'],
            'name': display_name,
            'role': 'Admin'
        }

        return render_template('completed_requests_table.html', user=user_details, completed_requests=completed_requests)

    else:
        return redirect(url_for('home'))  # Redirect to login if user details not found



@app.route('/login.html', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    connection.reconnect()
    cursor = connection.cursor(dictionary=True)
    cursor.execute('SELECT * FROM User WHERE email = %s', (username,))
    user = cursor.fetchone()

    if user and user['password'] == password:
        # Fetch the user's role description from User_Role and Role tables
        cursor.execute('SELECT Role_Id FROM User_Role WHERE User_Id = %s', (user['Id'],))
        role_id = cursor.fetchone()['Role_Id']

        cursor.execute('SELECT Display FROM Role WHERE Id = %s', (role_id,))
        role_description = cursor.fetchone()['Display']

        # Set the 'user_id' in the session
        session['user_id'] = user['Id']

        # Redirect the user to their respective dashboard based on their role description
        if role_description == 'teacher':
            return redirect(url_for('teacher_dashboard'))
        elif role_description == 'admin':
            return redirect(url_for('admin_dashboard'))

    # If authentication fails or user doesn't have appropriate role, redirect to login page
    return redirect(url_for('home'))

@app.route('/edit_lab', methods=['GET', 'POST'])
def edit_lab():
    user_id = session.get('user_id')
    if user_id is None:
        return redirect(url_for('home'))

    connection.reconnect()
    cursor = connection.cursor(dictionary=True)

    query_user_lab = '''
        SELECT * FROM User_Lab
        WHERE User_Id = %s
    '''
    cursor.execute(query_user_lab, (user_id,))
    user_lab = cursor.fetchone()

    print("User Lab:", user_lab)

    query_labs = 'SELECT display_name, Id FROM Lab'
    cursor.execute(query_labs)
    labs = cursor.fetchall()

    query_labs_2 = 'SELECT display_name FROM Lab WHERE Id = %s'
    cursor.execute(query_labs_2, (user_lab['Lab_id'],))
    current_lab = cursor.fetchall()

    connection.commit()
    cursor.close()

    return render_template('edit_lab.html', user_lab=user_lab, user_id=user_id, labs=labs, current_lab=current_lab)

@app.route('/submit_lab_change', methods=['POST'])
def submit_lab_change():
    connection.reconnect()
    cursor = connection.cursor(dictionary=True)
    user_id = session.get('user_id')
    if request.method == 'POST':
        current_lab_id = request.form['current_lab_id']
        new_lab_display_name = request.form['lab']  # Retrieve the display name of the new lab from radio button
        new_lab_id = None

        query_og = '''
            Select User_Id FROM Lab_State WHERE Current_Lab_Id = %s AND New_Lab_Id = %s AND User_Id = %s
        '''
        cursor.execute(query_og, (current_lab_id, new_lab_id, user_id,))
        quickcheck = cursor.fetchone()

        if quickcheck:
            return "You already have a request in progress"

        # Fetch the ID of the selected lab from the database based on its display name
        connection.reconnect()
        cursor = connection.cursor()
        query = '''
            SELECT Id FROM Lab WHERE display_name = %s
        '''
        cursor.execute(query, (new_lab_display_name,))
        new_lab_result = cursor.fetchone()

        if new_lab_result:
            new_lab_id = new_lab_result[0]

        # Check if the current lab is the same as the selected new lab
        if current_lab_id == new_lab_id:
            return "You are already in that lab"

        # Insert new entry into Lab_State table
        query = '''
            INSERT INTO Lab_State (Current_Lab_Id, New_Lab_Id, State_Id, User_Id)
            VALUES (%s, %s, %s, %s)
        '''
        cursor.execute(query, (current_lab_id, new_lab_id, 3, user_id))
        connection.commit()

        return redirect(url_for('teacher_dashboard'))
    else:
        return "Method not allowed"


@app.route('/edit_request/<int:request_id>', methods=['GET', 'POST'])
def edit_request(request_id):
    user_id = session.get('user_id')
    if user_id is None:
        return redirect(url_for('home'))

    connection.reconnect()
    cursor = connection.cursor(dictionary=True)

    if request.method == 'GET':
        # Fetch the user request from the database
        query = '''
            SELECT * FROM Request
            WHERE Id = %s AND User_Id = %s
        '''
        cursor.execute(query, (request_id, user_id))
        user_request = cursor.fetchone()

        if user_request:
            # Check if the request is completed or denied
            if user_request['State_Id'] in [4, 6]:
                return "Request is completed or denied. Cannot edit."

            cursor.execute('SELECT Id, display_name FROM Lab')
            labs = cursor.fetchall()

            cursor.execute('SELECT Id, Display FROM Request_Type')
            request_types = cursor.fetchall()

            lab_query = '''
            SELECT l.display_name
            FROM Lab l
            JOIN User_Lab ul ON l.Id = ul.lab_id
            WHERE ul.user_id = %s
            '''
            cursor.execute(lab_query, (user_id,))
            lab_display_name = cursor.fetchone()

            # Render a form to edit the request with prefilled details
            return render_template('edit_request.html', request=user_request, labs=labs, request_types=request_types, lab_display_name = lab_display_name)
        else:
            return "Request not found or you don't have permission to edit it."
    elif request.method == 'POST':
        # Update the request based on the form data
        lab_id = request.form.get('lab_id')
        requested_date = request.form.get('requested_date')
        description = request.form.get('description')
        unit_price = request.form.get('unit_price')
        quantity = request.form.get('quantity')
        oac_recommended_date = request.form.get('oac_recommended_date')
        request_type_id = request.form.get('request_type_id')
        additional_notes = request.form.get('additional_notes')

        # Fetch the user request from the database
        query = '''
            SELECT * FROM Request
            WHERE Id = %s AND User_Id = %s
        '''
        cursor.execute(query, (request_id, user_id))
        user_request = cursor.fetchone()

        if user_request:
            # Check if the request is completed or denied
            if user_request['State_Id'] in [4, 6]:
                return "Request is completed or denied. Cannot edit."

            # Check if the state is 7 (return for more detail)
            if user_request['State_Id'] == 7:
                # Update the State_Id to 3
                update_state_query = '''
                    UPDATE Request
                    SET State_Id = 3
                    WHERE Id = %s AND User_Id = %s
                '''
                cursor.execute(update_state_query, (request_id, user_id))
                connection.commit()

            # Update the request in the database
            update_query = '''
                UPDATE Request
                SET Lab_Id = %s, Requested_Date = %s, Description = %s, Unit_Price = %s,
                    Quantity = %s, OAC_Recommended_Date = %s, Request_Type_Id = %s,
                    Additional_Notes = %s
                WHERE Id = %s AND User_Id = %s
            '''
            cursor.execute(update_query, (
                lab_id, requested_date, description, unit_price, quantity, oac_recommended_date,
                request_type_id, additional_notes, request_id, user_id
            ))
            connection.commit()

            return redirect(url_for('teacher_dashboard'))
        else:
            return "Request not found or you don't have permission to edit it."


@app.route('/review_role_change/<int:User_Id>', methods=["POST"])
def review_role_change(User_Id):
    action = request.form['action']
    connection.reconnect()
    cursor = connection.cursor(dictionary=True)
    if action == "accept":
        query1 = """
            UPDATE Request_Role
            SET State_Id = 4
            WHERE User_Id = %s
            AND State_Id = 3
        """
        cursor.execute(query1, (User_Id,))
        # connection.commit()
        query2 = """
            UPDATE User_Role
            SET Role_Id = 2
            WHERE User_Id = %s
        """
        cursor.execute(query2, (User_Id,))
        connection.commit()
    else:
        query = """
            UPDATE Request_Role
            SET State_Id = 6
            WHERE User_Id = %s
            AND State_Id = 3
        """
        cursor.execute(query, (User_Id,))
        connection.commit()


    connection.reconnect()
    cursor = connection.cursor(dictionary=True)

    query = """
    SELECT * FROM Request_Role r
    INNER JOIN User u ON r.User_Id = u.Id
    INNER JOIN State s ON r.State_Id = s.Id
    WHERE r.State_Id = 3
    """

    cursor.execute(query)
    requests = cursor.fetchall()

    return render_template('review_role_change_requests.html', requests=requests)
    #return redirect(url_for(review_role_change_requests))



@app.route('/remove_request/<int:request_id>', methods=['POST'])
def remove_request(request_id):
    user_id = session.get('user_id')
    if user_id is None:
        return redirect(url_for('home'))

    # Check if the request exists and belongs to the user
    connection.reconnect()
    cursor = connection.cursor(dictionary=True)
    query = '''
        SELECT * FROM Request
        WHERE Id = %s AND User_Id = %s
    '''
    cursor.execute(query, (request_id, user_id))
    user_request = cursor.fetchone()

    if user_request:
        # Delete the request from the database
        delete_query = '''
            DELETE FROM Request
            WHERE Id = %s AND User_Id = %s
        '''
        cursor.execute(delete_query, (request_id, user_id))
        connection.commit()
        return redirect(url_for('teacher_dashboard'))
    else:
        return "Request not found or you don't have permission to remove it."



if __name__ == '__main__':
    app.run(debug=True)