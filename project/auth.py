from flask import Blueprint, render_template, redirect,url_for, request,flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user,login_required, logout_user
#new
import pickle
import pandas as pd #end new


from .models import User
from . import db

#loading the pre-trained model using pickle
#new
filename = "/home/arnold/flask_auth_new/project/random_forest_model.pkl"
model = pickle.load(open(filename,"rb")) #end new

auth = Blueprint('auth', __name__)

@auth.route('/login')
def login():
    return render_template('login.html')

#set up route for prediction
@auth.route('/prediction')
def prediction():
    return render_template('prediction.html')
@auth.route('/prediction', methods=["GET","POST"])
def prediction_post():
    if request.method == 'POST':
        product_department_id = request.form.get("product_department_id")
        product_subdepartment_id = request.form.get("product_subdepartment_id")
        product_type_id = request.form.get("product_type_id")
        product_subtype_id = request.form.get("product_subtype_id")
        product_family_id = request.form.get("product_family_id")
        origin_site_key = request.form.get("origin_site_key")
        destination_site_key = request.form.get("destination_site_key")
        day_of_delivery = request.form.get("day_of_delivery")
        distance = request.form.get("distance")

        #create dataframe based on input

        input_variables = pd.DataFrame([[
            product_department_id,product_subdepartment_id,product_type_id,
            product_subtype_id,product_family_id,origin_site_key,
            destination_site_key,day_of_delivery,distance
        ]],
        columns=['product_department_id','product_subdepartment_id','product_type_id',
            'product_subtype_id','product_family_id','origin_site_key',
            'destination_site_key','day_of_delivery','distance'],
            #dtype=int,
            index=['input']
        )
        #get the model's prediction
        prediction = model.predict(input_variables)[0]
        #we now pass the input from the form and the prediction to the index page
        return render_template("prediction.html",
        original_input={'product_department_id':product_department_id,
        'product_subdepartment_id':product_subdepartment_id,
        'product_type_id':product_type_id,
            'product_subtype_id':product_subtype_id,
            'product_family_id':product_family_id,
            'origin_site_key':origin_site_key,
            'destination_site_key':destination_site_key,
            'day_of_delivery':day_of_delivery,
            'distance':distance},
            result=prediction)
    else :
            return render_template("prediction.html")
    return render_template("prediction.html")





@auth.route('/login', methods=['POST'])
def login_post():
    # login code goes here
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(email=email).first()

    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('main.profile'))


@auth.route('/signup')
def signup():
    return render_template('signup.html')
@auth.route('/signup',methods=['POST'])
def signup_post():
    # code to validate and add user to database goes here
    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')

    user = User.query.filter_by(email=email).first() # if this returns a user, then the email already exists in database

    if user: # if a user is found, we want to redirect back to signup page so user can try again
        return redirect(url_for('auth.signup'))

    # create a new user with the form data. Hash the password so the plaintext version isn't saved.
    new_user = User(email=email, name=name, password=generate_password_hash(password, method='sha256'))

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()
    if user: # if a user is found, we want to redirect back to signup page so user can try again
        flash('Email address already exists')
    return redirect(url_for('auth.login'))
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))
