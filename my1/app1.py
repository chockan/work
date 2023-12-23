from flask import Flask,request,redirect,url_for,flash,render_template
from werkzeug.security import generate_password_hash,check_password_hash
from flask_login import login_user,LoginManager,UserMixin,logout_user,login_required
from datetime import datetime

from flask_login import login_user,current_user,LoginManager,UserMixin,logout_user,login_required


from flask_sqlalchemy import SQLAlchemy
import sys
sys.path.append('E:/flask workouts/gym/newgym/my1')  # Adjust the path accordingly

db = SQLAlchemy()

def create_app():
    
    app = Flask(__name__)



        
    app.config['SECRET_KEY'] = 'abcde12345'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
    db.init_app(app)

        
        



    class User(db.Model,UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        email = db.Column(db.String(100), unique=True)
        password = db.Column(db.String(100))
        name = db.Column(db.String(1000))
        workouts = db.relationship('Workout2', backref='author', lazy=True)
        
    class Workout2(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        workout_body_area = db.Column(db.Text, nullable=False)
        number_of_sets = db.Column(db.Integer, nullable=False)
        date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
        comment = db.Column(db.Text, nullable=False)
        user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    with app.app_context():
        db.create_all()  
        
    login_manager = LoginManager()
    login_manager.login_view = 'login'
    login_manager.init_app(app)

    @app.route('/signup')
    def signup():
        return render_template('signup.html')





    @app.route('/login')
    def login():
        return render_template('login.html')

    @app.route('/')
    def base():
        return render_template('base.html')


    @app.route('/profile')
    @login_required
    def profile():
        return render_template('profile.html', name=current_user.name)

    @app.route('/index')
    def index():
        return render_template('index.html')

    @app.route("/new")
    @login_required
    def new_workout():
        return render_template('create_workout.html')



    @login_manager.user_loader
    def load_user(user_id):
        # since the user_id is just the primary key of our user table, use it in the query for the user
        return User.query.get(int(user_id))
        
    @app.route('/signup', methods=['POST'])
    def signup_post():

        email = request.form.get('email1')
        name = request.form.get('firstname1')
        password = request.form.get('password1')
        
        #print(email,name,password)
        user=User.query.filter_by(email=email).first()
        if user:  # if a user is found, we want to redirect back to signup page so user can try again
            flash('Email address already exists')
            return redirect(url_for('login'))

        # create new user with the form data. Hash the password so plaintext version isn't saved.
        new_user = User(email=email, name=name, password=generate_password_hash(password,method='pbkdf2:sha256'))

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        flash('successfully registered')

        return redirect(url_for('signup'))

    @app.route('/login', methods=['POST'])
    def login_post():
        email = request.form.get('email1')
        password = request.form.get('password1')
        remember = True if request.form.get('remember1') else False

        user = User.query.filter_by(email=email).first()

        # check if user actually exists
        # take the user supplied password, hash it, and compare it to the hashed password in database
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('login'))  # if user doesn't exist or password is wrong, reload the page

        # if the above check passes, then we know the user has the right credentials
        login_user(user, remember=remember)
        return redirect(url_for('profile'))


    @app.route("/new", methods=['POST'])
    @login_required
    def new_workout_post():
        pushups = request.form.get('pushups')
        number_of_sets = request.form.get('number_of_sets')
        comment = request.form.get('comment')
        print(pushups, comment)
        workout = Workout2(workout_body_area=pushups,number_of_sets=number_of_sets, comment=comment, author=current_user)
        db.session.add(workout)
        db.session.commit()
        flash('Your workout has been added!')
        return redirect(url_for('index'))


    @app.route("/all")
    @login_required
    def user_workouts():
        user = User.query.filter_by(email=current_user.email).first_or_404()
        workouts = user.workouts  # Workout.query.filter_by(author=user).order_by(Workout.date_posted.desc())
        return render_template('all_workouts.html', workouts=workouts, user=user)


    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('index'))


    @app.route("/workout/<int:workout_id>/update", methods=['GET', 'POST'])
    @login_required
    def update_workout(workout_id):
        workout = Workout2.query.get_or_404(workout_id)
        if request.method == "POST":
            workout.workout_body_area = request.form['pushups']
            workout.number_of_sets = request.form['number_of_sets']
            workout.comment = request.form['comment']
            db.session.commit()
            flash('Your post has been updated!')
            return redirect(url_for('user_workouts'))

        return render_template('update_workout.html', workout=workout)


    @app.route("/workout/<int:workout_id>/delete", methods=['GET', 'POST'])
    @login_required
    def delete_workout(workout_id):
        workout = Workout2.query.get_or_404(workout_id)
        db.session.delete(workout)
        db.session.commit()
        flash('Your post has been deleted!')
        return redirect(url_for('user_workouts'))

    return app

if __name__ == '__main__':
    
    app=create_app()
 
    # run() method of Flask class runs the application 
    # on the local development server.
    app.run(debug=True)







    


