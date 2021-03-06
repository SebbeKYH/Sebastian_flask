import datetime
from app import db

# Creation of relational table for interaction between tables (classes)
message_recv = db.Table('message_recv',
                        db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                        db.Column('message_id', db.Integer, db.ForeignKey('message.id'), primary_key=True)
                        )

# Create User class object for interaction with the database
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(100))
    public_rsa_key = db.Column(db.VARCHAR(2048))
    admin = db.Column(db.BOOLEAN, default=False)
    online = db.Column(db.BOOLEAN, default=False)
    sent_messages = db.relationship('Message', backref='sender', lazy=True)
    recv_messages = db.relationship('Message', secondary=message_recv, lazy='subquery',
                                    backref=db.backref('receivers', lazy=True))


    def is_active(self):
        return True

    def is_authenticated(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        return self.id


# Create Message class object for interaction with the database
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    body = db.Column(db.Text)
    aes_key = db.Column(db.Text)
    aes_nonce = db.Column(db.Text)
    aes_tag = db.Column(db.Text)
    rsa_key = db.Column(db.Text)
    read = db.Column(db.BOOLEAN, default=False)
    sent_time = db.Column(db.DateTime, default=datetime.datetime.now())
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)




