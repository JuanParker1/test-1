from datetime import datetime
from itsdangerous.url_safe import URLSafeTimedSerializer
from misp_app import db, login_manager, app
from flask_login import UserMixin

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    is_admin = db.Column(db.String(60), nullable=False)
    password = db.Column(db.String(60), nullable=False)
    Attribute = db.relationship('Attributes', backref='author', lazy=True)
    Event = db.relationship('Events', backref='has_events', lazy=True)

    def get_reset_token(self):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token):
        s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, max_age=600)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.image_file}')"


class Attributes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    Category = db.Column(db.String(40), nullable=False)
    Type = db.Column(db.String(20), nullable=False)
    Value = db.Column(db.String(160), unique=False, nullable=False)
    Threat_Level = db.Column(db.String(10))
    Creator_user = db.Column(db.String(20), nullable=False)
    Comment = db.Column(db.String(120), nullable=False, default='No Comment')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id'))

    def __repr__(self):
        return f"Attributes('{self.Type}', '{self.Value}', '{self.date_posted}', '{self.Category}')"

    def to_dict(self):
        return {
            'Date': self.date_posted,
            'Category': self.Category,
            'Type': self.Type,
            'Value': self.Value,
            'Threat Level': self.Threat_Level
        }

class Clients(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    clientname = db.Column(db.String(20), nullable=False)
    q_ip = db.Column(db.String(20), nullable=False)
    q_token = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(10), nullable=False)

    def __repr__(self):
        return f"Clients('{self.clientname}', '{self.q_ip}', '{self.q_token}')"

class Events(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_name = db.Column(db.String(40), nullable=False)
    Creator_org = db.Column(db.String(40), nullable=False)
    Owner_org = db.Column(db.String(40), nullable=False)
    Creator_user = db.Column(db.String(20), db.ForeignKey('user.username'), nullable=False)
    Tags = db.Column(db.String)
    Date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    Threat_Level = db.Column(db.String(10), nullable=False)
    Distribution = db.Column(db.String(40), nullable=False)
    Analysis = db.Column(db.String(40), nullable=False)
    Comment = db.Column(db.Text(350), nullable=False, default='No Comment')
    Attributes = db.relationship('Attributes', backref='has_Attributes', lazy=True)

    def __repr__(self):
        return f"Event('{self.id}', '{self.event_name}', '{self.Owner_org}')"

class Tags(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tag_name = db.Column(db.String(40), nullable=False)
    tag_color = db.Column(db.String(10), nullable=False)

    def __repr__(self):
        return f"Attributes('{self.id}', '{self.tag_name}', '{self.tag_color}')"
class Attributesaccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    URLs = db.Column(db.Integer, nullable=False)
    Domains = db.Column(db.Integer, nullable=False)
    IPs = db.Column(db.Integer, nullable=False)
    SHA256 = db.Column(db.Integer, nullable=False)
    SHA1 = db.Column(db.Integer, nullable=False)
    MD5 = db.Column(db.Integer, nullable=False)
    def __repr__(self):
        return f"Attributesaccount('{self.id}', '{self.URLs}', '{self.Domains}')"

class Results(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    client = db.Column(db.String(20))
    ipaddress = db.Column(db.String(20))
    feedstatus = db.Column(db.String(20))
