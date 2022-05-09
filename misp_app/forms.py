from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField, IntegerField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError, AnyOf, IPAddress
from misp_app.models import User, Attributes, Events
from misp_app.fonctions import emailcheck
from misp_app import bcrypt

class search(FlaskForm):
        Search = StringField('Search with value', validators=[Length(max=160)])


class feedfromMisp(FlaskForm):
    Category= SelectField('Category', choices=["Payload delivery","Network activity","Antivirus detection","Artifacts dropped","External analysis"])
    Type = SelectField('Type', choices=["md5","sha1","sha256","link","text","hex","md5","sha1","sha256","domain","url","md5","sha1","sha256","sha384","sha512","filename","md5","sha1","sha224","sha256","sha384","sha512","filename","ip-src","ip-dst","ip-dst|port","ip-src|port","port","hostname","domain","url"])
    Last = StringField('Last', validators=[DataRequired(), Length(min=2, max=5)])
    send = BooleanField('Add to table')
    submit = SubmitField('Add')


class AddAttributes(FlaskForm):
    Eventid = IntegerField('event Id', validators=[DataRequired()])
    Category= SelectField('Category', choices=["Payload delivery","Artifacts dropped","Network activity","Antivirus detection","Payload installation","Internal reference","External analysis","Other"])
    Type = SelectField('Type', choices=["md5","sha1","sha224","sha256","sha384","sha512","text","link","comment","other","hex","git-commit-id","attachment","anonymised","md5","sha1","sha224","sha256","sha384","sha512","sha512/224","sha512/256","sha3-224","sha3-256","sha3-384","sha3-512","ssdeep","imphash","telfhash","impfuzzy","authentihash","vhash","pehash","tlsh","cdhash","filename","filename|md5","filename|sha1","filename|sha224","filename|sha256","filename|sha384","filename|sha512","filename|sha512/224","filename|sha512/256","filename|sha3-224","filename|sha3-256","filename|sha3-384","filename|sha3-512","filename|authentihash","filename|vhash","filename|ssdeep","filename|tlsh","filename|imphash","filename|impfuzzy","filename|pehash","mac-address","mac-eui-64","ip-src","ip-dst","ip-dst|port","ip-src|port","hostname","domain","email","email-src","email-dst","email-subject","email-attachment","email-body","url","user-agent","AS","pattern-in-file","pattern-in-traffic","filename-pattern","stix2-pattern","yara","sigma","mime-type","malware-sample","malware-type","vulnerability","cpe","weakness","x509-fingerprint-sha1","x509-fingerprint-md5","x509-fingerprint-sha256","ja3-fingerprint-md5","jarm-fingerprint","hassh-md5","hasshserver-md5","hostname|port","email-dst-display-name","email-src-display-name","email-header","email-reply-to","email-x-mailer","email-mime-boundary","email-thread-index","email-message-id","mobile-application-id","chrome-extension-id","whois-registrant-email","filename","filename|md5","filename|sha1","filename|sha224","filename|sha256","filename|sha384","filename|sha512","pattern-in-file","pattern-in-memory","filename-pattern","yara","cookie","mime-type","filename","filename|md5","filename|sha1","filename|sha224","filename|sha256","filename|sha384","filename|sha512","pattern-in-file","pattern-in-memory","filename-pattern","yara","vulnerability","weakness","malware-sample","malware-type","mime-type","ip-src","ip-dst","ip-dst|port","ip-src|port","port","hostname","domain","domain|ip","mac-address","email","email-dst","email-src","eppn","url","uri","http-method","snort","pattern-in-file","filename-pattern","pattern-in-traffic","hassh-md5","cookie","hostname|port","zeek","email-subject","md5","sha1","sha224","sha256","sha384","sha512","filename","filename|md5","filename|sha1","filename|sha256","ip-src","ip-dst","mac-address","hostname","domain","url","snort","zeek","bro","pattern-in-file","pattern-in-traffic","vulnerability","link","comment","text","weakness","other"])
    Value = StringField('Value', validators=[DataRequired(), Length(min=2, max=160)])
    Comment = TextAreaField('Comment',validators=[Length(max=120)])
    send = BooleanField('Add to QRadar')
    submit = SubmitField('Add')

    def validate_Eventid(self, Eventid):
        if_event_in_data_base = Events.query.filter_by(id=Eventid.data).first()
        if if_event_in_data_base is None:
            raise ValidationError('There is no event with that id. You must add the event first.')



class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email(allow_empty_local=False)])
    privilage = BooleanField('admin')
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Add User')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('That email is taken. Please choose a different one.')

    #def validate_email(self, email):
       # #var = emailcheck(email.data)
        #email = User.query.filter_by(email=email.data).first()
        #if var:
        #    if email:
        #        raise ValidationError('This email address is already used. Please choose a different one.')
        #else:
        #    raise ValidationError('Email syntax error "user@dataprotect.com"')



class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(allow_empty_local=False)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

    def validate_email(self, email):
        var6 = emailcheck(email.data)
        if var6 is None:
            raise ValidationError('email not valid')

class UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email(allow_empty_local=False)])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png','jpeg'])])
    current_password = PasswordField('Current Password')
    new_password = PasswordField('New Password')
    confirm_new_password = PasswordField('Confirm New Password',
                                     validators=[EqualTo('new_password')])
    submit = SubmitField('Update')

    def validate_current_password(self, current_password):
        if bcrypt.check_password_hash(current_user.password, current_password.data) is False:
            raise ValidationError('The Password is incorrect !')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('That email is taken. Please choose a different one.')




class UpdateAttributes(FlaskForm):
    update_att_id = IntegerField('update att id')
    Eventid = IntegerField('event Id', validators=[DataRequired()])
    Category= SelectField('Category', choices=["Payload delivery","Artifacts dropped","Network activity","Antivirus detection","External analysis","Other"])
    Type = SelectField('Type', choices=["text","link","comment","other","hex","git-commit-id","attachment","anonymised","md5","sha1","sha224","sha256","sha384","sha512","sha512/224","sha512/256","sha3-224","sha3-256","sha3-384","sha3-512","ssdeep","imphash","telfhash","impfuzzy","authentihash","vhash","pehash","tlsh","cdhash","filename","filename|md5","filename|sha1","filename|sha224","filename|sha256","filename|sha384","filename|sha512","filename|sha512/224","filename|sha512/256","filename|sha3-224","filename|sha3-256","filename|sha3-384","filename|sha3-512","filename|authentihash","filename|vhash","filename|ssdeep","filename|tlsh","filename|imphash","filename|impfuzzy","filename|pehash","mac-address","mac-eui-64","ip-src","ip-dst","ip-dst|port","ip-src|port","hostname","domain","email","email-src","email-dst","email-subject","email-attachment","email-body","url","user-agent","AS","pattern-in-file","pattern-in-traffic","filename-pattern","stix2-pattern","yara","sigma","mime-type","malware-sample","malware-type","vulnerability","cpe","weakness","x509-fingerprint-sha1","x509-fingerprint-md5","x509-fingerprint-sha256","ja3-fingerprint-md5","jarm-fingerprint","hassh-md5","hasshserver-md5","hostname|port","email-dst-display-name","email-src-display-name","email-header","email-reply-to","email-x-mailer","email-mime-boundary","email-thread-index","email-message-id","mobile-application-id","chrome-extension-id","whois-registrant-email","filename","filename|md5","filename|sha1","filename|sha224","filename|sha256","filename|sha384","filename|sha512","pattern-in-file","pattern-in-memory","filename-pattern","yara","cookie","mime-type","filename","filename|md5","filename|sha1","filename|sha224","filename|sha256","filename|sha384","filename|sha512","pattern-in-file","pattern-in-memory","filename-pattern","yara","vulnerability","weakness","malware-sample","malware-type","mime-type","ip-src","ip-dst","ip-dst|port","ip-src|port","port","hostname","domain","domain|ip","mac-address","email","email-dst","email-src","eppn","url","uri","http-method","snort","pattern-in-file","filename-pattern","pattern-in-traffic","hassh-md5","cookie","hostname|port","zeek","email-subject","md5","sha1","sha224","sha256","sha384","sha512","filename","filename|md5","filename|sha1","filename|sha256","ip-src","ip-dst","mac-address","hostname","domain","url","snort","zeek","bro","pattern-in-file","pattern-in-traffic","vulnerability","link","comment","text","weakness","other"])
    Value = StringField('Value', validators=[DataRequired(), Length(min=2, max=160)])
    Comment = TextAreaField('Comment',validators=[Length(max=120)])
    send = BooleanField('send')
    submit = SubmitField('Update')


class AddClient(FlaskForm):
    clientname = StringField('Client Name', validators=[DataRequired()])
    q_ip = StringField('ip address', validators=[DataRequired(),IPAddress(ipv4=True, ipv6=True)])
    q_token = StringField('QRadar token', validators=[DataRequired()])
    submit = SubmitField('Add')

class UpdateClient(FlaskForm):
    clientname = StringField('Client Name', validators=[DataRequired()])
    q_ip = StringField('ip address', validators=[DataRequired(),IPAddress(ipv4=True, ipv6=True)])
    q_token = StringField('QRadar token', validators=[DataRequired()])
    submit = SubmitField('Update')

class RequestResetForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('There is no account with that email. You must register first.')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

